#include "api.hpp"

#include <httplib.h>

#include <functional>
#include <iostream>
#include <regex>

#include "kernel.hpp"

using nlohmann::json;

namespace {

void reply(httplib::Response& res, const json& body, int status = 200) {
    res.status = status;
    res.set_content(body.dump(2) + "\n", "application/json");
}

// Runs a handler, turning bad input into 400 instead of a crash.
void guarded(httplib::Response& res, const std::function<void()>& fn) {
    try {
        fn();
    } catch (const std::exception& e) {
        reply(res, {{"error", e.what()}}, 400);
    }
}

// Rules and domains changed: drop every cached flow verdict in the kernel so
// existing connections are re-checked against the new policy, not just new ones.
void policy_changed() { kernel_flush_conntrack(); }

// The demo website calls this API from the browser. Only pages served from
// this machine (localhost / 127.0.0.1, any port) may do so.
bool local_origin(const std::string& origin) {
    static const std::regex allowed(R"(^https?://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?$)");
    return std::regex_match(origin, allowed);
}

}  // namespace

void run_api(Engine& engine, const std::string& host, int port, const std::string& policy_path) {
    httplib::Server svr;

    // ── CORS for the local demo website ──
    svr.set_post_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        const std::string origin = req.get_header_value("Origin");
        if (local_origin(origin)) {
            res.set_header("Access-Control-Allow-Origin", origin);
            res.set_header("Vary", "Origin");
        }
    });
    svr.Options(R"(/.*)", [](const httplib::Request& req, httplib::Response& res) {
        if (!local_origin(req.get_header_value("Origin"))) {
            res.status = 403;
            return;
        }
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.status = 204;
    });

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) { reply(res, {{"status", "ok"}}); });

    // ── Policy ──
    svr.Get("/policy", [&](const httplib::Request&, httplib::Response& res) { reply(res, engine.policy_json()); });

    svr.Put("/policy", [&](const httplib::Request& req, httplib::Response& res) {
        guarded(res, [&] {
            engine.replace_policy(policy_from_json(json::parse(req.body)));
            policy_changed();
            reply(res, engine.policy_json());
        });
    });

    svr.Post("/policy/reload", [&](const httplib::Request&, httplib::Response& res) {
        guarded(res, [&] {
            engine.replace_policy(load_policy_file(policy_path));
            policy_changed();
            reply(res, engine.policy_json());
        });
    });

    // ── Rules ──  POST /rules?position=0 inserts at the top (default: bottom)
    svr.Post("/rules", [&](const httplib::Request& req, httplib::Response& res) {
        guarded(res, [&] {
            std::optional<size_t> position;
            if (req.has_param("position")) position = std::stoul(req.get_param_value("position"));
            engine.add_rule(rule_from_json(json::parse(req.body)), position);
            policy_changed();
            reply(res, engine.policy_json()["rules"], 201);
        });
    });

    svr.Delete(R"(/rules/([A-Za-z0-9._-]+))", [&](const httplib::Request& req, httplib::Response& res) {
        if (!engine.remove_rule(req.matches[1])) return reply(res, {{"error", "no such rule"}}, 404);
        policy_changed();
        reply(res, engine.policy_json()["rules"]);
    });

    // ── Blocked domains ──
    svr.Post("/domains", [&](const httplib::Request& req, httplib::Response& res) {
        guarded(res, [&] {
            engine.add_domain(json::parse(req.body).at("domain").get<std::string>());
            policy_changed();
            reply(res, engine.policy_json()["blocked_domains"], 201);
        });
    });

    svr.Delete(R"(/domains/([A-Za-z0-9._-]+))", [&](const httplib::Request& req, httplib::Response& res) {
        if (!engine.remove_domain(req.matches[1])) return reply(res, {{"error", "no such domain"}}, 404);
        policy_changed();
        reply(res, engine.policy_json()["blocked_domains"]);
    });

    // ── Bans ──
    svr.Get("/bans", [&](const httplib::Request&, httplib::Response& res) { reply(res, engine.bans()); });

    svr.Delete(R"(/bans/([0-9.]+))", [&](const httplib::Request& req, httplib::Response& res) {
        uint32_t ip = 0;
        if (!parse_ip(req.matches[1], ip)) return reply(res, {{"error", "invalid IP"}}, 400);
        const bool found = engine.unban(ip);
        kernel_unban(ip);
        reply(res, {{"unbanned", ip_to_string(ip)}}, found ? 200 : 404);
    });

    // ── Runtime config ──  {"fast_path": false} sends every packet through userspace (benchmarking)
    svr.Get("/config", [&](const httplib::Request&, httplib::Response& res) {
        reply(res, {{"fast_path", engine.fast_path()}});
    });

    svr.Put("/config", [&](const httplib::Request& req, httplib::Response& res) {
        guarded(res, [&] {
            const json body = json::parse(req.body);
            if (body.contains("fast_path")) {
                engine.set_fast_path(body.at("fast_path").get<bool>());
                policy_changed();  // flows already offloaded must come back to be re-judged
            }
            reply(res, {{"fast_path", engine.fast_path()}});
        });
    });

    // ── Observability ──
    svr.Get("/flows", [&](const httplib::Request&, httplib::Response& res) { reply(res, engine.pending_flows()); });

    svr.Get("/events", [&](const httplib::Request& req, httplib::Response& res) {
        guarded(res, [&] {
            const size_t limit = req.has_param("limit") ? std::stoul(req.get_param_value("limit")) : 50;
            reply(res, engine.events(limit));
        });
    });

    svr.Get("/stats", [&](const httplib::Request&, httplib::Response& res) { reply(res, engine.stats()); });

    // Packet counters of the nftables rules: how much traffic took the fast path.
    svr.Get("/kernel", [](const httplib::Request&, httplib::Response& res) { reply(res, kernel_counters()); });

    svr.Get("/metrics", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(engine.prometheus_metrics(), "text/plain; version=0.0.4");
    });

    std::cerr << "gatekeep: control API on http://" << host << ":" << port << '\n';
    if (!svr.listen(host, port)) std::cerr << "gatekeep: control API failed to bind " << host << ":" << port << '\n';
}
