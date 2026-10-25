"""The demo scenarios: the one definition used by the runner (live mode) and,
through the runner, by scripts/record.py (the website's recording).

A step is either traffic sent from the client container through the firewall,
or a call to the firewall's control API.
"""

CURL = "curl -sS -m 3"


def traffic(label, cmd, display, outcome=None):
    """`outcome` overrides allowed/blocked for commands that always succeed."""
    return {"kind": "traffic", "label": label, "cmd": cmd, "command": display, "outcome": outcome}


def api(label, method, path, body=None):
    return {"kind": "api", "label": label, "method": method, "path": path, "body": body}


SCENARIOS = [
    {
        "id": "web",
        "title": "Open the web server",
        "summary": "Plain HTTP to port 80. The allow-web rule matches, the first request is read (Host: 10.10.2.10), and the connection moves to the fast path.",
        "steps": [traffic("Request the home page", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/")],
    },
    {
        "id": "tls-allowed",
        "title": "Visit shop.test over HTTPS",
        "summary": "The engine waits for the TLS ClientHello, reads the server name (SNI) shop.test, finds it isn't blocked, and hands the connection to the kernel.",
        "steps": [traffic("HTTPS to shop.test", f"{CURL} -k --resolve shop.test:443:10.10.2.10 https://shop.test/", "curl https://shop.test/")],
    },
    {
        "id": "tls-blocked",
        "title": "Visit evil.test over HTTPS",
        "summary": "The traffic is encrypted, but the ClientHello names the site in plain text. evil.test is on the blocklist, so the connection is reset.",
        "steps": [traffic("HTTPS to evil.test", f"{CURL} -k --resolve evil.test:443:10.10.2.10 https://evil.test/", "curl https://evil.test/")],
    },
    {
        "id": "tls-other-port",
        "title": "Hide evil.test on port 8443",
        "summary": "Moving to a non-standard port doesn't help: TLS is recognised by its first bytes, not by the port number. Subdomains of a blocked domain are blocked too.",
        "steps": [traffic("HTTPS to cdn.evil.test:8443", f"{CURL} -k --resolve cdn.evil.test:8443:10.10.2.10 https://cdn.evil.test:8443/", "curl https://cdn.evil.test:8443/")],
    },
    {
        "id": "http-host",
        "title": "Reach tracker.test over plain HTTP",
        "summary": "For unencrypted HTTP the engine reads the Host header of the first request.",
        "steps": [traffic("HTTP with Host: tracker.test", f'{CURL} -H "Host: tracker.test" http://10.10.2.10/', "curl -H 'Host: tracker.test' http://10.10.2.10/")],
    },
    {
        "id": "dns",
        "title": "Look up names over DNS",
        "summary": "DNS queries are checked one by one and never offloaded. A query for a subdomain of a blocked domain is refused.",
        "steps": [
            traffic("Look up shop.test", "dig +short +time=2 +tries=1 @10.10.2.10 shop.test | grep -qx 10.10.2.10", "dig shop.test"),
            traffic("Look up ads.tracker.test", "dig +short +time=2 +tries=1 @10.10.2.10 ads.tracker.test | grep -qx 10.10.2.10", "dig ads.tracker.test"),
        ],
    },
    {
        "id": "ports",
        "title": "Try telnet and SSH",
        "summary": "Telnet matches a reject rule and gets an immediate TCP reset. SSH matches no rule, so the default policy drops it silently.",
        "steps": [
            traffic("Telnet to port 23", "nc -z -w 2 10.10.2.10 23", "nc 10.10.2.10 23"),
            traffic("SSH to port 22", "nc -z -w 2 10.10.2.10 22", "nc 10.10.2.10 22"),
        ],
    },
    {
        "id": "quarantine",
        "title": "Connect from a quarantined host",
        "summary": "Traffic from 10.10.1.66 matches the first rule and is dropped, whatever it is.",
        "steps": [traffic("HTTP from 10.10.1.66", f"{CURL} --interface 10.10.1.66 http://10.10.2.10/", "curl --interface 10.10.1.66 http://10.10.2.10/")],
    },
    {
        "id": "hot-rule",
        "title": "Change the rules while it runs",
        "summary": "A rule added through the API applies immediately, including to connections that were already open: cached verdicts are flushed and re-checked.",
        "steps": [
            api("Add a rule at the top", "POST", "/rules?position=0", {"id": "maintenance", "action": "reject", "proto": "tcp", "dst_ports": "80"}),
            traffic("Request the home page", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/"),
            api("Remove the rule", "DELETE", "/rules/maintenance"),
            traffic("Request the home page again", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/"),
        ],
    },
    {
        "id": "flood",
        "title": "Launch a SYN flood",
        "summary": "3,000 connection attempts at 2,000 per second. The token bucket lets a burst through, refuses the rest, and after 200 refusals bans the source in the kernel.",
        "steps": [
            traffic("3,000 SYNs at 2,000/s", "hping3 -S -p 80 -i u500 -c 3000 -q 10.10.2.10 >/dev/null 2>&1; true", "hping3 -S -p 80 -i u500 -c 3000 10.10.2.10", outcome="sent"),
            traffic("Request the home page while banned", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/"),
            api("Lift the ban", "DELETE", "/bans/10.10.1.10"),
            traffic("Request the home page again", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/"),
        ],
    },
    {
        "id": "bulk",
        "title": "Download at full speed",
        "summary": "A 3-second iperf3 transfer. Only the first packets of each connection reach the engine; the kernel forwards the rest.",
        "steps": [traffic("3-second iperf3 transfer", "iperf3 -c 10.10.2.10 -t 3 -f g | grep receiver", "iperf3 -c 10.10.2.10 -t 3")],
    },
]
