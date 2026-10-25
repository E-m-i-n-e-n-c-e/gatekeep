#!/usr/bin/env bash
# Walks through every firewall feature against the running lab
# (docker compose up -d --build) and checks each result.
set -uo pipefail
cd "$(dirname "$0")/.."

API=http://127.0.0.1:8080
pass=0
fail=0

if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'; else G= R= B= D= N=; fi

client() { docker compose exec -T client "$@"; }
section() { printf "\n${B}%s${N}\n" "$1"; }

# expect <allow|block> <description> <command...>
expect() {
    local want=$1 desc=$2
    shift 2
    local got=block
    client "$@" >/dev/null 2>&1 && got=allow
    if [ "$got" = "$want" ]; then
        printf "  ${G}PASS${N}  %-58s ${D}%s${N}\n" "$desc" "$got"
        pass=$((pass + 1))
    else
        printf "  ${R}FAIL${N}  %-58s ${D}expected %s, got %s${N}\n" "$desc" "$want" "$got"
        fail=$((fail + 1))
    fi
}

curl -fsS "$API/health" >/dev/null || { echo "firewall API not reachable; run: docker compose up -d --build"; exit 1; }
curl -fsS -X POST "$API/policy/reload" >/dev/null  # start from the policy file
for ip in 10.10.1.10 10.10.1.66; do curl -s -X DELETE "$API/bans/$ip" >/dev/null; done

section "1. L3/L4 rules (first match wins, default deny)"
expect allow "HTTP to the web server (allow-web)" curl -fsS -m 3 http://10.10.2.10/
expect allow "ping (allow-ping)" ping -c 1 -W 2 10.10.2.10
expect block "telnet :23 gets a TCP RST (reject-telnet)" nc -z -w 2 10.10.2.10 23
expect block "SSH :22 is not allowed by any rule (default drop)" nc -z -w 2 10.10.2.10 22
expect block "quarantined source 10.10.1.66 (quarantine-host)" curl -fsS -m 3 --interface 10.10.1.66 http://10.10.2.10/

section "2. L7 inspection: domains, found by reading the traffic"
expect allow "TLS to shop.test (SNI allowed)" curl -fsSk -m 3 --resolve shop.test:443:10.10.2.10 https://shop.test/
expect block "TLS to evil.test (SNI blocked)" curl -fsSk -m 3 --resolve evil.test:443:10.10.2.10 https://evil.test/
expect block "TLS to cdn.evil.test on port 8443 (TLS found by bytes, not port)" \
    curl -fsSk -m 3 --resolve cdn.evil.test:8443:10.10.2.10 https://cdn.evil.test:8443/
expect block "HTTP with Host: tracker.test (Host header blocked)" curl -fsS -m 3 -H "Host: tracker.test" http://10.10.2.10/
expect allow "DNS query for shop.test" sh -c 'dig +short +time=2 +tries=1 @10.10.2.10 shop.test | grep -qx 10.10.2.10'
expect block "DNS query for ads.tracker.test (subdomain of a blocked domain)" \
    sh -c 'dig +short +time=2 +tries=1 @10.10.2.10 ads.tracker.test | grep -qx 10.10.2.10'

section "3. Hot rule changes through the API (existing connections re-checked)"
curl -fsS -X POST "$API/rules?position=0" \
    -d '{"id": "maintenance", "action": "reject", "proto": "tcp", "dst_ports": "80"}' >/dev/null
expect block "after POST /rules {reject tcp/80} at the top" curl -fsS -m 3 http://10.10.2.10/
curl -fsS -X DELETE "$API/rules/maintenance" >/dev/null
expect allow "after DELETE /rules/maintenance" curl -fsS -m 3 http://10.10.2.10/
curl -fsS -X POST "$API/domains" -d '{"domain": "shop.test"}' >/dev/null
expect block "after POST /domains {shop.test}" curl -fsSk -m 3 --resolve shop.test:443:10.10.2.10 https://shop.test/
curl -fsS -X DELETE "$API/domains/shop.test" >/dev/null
expect allow "after DELETE /domains/shop.test" curl -fsSk -m 3 --resolve shop.test:443:10.10.2.10 https://shop.test/

section "4. SYN flood -> rate limit -> automatic ban"
printf "  ${D}hping3: 3000 SYNs at 2000/s from 10.10.1.10...${N}\n"
client hping3 -S -p 80 -i u500 -c 3000 -q 10.10.2.10 >/dev/null 2>&1
expect block "flooding source is banned (kernel @banned set)" curl -fsS -m 3 http://10.10.2.10/
printf "  ${D}GET /bans -> %s${N}\n" "$(curl -fsS "$API/bans" | tr -d ' \n')"
curl -fsS -X DELETE "$API/bans/10.10.1.10" >/dev/null
expect allow "after DELETE /bans/10.10.1.10" curl -fsS -m 3 http://10.10.2.10/

section "5. Fast path: a 3-second bulk transfer, then where its packets went"
# Prints "<fast path packets> <slow path packets>" from the nftables rule counters.
path_counters() {
    docker compose exec -T firewall nft list chain inet gatekeep forward |
        awk '/comment "fast path/ {for (i = 1; i <= NF; i++) if ($i == "packets") f = $(i + 1)}
             /comment "slow path/ {for (i = 1; i <= NF; i++) if ($i == "packets") s = $(i + 1)}
             END {print f, s}'
}
read -r fast0 slow0 <<<"$(path_counters)"
printf "  ${D}%s${N}\n" "$(client iperf3 -c 10.10.2.10 -t 3 -f g | awk '/receiver/ {print "iperf3: " $(NF-2) " Gbit/s through the firewall"}')"
read -r fast1 slow1 <<<"$(path_counters)"
printf "  %9d packets handled in the kernel (fast path)\n" "$((fast1 - fast0))"
printf "  %9d packets sent to the engine (slow path): the first few of each connection\n" "$((slow1 - slow0))"

printf "\n${B}%d passed, %d failed${N}\n" "$pass" "$fail"
[ "$fail" -eq 0 ]
