#!/usr/bin/env bash
# Benchmarks the firewall in three modes:
#   kernel only  - an "accept everything" rule at the top of the chain; the engine never sees traffic
#   fast path    - normal mode: the engine judges the first packets, the kernel handles the rest
#   every packet - fast path off: every packet makes the round trip to userspace
#
# For each mode it measures:
#   - small-packet rate: 4 parallel UDP streams of 64-byte payloads, packets/s received
#     (packets per second is what firewalls are rated on, not bulk throughput)
#   - bulk TCP throughput, and the CPU used by the firewall container's processes
#     (the engine) while forwarding it. The kernel's own forwarding work runs in
#     softirq context and is not charged to the container.
set -euo pipefail
cd "$(dirname "$0")/.."

API=http://127.0.0.1:8080
DURATION=${DURATION:-10}
FIREWALL=$(docker compose ps -q firewall)
fw() { docker compose exec -T firewall "$@"; }

udp_pps() {
    docker compose exec -T client sh -c "
        for port in 5201 5202 5203 5204; do
            iperf3 -c 10.10.2.10 -p \$port -u -b 0 -l 64 -t $DURATION -J > /tmp/udp-\$port.json &
        done
        wait
        python3 -c '
import json
total = 0
for port in (5201, 5202, 5203, 5204):
    s = json.load(open(f\"/tmp/udp-{port}.json\"))[\"end\"][\"sum\"]
    total += (s[\"packets\"] - s[\"lost_packets\"]) / s[\"seconds\"]
print(int(total))'"
}

# Prints "<Mbit/s> <engine CPU%>": samples CPU halfway through the transfer.
tcp_with_cpu() {
    local out
    out=$(mktemp)
    docker compose exec -T client iperf3 -c 10.10.2.10 -t "$DURATION" -f m >"$out" &
    local pid=$!
    sleep $((DURATION / 2))
    local cpu
    cpu=$(docker stats --no-stream --format '{{.CPUPerc}}' "$FIREWALL")
    wait "$pid"
    echo "$(awk '/receiver/ {print $(NF-2)}' "$out") ${cpu%\%}"
    rm -f "$out"
}

run_mode() {
    fw conntrack -F >/dev/null 2>&1 || true
    local pps tcp
    pps=$(udp_pps)
    tcp=$(tcp_with_cpu)
    echo "$pps $tcp"
}

set_fast_path() { curl -fsS -X PUT "$API/config" -d "{\"fast_path\": $1}" >/dev/null; }

echo "Benchmarking: ${DURATION}s per test, 6 tests..."

fw nft insert rule inet gatekeep forward accept comment \"bench-bypass\"
read -r base_pps base_tcp base_cpu <<<"$(run_mode)"
handle=$(fw nft -a list chain inet gatekeep forward | awk '/bench-bypass/ {print $NF}')
fw nft delete rule inet gatekeep forward handle "$handle"

set_fast_path true
read -r fast_pps fast_tcp fast_cpu <<<"$(run_mode)"

set_fast_path false
read -r slow_pps slow_tcp slow_cpu <<<"$(run_mode)"
set_fast_path true

pct() { awk -v a="$1" -v b="$2" 'BEGIN {printf "%.0f%%", 100 * a / b}'; }
kpps() { awk -v a="$1" 'BEGIN {printf "%.0fk", a / 1000}'; }
gbps() { awk -v a="$1" 'BEGIN {printf "%.1f", a / 1000}'; }

echo
printf "%-16s %14s %10s %14s %16s\n" "mode" "64B pkts/s" "vs kernel" "TCP Gbit/s" "engine CPU"
printf "%-16s %14s %10s %14s %15s%%\n" "kernel only" "$(kpps "$base_pps")" "100%" "$(gbps "$base_tcp")" "$base_cpu"
printf "%-16s %14s %10s %14s %15s%%\n" "fast path" "$(kpps "$fast_pps")" "$(pct "$fast_pps" "$base_pps")" "$(gbps "$fast_tcp")" "$fast_cpu"
printf "%-16s %14s %10s %14s %15s%%\n" "every packet" "$(kpps "$slow_pps")" "$(pct "$slow_pps" "$base_pps")" "$(gbps "$slow_tcp")" "$slow_cpu"
echo
awk -v f="$fast_pps" -v s="$slow_pps" 'BEGIN {printf "fast path forwards %.1fx more small packets than sending every packet to userspace\n", f / s}'
