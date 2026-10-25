#!/bin/sh
# Server host: web (80), HTTPS (443, 8443), telnet-like banner (23),
# DNS (53, answers every *.test name with this host) and iperf3 (5201-5204).
set -e
ip route add 10.10.1.0/24 via 10.10.2.2

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=gatekeep-lab" \
    -keyout /tmp/key.pem -out /tmp/cert.pem 2>/dev/null

dnsmasq --no-resolv --no-hosts --listen-address=10.10.2.10 --bind-interfaces \
    --address=/test/10.10.2.10 --log-queries --log-facility=-
for port in 5201 5202 5203 5204; do iperf3 -s -D -p "$port"; done
echo "server ready"
exec python3 -u /lab/server.py
