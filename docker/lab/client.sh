#!/bin/sh
# Client host. Reaches the server network only through the firewall.
set -e
ip route add 10.10.2.0/24 via 10.10.1.2
# Second address, used by the demo to act as a quarantined host.
ip addr add 10.10.1.66/24 dev eth0
echo "client ready: $(ip -4 -o addr show dev eth0 | awk '{print $4}' | tr '\n' ' ')"
# Scenario runner for the website's live mode.
cd /lab && exec python3 -u runner.py
