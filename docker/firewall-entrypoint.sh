#!/bin/sh
set -e

# Load the kernel rules first: until the engine binds the queue, forwarded
# packets wait in it or are dropped, never let through unchecked.
nft -f /etc/gatekeep/gatekeep.nft
echo "gatekeep: nftables rules loaded"

exec gatekeep --policy /etc/gatekeep/policy.json --queue 0 --api-host 0.0.0.0 --api-port 8080 \
    --cors-origin "${GATEKEEP_CORS_ORIGINS:-}"
