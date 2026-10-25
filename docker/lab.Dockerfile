# One image for both lab hosts (client and server); the entrypoint picks the role.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping curl dnsutils netcat-openbsd hping3 iperf3 \
        python3 dnsmasq openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY docker/lab/ /lab/
RUN chmod +x /lab/*.sh
