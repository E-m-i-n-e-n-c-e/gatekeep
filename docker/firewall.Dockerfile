# ── Build stage: compile the engine and run the unit tests ──
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ cmake make pkg-config ca-certificates \
        libnetfilter-queue-dev nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

# cpp-httplib is a single header; pinned to a release tag.
ADD https://raw.githubusercontent.com/yhirose/cpp-httplib/v0.18.3/httplib.h /usr/local/include/httplib.h

WORKDIR /src
COPY engine/ .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j"$(nproc)" \
    && ./build/gatekeep_tests

# ── Runtime stage ──
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libnetfilter-queue1 nftables conntrack iproute2 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/gatekeep /usr/local/bin/gatekeep
COPY nft/gatekeep.nft /etc/gatekeep/gatekeep.nft
COPY config/policy.json /etc/gatekeep/policy.json
COPY docker/firewall-entrypoint.sh /entrypoint.sh

EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s CMD curl -fs http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/entrypoint.sh"]
