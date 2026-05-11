# syntax=docker/dockerfile:1.7
# Multi-stage: cache deps via dummy crate, then build the real binary,
# then ship a minimal debian-slim runtime image.

FROM rust:1.83-slim-bookworm AS builder
WORKDIR /build

# Cache deps: copy manifests, build a stub, then replace with real source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY src ./src
# Touch main.rs so cargo rebuilds it (mtime would otherwise match the stub).
RUN touch src/main.rs && cargo build --release && \
    strip target/release/agent-firewall

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /data
COPY --from=builder /build/target/release/agent-firewall /app/agent-firewall

ENV PORT=8080 SLED_PATH=/data/firewall.sled RUST_LOG=info
EXPOSE 8080
CMD ["/app/agent-firewall"]
