# syntax=docker/dockerfile:1.7
# Rust gateway image. The dashboard is built first and embedded into the
# release binary by keyla-gateway's build script, so the runtime image
# carries one executable plus CA certificates.

FROM oven/bun:1.4.2-alpine AS dashboard

WORKDIR /build
COPY package.json bun.lock ./
COPY dashboard/package.json ./dashboard/package.json
RUN bun install --frozen-lockfile
COPY dashboard ./dashboard
RUN bun run dashboard:build

FROM rust:1.90-bookworm AS builder

WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
COPY --from=dashboard /build/dist/dashboard ./dist/dashboard
RUN cargo build --release --locked -p keyla-cli --bin keyla

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 keyla \
    && useradd --system --uid 10001 --gid keyla --home-dir /app --shell /usr/sbin/nologin keyla \
    && mkdir -p /app/data \
    && chown -R keyla:keyla /app

WORKDIR /app
COPY --from=builder --chown=keyla:keyla /build/target/release/keyla /usr/local/bin/keyla
COPY --chown=keyla:keyla LICENSE /app/LICENSE

ENV KEYLA_BIND_HOST=0.0.0.0 \
    KEYLA_DATA_DIR=/app/data \
    PORT=12800

USER keyla
EXPOSE 12800
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-12800}/health/ready" >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/keyla"]
CMD ["up"]
