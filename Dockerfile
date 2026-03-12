FROM node:22-bookworm-slim AS frontend

WORKDIR /web
COPY web/package*.json .
RUN npm ci
COPY web/ .
RUN npm run build

# ---------------------------------------------------------------------------
FROM rust:1.87-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates crates

RUN cargo build --release --bin sfgw

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/sfgw /usr/local/bin/sfgw
COPY --from=frontend /web/dist /usr/share/sfgw/web

EXPOSE 8443 8080

ENV SFGW_DB_PATH=/data/sfgw.db
ENV SFGW_LISTEN_ADDR=0.0.0.0:8443
ENV SFGW_WEB_DIR=/usr/share/sfgw/web

VOLUME /data

CMD ["sfgw"]
