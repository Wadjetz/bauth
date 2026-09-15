# syntax=docker/dockerfile:1

FROM rust:1.98-slim-trixie AS chef
RUN cargo install cargo-chef --locked --version 0.1.77
WORKDIR /build

# Dependency recipe: only changes when Cargo.toml or Cargo.lock change.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# `query!` checks SQL against bauth_server/.sqlx instead of a live database.
# Run `cargo sqlx prepare` in bauth_server/ after changing a query.
ENV SQLX_OFFLINE=true
COPY --from=planner /build/recipe.json recipe.json
# Dependencies get their own cached layer: code changes don't rebuild them.
RUN cargo chef cook --release --locked --recipe-path recipe.json --package bauth_server
COPY . .
RUN cargo build --release --locked --package bauth_server

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --no-create-home bauth

# Migrations are embedded in the binary and run at startup.
COPY --from=builder /build/target/release/bauth_server /usr/local/bin/bauth

USER bauth
# Mount the clients configuration at /etc/bauth/bauth.toml; secrets come from the environment.
ENV BAUTH_BIND_ADDR=0.0.0.0:8401 \
    BAUTH_CONFIG=/etc/bauth/bauth.toml
EXPOSE 8401
CMD ["bauth"]
