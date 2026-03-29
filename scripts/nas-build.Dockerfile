# SPDX-License-Identifier: AGPL-3.0-or-later
#
# nas-build.Dockerfile — Static musl cross-compilation for secfirstNAS (aarch64)
#
# Produces a fully static aarch64 binary that runs on Alpine Linux (UNVR).
#
# Usage (called by nas-deploy.sh, not directly):
#   docker build -f scripts/nas-build.Dockerfile -t sfnas-builder .
#   docker run --rm -v "$PWD/target:/build/target" sfnas-builder

FROM rust:1-alpine AS builder

# musl-dev: standard C headers
# clang/lld: cross-compiler for ring crate's C/asm (targets aarch64 without a full cross-gcc)
# perl/make: required by openssl-sys (SQLCipher vendored OpenSSL build)
RUN apk add --no-cache musl-dev clang lld perl make

RUN rustup target add aarch64-unknown-linux-musl

WORKDIR /build

# Copy manifests and config first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY patches patches

# Copy all workspace crates (Cargo needs the full workspace to resolve)
COPY crates crates

# Use rust-lld (ships with Rust) as the cross-linker — no external
# aarch64 cross-gcc needed.  Override the .cargo/config.toml linker
# setting via environment so it works inside this container.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="rust-lld"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C linker-flavor=ld.lld"
# clang as C cross-compiler for ring crate (compiles C/asm for aarch64)
ENV CC_aarch64_unknown_linux_musl="clang"
ENV CFLAGS_aarch64_unknown_linux_musl="--target=aarch64-unknown-linux-musl"

RUN cargo build \
    --release \
    --target aarch64-unknown-linux-musl \
    --bin secfirstnas \
    -p sfnas-cli
