# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1.97.0-bookworm AS web-builder
ARG WASM_BINDGEN_VERSION=0.2.126
ARG WASM_RUST_TOOLCHAIN=nightly-2026-07-17
WORKDIR /app
RUN rustup toolchain install "${WASM_RUST_TOOLCHAIN}" \
        --profile minimal \
        --component rust-src \
    && cargo install wasm-bindgen-cli --version "${WASM_BINDGEN_VERSION}" --locked
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo +"${WASM_RUST_TOOLCHAIN}" \
        -Z build-std=std,panic_abort \
        build --locked --release --lib --target wasm64-unknown-unknown \
    && wasm-bindgen target/wasm64-unknown-unknown/release/session_bridge.wasm \
        --target web \
        --no-typescript \
        --out-dir src/static/assets \
        --out-name session_bridge_web

FROM rust:1.97.0-bookworm AS server-builder
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang cmake \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY --from=web-builder /app/src src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --locked --release --bin session-bridge \
    && cp target/release/session-bridge /usr/local/bin/session-bridge

FROM debian:bookworm-slim AS app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system session-bridge \
    && useradd --system --gid session-bridge --no-create-home session-bridge
COPY --from=server-builder /usr/local/bin/session-bridge /usr/local/bin/session-bridge
USER session-bridge:session-bridge
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/session-bridge"]
