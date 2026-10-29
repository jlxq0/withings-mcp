# syntax=docker/dockerfile:1.7

# Multi-stage build → distroless runtime. Final image ~20-25 MiB.
# withings-mcp has no C build dependencies and no bundled database. It is a
# Withings MCP server built with pure Rust and rustls; token state stays on
# separately configured persistent storage.

ARG RUST_VERSION=1.93
# Digest pinned to rust:1.93-bookworm (OCI index). Update via Renovate.
FROM rust:${RUST_VERSION}-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS builder

WORKDIR /build

# Cache dependencies separately from source: copy manifest first, build a
# stub, then copy real source. `cargo build` only re-runs the slow dependency
# compile if Cargo.toml / Cargo.lock change.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && \
    echo 'fn main() { println!("dep stub"); }' > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src target/release/deps/hevy_mcp* target/release/withings-mcp*

COPY src ./src
RUN cargo build --release --locked

# Distroless runtime: no shell, no apt. `cc` variant ships glibc + ca-certs,
# which we need for HTTPS to Withings.
# The current Debian 12 distroless tag still contains vulnerable OpenSSL.
# Debian 13 supplies the fixed package; final-image scanning remains mandatory.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e

ARG APP_VERSION=0.0.0-dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="withings-mcp" \
      org.opencontainers.image.source="https://forge.oddie.app/jlxq0/withings-mcp" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

WORKDIR /app
COPY --from=builder /build/target/release/withings-mcp /app/withings-mcp

# Non-root by default (distroless `nonroot`, UID 65532).
USER nonroot:nonroot

EXPOSE 3000
ENTRYPOINT ["/app/withings-mcp"]
