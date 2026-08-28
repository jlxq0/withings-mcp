# syntax=docker/dockerfile:1.7

# Multi-stage build → distroless runtime. Final image ~20-25 MiB.
# withings-mcp has no C build dependencies and no bundled database. It is a
# stateless Withings MCP server built with pure Rust and rustls.

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
    rm -rf src target/release/deps/withings_mcp* target/release/withings-mcp*

COPY src ./src
RUN cargo build --release --locked

# Distroless runtime: no shell, no apt. `cc` variant ships glibc + ca-certs,
# which we need for HTTPS to Withings.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:e2d29aec8061843706b7e484c444f78fafb05bfe47745505252b1769a05d14f1

WORKDIR /app
COPY --from=builder /build/target/release/withings-mcp /app/withings-mcp

# Non-root by default (distroless `nonroot`, UID 65532).
USER nonroot:nonroot

EXPOSE 3000
ENTRYPOINT ["/app/withings-mcp"]
