# Multi-stage, multi-architecture build for minimal runtime image
# Supports: linux/amd64, linux/arm64
#
# Build for current platform:
#   docker build -t redact .
#
# Build multi-arch (requires buildx):
#   docker buildx build --platform linux/amd64,linux/arm64 -t redact .
#

# Stage 1: Build
# Pin to bookworm so the linked glibc matches the distroless cc-debian12 runtime.
FROM --platform=$BUILDPLATFORM rust:1.93-slim-bookworm AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETARCH

# Install build dependencies (including C++ for tokenizers/esaxx-rs)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    g++ \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Install cross-compilation tools if needed
RUN if [ "$TARGETARCH" = "arm64" ] && [ "$BUILDPLATFORM" != "linux/arm64" ]; then \
        apt-get update && apt-get install -y \
            gcc-aarch64-linux-gnu \
            g++-aarch64-linux-gnu \
            libc6-dev-arm64-cross \
        && rm -rf /var/lib/apt/lists/* \
        && rustup target add aarch64-unknown-linux-gnu; \
    elif [ "$TARGETARCH" = "amd64" ] && [ "$BUILDPLATFORM" != "linux/amd64" ]; then \
        apt-get update && apt-get install -y \
            gcc-x86-64-linux-gnu \
            g++-x86-64-linux-gnu \
            libc6-dev-amd64-cross \
        && rm -rf /var/lib/apt/lists/* \
        && rustup target add x86_64-unknown-linux-gnu; \
    fi

WORKDIR /app

# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build for target architecture with optimizations
ENV CARGO_PROFILE_RELEASE_LTO=thin
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

RUN case "$TARGETARCH" in \
        arm64) \
            if [ "$BUILDPLATFORM" = "linux/arm64" ]; then \
                RUSTFLAGS="-C target-cpu=native" cargo build --release --package redact-api; \
            else \
                RUSTFLAGS="-C linker=aarch64-linux-gnu-gcc -C target-cpu=neoverse-n1" \
                cargo build --release --package redact-api --target aarch64-unknown-linux-gnu \
                && cp target/aarch64-unknown-linux-gnu/release/redact-api target/release/; \
            fi ;; \
        amd64) \
            if [ "$BUILDPLATFORM" = "linux/amd64" ]; then \
                RUSTFLAGS="-C target-cpu=native" cargo build --release --package redact-api; \
            else \
                RUSTFLAGS="-C linker=x86_64-linux-gnu-gcc -C target-cpu=x86-64-v3" \
                cargo build --release --package redact-api --target x86_64-unknown-linux-gnu \
                && cp target/x86_64-unknown-linux-gnu/release/redact-api target/release/; \
            fi ;; \
        *) cargo build --release --package redact-api ;; \
    esac

# Stage 2: Minimal runtime using distroless
# gcr.io/distroless/cc contains only:
# - glibc
# - libgcc
# - ca-certificates
# No shell, no package manager, no OS utilities = smaller attack surface
FROM gcr.io/distroless/cc-debian12

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/redact-api /usr/local/bin/redact-api

# Expose API port
EXPOSE 8080

# Run as non-root (distroless includes nonroot user with UID 65532)
USER nonroot:nonroot

# Run the API server
ENTRYPOINT ["/usr/local/bin/redact-api"]
