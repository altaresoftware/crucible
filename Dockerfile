# Copyright (c) Altare Technologies Limited. All rights reserved.

# Build stage
FROM rust:1.75-slim as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml ./

# Copy source code
COPY src ./src

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 crucible

# Copy binary from builder
COPY --from=builder /app/target/release/crucible /usr/local/bin/crucible

# Set ownership
RUN chown crucible:crucible /usr/local/bin/crucible

# Create config directory
RUN mkdir -p /etc/crucible && \
    chown crucible:crucible /etc/crucible

# Switch to non-root user
USER crucible

WORKDIR /etc/crucible

# Expose ports
EXPOSE 80 443

# Run the binary
CMD ["crucible"]
