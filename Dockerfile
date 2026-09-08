# syntax=docker/dockerfile:1

# ---- Builder ----
FROM rust:1.98.0 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --locked

# ---- Runtime ----
FROM debian:trixie-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/hedwig /usr/local/bin/hedwig
ENTRYPOINT ["hedwig"]
