# Build Stage
FROM rust:1.86 AS builder

WORKDIR /usr/src/hedwig

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime Stage
FROM ubuntu:latest

# Set working directory
WORKDIR /app

# Install necessary dependencies
RUN apt-get update && \
    apt-get install -y libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/hedwig/target/release/hedwig .

# Set the entrypoint
ENTRYPOINT ["./hedwig"]
