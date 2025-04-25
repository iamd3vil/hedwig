<div align="right">
  <a href="https://zerodha.tech">
    <img src="https://zerodha.tech/static/images/github-badge.svg" width=140 />
  </a>
</div>

<div align="center">
  <img src="logo.png" alt="Hedwig" width="75"/>
  <h1>Hedwig</h1>
</div>

<p align="center">
   Hedwig - A high-performance, minimalist SMTP server implemented in Rust.
</p>

---

## Overview

This SMTP server is designed with a focus on speed and simplicity. It provides a streamlined solution for receiving, queuing, and forwarding emails to destination SMTP servers.

## Key Features

- **Fast and Efficient**: Optimized for high-speed email processing.
- **Minimalist Design**: Focuses on core SMTP functionality without unnecessary complexities.
- **Persistent Queue**: Emails are queued on the filesystem, ensuring durability across server restarts.
- **Forward-Only**: Specializes in receiving and forwarding emails, not full SMTP functionality.
- **Security Features**: Supports DKIM, TLS, and SMTP authentication.

## Getting Started

### Prerequisites

- Rust toolchain (1.70 or later)
- A domain name (for DKIM setup)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/iamd3vil/hedwig.git
   cd hedwig
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Create a configuration file (config.toml):

   ```toml
   [server]
   addr = "0.0.0.0:25"  # SMTP server address
   workers = 4          # Number of worker threads
   pool_size = 100      # Outbund Connection pool size
   max_retries = 5      # Maximum number of retries for deferred emails (Default is 5)


   # Optional TLS configuration
   [server.tls]
   cert_path = "/path/to/cert.pem"
   key_path = "/path/to/key.pem"

   # Optional SMTP authentication
   [[server.auth]]
   username = "your_username"
   password = "your_password"

   # Optional DKIM configuration
   [server.dkim]
   domain = "yourdomain.com"
   selector = "default"
   private_key = "/path/to/dkim/private.key"

   [storage]
   storage_type = "fs"
   base_path = "/var/lib/hedwig/mail"
   ```

4. Run the server:
   ```bash
   HEDWIG_LOG_LEVEL=info ./target/release/hedwig
   ```

## Configuration

### Server Configuration

- `addr`: Server address and port (default: "0.0.0.0:25")
- `workers`: Number of worker threads (optional)
- `pool_size`: Maximum number of concurrent connections (optional)
- `disable_outbound`: Disable outbound email delivery (optional)
- `outbound_local`: Only allow local outbound delivery (optional)

### TLS Configuration (Optional)

```toml
[server.tls]
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"
```

### Authentication (Optional)

Multiple users can be configured for SMTP authentication. Just add multiple `[[server.auth]]` sections to the configuration file.

```toml
[[server.auth]]
username = "your_username"
password = "your_password"
```

### Storage Configuration

```toml
[storage]
storage_type = "filesystem"  # Currently only filesystem storage is supported
base_path = "/var/lib/hedwig/mail"
```

## DKIM Setup

DKIM (DomainKeys Identified Mail) allows receiving mail servers to verify that emails were sent by an authorized sender.

### Generating DKIM Keys

1. Generate a private key:

   ```bash
   openssl genrsa -out private.key 4096
   ```

2. Extract the public key:

   ```bash
   openssl rsa -in private.key -pubout -outform der 2>/dev/null | openssl base64 -A
   ```

3. Add a DNS TXT record for your domain:

   ```
   selector._domainkey.yourdomain.com. IN TXT "v=DKIM1; k=rsa; p=[public_key]"
   ```

   Replace `selector` with your chosen selector name and `[public_key]` with the base64-encoded public key.

4. Configure DKIM in config.toml:
   ```toml
   [server.dkim]
   domain = "yourdomain.com"
   selector = "selector"
   private_key = "/path/to/private.key"
   ```

## Environment Variables

- `HEDWIG_LOG_LEVEL`: Set logging level (error, warn, info, debug, trace)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the AGPL v3 License - see the LICENSE file for details.
