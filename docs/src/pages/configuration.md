---
layout: ../layouts/DocLayout.astro
title: Configuration
description: Core server configuration and file format.
---

# Configuration

Hedwig supports TOML (default) and HUML configuration formats. The default configuration file is `config.toml`, but you can specify a different path using the `-c` flag:

```bash
hedwig -c /path/to/custom-config.toml
```

## Log configuration (`[log]`)

```toml
[log]
level = "info"          # Log levels: trace, debug, info, warn, error
format = "fmt"          # Format: "fmt" for human-readable, "json" for JSON
```

## Server configuration (`[server]`)

```toml
[server]
workers = 4                    # Number of worker threads (default: 1)
max_retries = 5               # Maximum retry attempts for failed emails (default: 5)
disable_outbound = false      # Disable outbound email delivery for testing
outbound_local = false        # Use local/insecure connections for outbound delivery
pool_size = 100              # SMTP connection pool size per domain (default: 100)
```

## Listeners (`[[server.listeners]]`)

```toml
[[server.listeners]]
addr = "0.0.0.0:25"           # Bind address and port
# Optional TLS configuration
[server.listeners.tls]
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"

[[server.listeners]]
addr = "127.0.0.1:2525"       # Second listener without TLS
```

## Authentication (`[[server.auth]]`)

```toml
[[server.auth]]
username = "user1"
password = "password1"

[[server.auth]]
username = "user2"
password = "password2"
```

For advanced sections, see [DKIM](/dkim), [Rate limiting](/rate-limiting), [Metrics](/metrics), [Health checks](/health-checks), [Storage](/storage), and [Domain filtering](/domain-filtering).

For a full HUML example, see [HUML configuration example](/reference/huml-example).
