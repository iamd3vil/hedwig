# Hedwig SMTP Server Configuration

This document provides detailed information about configuring the Hedwig SMTP server.

## Configuration File Format

Hedwig uses TOML configuration format. The default configuration file is `config.toml`, but you can specify a different path using the `-c` flag:

```bash
hedwig -c /path/to/custom-config.toml
```

## Configuration Sections

### Log Configuration (`[log]`)

Controls logging output format and level.

```toml
[log]
level = "info"          # Log levels: trace, debug, info, warn, error
format = "fmt"          # Format: "fmt" for human-readable, "json" for JSON
```

### Server Configuration (`[server]`)

Core server settings including listeners, workers, authentication, and rate limiting.

```toml
[server]
workers = 4                    # Number of worker threads (default: 1)
max_retries = 5               # Maximum retry attempts for failed emails (default: 5)
disable_outbound = false      # Disable outbound email delivery for testing
outbound_local = false        # Use local/insecure connections for outbound delivery
pool_size = 100              # SMTP connection pool size per domain (default: 100)
```

#### Listeners (`[[server.listeners]]`)

Define network listeners for incoming SMTP connections. You can configure multiple listeners with different settings.

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

#### Authentication (`[server.auth]`)

Optional SMTP authentication configuration. Multiple users can be defined.

```toml
[[server.auth]]
username = "user1"
password = "password1"

[[server.auth]]
username = "user2"
password = "password2"
```

#### DKIM Signing (`[server.dkim]`)

Configure DKIM signing for outbound emails.

```toml
[server.dkim]
domain = "example.com"                    # Signing domain
selector = "default"                      # DKIM selector
private_key = "/path/to/dkim-private.pem" # Path to DKIM private key
key_type = "rsa"                         # Key type: "rsa" or "ed25519"
```

To generate DKIM keys:
```bash
hedwig dkim-generate
```

#### Rate Limiting (`[server.rate_limits]`)

**NEW FEATURE**: Configure per-domain rate limiting to control email sending rates.

```toml
[server.rate_limits]
enabled = true                           # Enable rate limiting (default: false)
default_limit = 60                       # Default emails per minute (default: 60)

# Domain-specific rate limits (optional)
[server.rate_limits.domain_limits]
"gmail.com" = 30                        # Gmail: 30 emails/minute
"outlook.com" = 20                      # Outlook: 20 emails/minute
"yahoo.com" = 15                        # Yahoo: 15 emails/minute
"corporate.com" = 120                   # Corporate domain: 120 emails/minute
```

**Rate Limiting Details:**
- Uses token bucket algorithm for smooth rate limiting
- Limits are applied per destination domain
- Multiple workers share the same rate limits safely
- When rate limited, workers wait for tokens to become available
- Tokens refill continuously (e.g., 60/minute = 1 token per second)

### Storage Configuration (`[storage]`)

Configure email storage backend.

```toml
[storage]
storage_type = "fs"                      # Storage type: "fs" (filesystem)
base_path = "/var/spool/hedwig"         # Base directory for email storage

# Optional retention policy for cleaning up local spool data
[storage.cleanup]
bounced_retention = "7d"                 # Remove bounced messages after 7 days
deferred_retention = "2d"                # Remove deferred messages after 2 days
interval = "1h"                          # Run the cleanup task hourly
```

- All keys inside `[storage.cleanup]` are optional; omit them to disable specific cleanups
- Retention values accept human-readable durations (e.g., `"24h"`, `"5m"`)
- The cleanup task runs on a background interval and also executes once during startup

### Domain Filtering (`[[filters]]`)

Configure domain-based filtering for incoming emails.

```toml
[[filters]]
type = "from_domain_filter"              # Filter type: "from_domain_filter" or "to_domain_filter"
domain = ["allowed1.com", "allowed2.com"] # List of domains
action = "allow"                         # Action: "allow" or "deny"

[[filters]]
type = "to_domain_filter"
domain = ["spam.com", "blocked.com"]
action = "deny"
```

## Complete Example Configuration

```toml
# Logging configuration
[log]
level = "info"
format = "fmt"

# Server configuration
[server]
workers = 4
max_retries = 3
pool_size = 50

# Multiple listeners
[[server.listeners]]
addr = "0.0.0.0:25"
[server.listeners.tls]
cert_path = "/etc/hedwig/server.crt"
key_path = "/etc/hedwig/server.key"

[[server.listeners]]
addr = "127.0.0.1:2525"  # Local plaintext listener

# Authentication
[[server.auth]]
username = "smtp_user"
password = "secure_password"

# DKIM signing
[server.dkim]
domain = "example.com"
selector = "hedwig"
private_key = "/etc/hedwig/dkim-private.pem"
key_type = "rsa"

# Rate limiting
[server.rate_limits]
enabled = true
default_limit = 60

[server.rate_limits.domain_limits]
"gmail.com" = 30
"outlook.com" = 25
"yahoo.com" = 20

# Storage
[storage]
storage_type = "fs"
base_path = "/var/spool/hedwig"

[storage.cleanup]
bounced_retention = "7d"
deferred_retention = "2d"
interval = "1h"

# Domain filtering
[[filters]]
type = "from_domain_filter"
domain = ["trusted1.com", "trusted2.com"]
action = "allow"

[[filters]]
type = "to_domain_filter"
domain = ["spam.com"]
action = "deny"
```

## Environment Variables

You can also control logging via environment variables:

- `HEDWIG_LOG_LEVEL`: Override log level (e.g., `HEDWIG_LOG_LEVEL=debug`)

## Security Considerations

1. **File Permissions**: Ensure DKIM private keys have restricted permissions (600)
2. **TLS Certificates**: Use valid TLS certificates for production
3. **Authentication**: Use strong passwords for SMTP authentication
4. **Network**: Bind to localhost for development, specific interfaces for production
5. **Rate Limiting**: Configure appropriate rate limits to avoid being blocked by destination servers

## Monitoring and Troubleshooting

- Use `info` level logging for production monitoring
- Use `debug` level for troubleshooting email delivery issues
- Monitor rate limiting logs to adjust limits as needed
- Check DKIM signature validation with online tools
