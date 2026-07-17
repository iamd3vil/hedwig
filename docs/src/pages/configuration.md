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
helo_hostname = "mail.example.com" # Public FQDN advertised in outbound HELO/EHLO
hostname = "mx.example.com"        # Hostname announced in the inbound 220 greeting and EHLO reply
```

Set `helo_hostname` in production to the public hostname for the sending IP. Many receivers expect the outbound EHLO name to be a public FQDN with matching reverse DNS. If omitted, Hedwig keeps lettre's default behavior, which uses the machine hostname.

Set `hostname` to the name clients should see when they connect to Hedwig (typically the MX name). If omitted, Hedwig uses the OS hostname.

## Outbound SMTP pool (`[server.smtp]`)

```toml
[server.smtp]
cache_size = 100  # Process-wide cache of destination MX transports (default: 100)
min_idle = 2      # Minimum idle connections per MX pool, shared by all workers (default: 2)
max_size = 10     # Maximum connections per MX pool, shared by all workers (default: 10)
```

All workers share this cache and its per-MX connection pools, so these limits are process-wide rather than multiplied by the worker count.

For new or low-volume senders, keep `min_idle` and `max_size` small so strict receivers do not see unnecessary parallel connections. The legacy `server.pool_size` setting is still accepted as a fallback for `server.smtp.cache_size`.

## Listeners (`[[server.listeners]]`)

```toml
[[server.listeners]]
addr = "0.0.0.0:465"          # Bind address and port
# Optional TLS configuration
[server.listeners.tls]
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"
mode = "implicit"             # "implicit" (default) or "starttls"

[[server.listeners]]
addr = "0.0.0.0:587"          # STARTTLS listener: accepts plaintext and
[server.listeners.tls]        # upgrades to TLS when the client asks
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"
mode = "starttls"

[[server.listeners]]
addr = "127.0.0.1:2525"       # Listener without TLS
```

Each listener can negotiate TLS in one of two ways:

- `mode = "implicit"` (the default): the TLS handshake happens as soon as the connection opens, before any SMTP traffic. Use this for SMTPS (port 465).
- `mode = "starttls"`: the connection starts in plaintext and the server advertises `STARTTLS` in its EHLO response; the session is upgraded to TLS when the client issues the `STARTTLS` command (RFC 3207). Use this for submission (port 587).

## Authentication (`[[server.auth]]`)

```toml
[[server.auth]]
username = "user1"
password = "password1"

[[server.auth]]
username = "user2"
password = "password2"
```

For advanced sections, see [DKIM](/dkim), [MTA-STS](/mta-sts), [Rate limiting](/rate-limiting), [Logging](/logging), [Metrics](/metrics), [Health checks](/health-checks), [Storage](/storage), and [Domain filtering](/domain-filtering).

For a full HUML example, see [HUML configuration example](/reference/huml-example).
