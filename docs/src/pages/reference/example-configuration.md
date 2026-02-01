---
layout: ../../layouts/DocLayout.astro
title: Example configuration
description: Complete example `config.toml`.
---

# Example configuration

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

# Metrics
[server.metrics]
bind = "0.0.0.0:9090"

# Health checks
[server.health]
bind = "0.0.0.0:8080"

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
