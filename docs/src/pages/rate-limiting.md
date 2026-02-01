---
layout: ../layouts/DocLayout.astro
title: Rate limiting
description: Configure per-domain rate limiting.
---

# Rate limiting

Hedwig supports per-domain rate limiting using a token bucket algorithm.

## Basic configuration

```toml
[server.rate_limits]
enabled = true
default_limit = 60  # emails per minute for all domains
```

## Domain-specific limits

```toml
[server.rate_limits]
enabled = true
default_limit = 60

[server.rate_limits.domain_limits]
"gmail.com" = 30
"outlook.com" = 25
"internal.com" = 200
```

Benefits:
- Prevents being rate-limited by destination servers
- Maintains sender reputation
- Non-blocking workers continue other tasks
