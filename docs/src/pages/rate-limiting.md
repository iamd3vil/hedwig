---
layout: ../layouts/DocLayout.astro
title: Rate limiting
description: Configure per-domain rate limiting.
---

# Rate limiting

Hedwig supports per-domain rate limiting using a token bucket algorithm.

All workers share one set of domain token buckets, so configured limits apply process-wide rather than once per worker.

## Domain-specific limits

```toml
[server.rate_limits]
enabled = true

[server.rate_limits.domain_limits]
"gmail.com" = 30
"outlook.com" = 25
"internal.com" = 200
```

When `default_limit` is omitted, only domains listed under `domain_limits` are rate limited. All other domains are unrestricted.

Setting `default_limit = 0` has the same effect as omitting it. A zero domain-specific limit also leaves that domain unrestricted.

## Default limit for unconfigured domains

```toml
[server.rate_limits]
enabled = true
default_limit = 60  # emails per minute for unconfigured domains

[server.rate_limits.domain_limits]
"gmail.com" = 30    # overrides the default
```

Benefits:
- Prevents being rate-limited by destination servers
- Maintains sender reputation
- Non-blocking workers continue other tasks
