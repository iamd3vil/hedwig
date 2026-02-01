---
layout: ../layouts/DocLayout.astro
title: Health checks
description: Liveness probe for orchestration platforms.
---

# Health checks

Enable a simple HTTP liveness probe so orchestration platforms can monitor Hedwig.

```toml
[server.health]
bind = "0.0.0.0:8080"  # Address that serves /healthz
```

Requests to `/healthz` return `200 OK` while the server is running and `503 Service Unavailable` during shutdown.
