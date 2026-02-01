---
layout: ../layouts/DocLayout.astro
title: Storage
description: Configure filesystem storage and retention policies.
---

# Storage

```toml
[storage]
storage_type = "fs"                      # Storage type: "fs" (filesystem)
base_path = "/var/spool/hedwig"         # Base directory for email storage

[storage.cleanup]
bounced_retention = "7d"                 # Remove bounced messages after 7 days
deferred_retention = "2d"                # Remove deferred messages after 2 days
interval = "1h"                          # Run the cleanup task hourly
```

- All keys inside `[storage.cleanup]` are optional; omit them to disable specific cleanups
- Retention values accept human-readable durations (e.g., `"24h"`, `"5m"`)
- The cleanup task runs on a background interval and also executes once during startup
