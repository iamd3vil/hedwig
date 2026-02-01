---
layout: ../layouts/DocLayout.astro
title: Quickstart
description: Run Hedwig with a minimal configuration.
---

# Quickstart

Install the release binary first: see [Installation](/installation).

## Minimal config

Create a `config.toml` (or a HUML config if you prefer that format):

```toml
[server]
workers = 4
pool_size = 100
max_retries = 5

[[server.listeners]]
addr = "0.0.0.0:25"

[storage]
storage_type = "fs"
base_path = "/var/lib/hedwig/mail"
```

## Run

```bash
HEDWIG_LOG_LEVEL=info ./hedwig
```

Next: customize listeners, auth, DKIM, and policies in [Configuration](/configuration).
