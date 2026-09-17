---
layout: ../layouts/DocLayout.astro
title: Quickstart
description: Run Hedwig with a minimal configuration.
---

# Quickstart

Install the release binary or pull the Docker image: see [Installation](/installation).

## Minimal config

Create a `config.toml` (or a HUML config if you prefer that format):

```toml
[server]
workers = 4
max_retries = 5

[server.smtp]
min_idle = 2
max_size = 10

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

## Run with Docker

Use the `config.toml` above. Its listener binds to `0.0.0.0:25` inside the
container, and its queue path is under the mounted data volume:

```bash
docker run -d --name hedwig --restart unless-stopped \
  -p 127.0.0.1:2525:25 \
  --mount type=bind,src="$(pwd)/config.toml",dst=/etc/hedwig/config.toml,readonly \
  --mount type=volume,src=hedwig-data,dst=/var/lib/hedwig \
  -e HEDWIG_LOG_LEVEL=info \
  ghcr.io/iamd3vil/hedwig:0.12.3 -c /etc/hedwig/config.toml

docker logs -f hedwig
```

This exposes SMTP on the host at `127.0.0.1:2525` for local testing. Adjust the
published address and port for your deployment. The named volume keeps queued
mail when the container is replaced. Mount any TLS certificates or DKIM keys
read-only at the paths specified in your configuration.

Next: customize listeners, auth, DKIM, and policies in [Configuration](/configuration).
