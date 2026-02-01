---
layout: ../layouts/DocLayout.astro
title: Metrics
description: Prometheus metrics and monitoring.
---

# Metrics

Hedwig exposes Prometheus-compatible metrics over HTTP when configured.

## Enable metrics

```toml
[server.metrics]
bind = "0.0.0.0:9090"  # HTTP listener for /metrics
```

- Endpoint: `GET /metrics`
- Protocol: plain HTTP (place behind a firewall or reverse proxy if exposed)

## Quick check

```bash
curl -s http://localhost:9090/metrics | head
```

## Exported metrics (examples)

- `hedwig_queue_depth`
- `hedwig_emails_received_total`
- `hedwig_emails_sent_total`
- `hedwig_worker_jobs_processed_total`
- `hedwig_send_attempts_total{domain,status}`
