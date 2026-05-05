---
layout: ../layouts/DocLayout.astro
title: Logging
description: Log formats, levels, and structured delivery events.
---

# Logging

Hedwig uses `tracing` for application logs. Logs can be emitted in a human-readable format for local development or as newline-delimited JSON for production log collectors.

## Basic configuration

```toml
[log]
level = "info"    # trace, debug, info, warn, error
format = "json"   # fmt or json
```

The configured `level` controls the maximum log level. You can override filtering at runtime with `HEDWIG_LOG_LEVEL`:

```bash
HEDWIG_LOG_LEVEL=debug hedwig -c config.toml
```

When `HEDWIG_LOG_LEVEL` is not set, Hedwig defaults to `hedwig=info`.

## Formats

Use `fmt` for local development:

```toml
[log]
level = "debug"
format = "fmt"
```

Use `json` when logs are shipped to a structured log pipeline:

```toml
[log]
level = "info"
format = "json"
```

JSON logs are emitted one event per line. The base shape comes from `tracing-subscriber`:

```json
{
  "timestamp": "2026-05-05T10:12:33.456789Z",
  "level": "INFO",
  "fields": {
    "message": "email delivery"
  }
}
```

Application fields are added under `fields`. The log target and source line number are not included.

## Delivery event schema

Delivery outcomes are logged as structured `INFO` events with `message = "email delivery"`.

| Field | Description |
| --- | --- |
| `job_id` | Queue job or message identifier. |
| `from_email` | Envelope sender address without angle brackets. |
| `recipient` | Recipient address without angle brackets. Deferred, bounced, and dropped events may contain a comma-separated recipient list. |
| `subject` | Parsed message subject, or an empty string when unavailable. |
| `status` | Delivery outcome: `delivered`, `deferred`, `bounced`, or `dropped`. |
| `smtp_response` | SMTP response text or internal reason for the outcome. |
| `dest_ip` | Destination MX exchange used for successful delivery. Present only for `delivered` events. |
| `queued_at` | Queue timestamp in RFC 3339 format with milliseconds, or an empty string when unavailable. |
| `logged_at` | Event timestamp in RFC 3339 format with milliseconds. |
| `delay_ms` | Milliseconds between `queued_at` and `logged_at`, or an empty string when `queued_at` is unavailable. |
| `attempt` | Delivery attempt number. Deferred retry events log the next attempt number. |

Example:

```json
{
  "timestamp": "2026-05-05T10:12:33.456789Z",
  "level": "INFO",
  "fields": {
    "message": "email delivery",
    "job_id": "01HX...",
    "from_email": "alice@example.com",
    "recipient": "bob@example.net",
    "subject": "Hello",
    "status": "delivered",
    "smtp_response": "250 OK",
    "dest_ip": "mx.example.net.",
    "queued_at": "2026-05-05T10:12:30.100Z",
    "logged_at": "2026-05-05T10:12:33.456Z",
    "delay_ms": "3356",
    "attempt": "0"
  }
}
```

## Operational events

Hedwig also emits structured fields for server lifecycle, storage, metrics, health checks, rate limiting, and MTA-STS operations. Common fields include:

- `addr`
- `attempts`
- `batch_size`
- `batch_timeout_ms`
- `domain`
- `error`
- `listener_addr`
- `mode`
- `retry_after_ms`
- `shard_id`
- `storage_type`
- `url`

These fields are event-specific and should be treated as operational diagnostics rather than a stable audit schema.
