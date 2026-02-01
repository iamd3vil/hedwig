---
layout: ../../layouts/DocLayout.astro
title: Architecture
description: Hedwig SMTP server architecture and data flow.
---

# Architecture

## Overview

Hedwig is a high-performance, async SMTP server written in Rust that provides email relay functionality with advanced features including DKIM signing, retry mechanisms, and a modular storage layer. The server is designed with a modular architecture that separates concerns and provides extensibility.

## High-level architecture

```
SMTP Listeners → SMTP Callbacks → Storage Queue → Workers → Outbound SMTP Pool
```

## Core components

### Main server
- Configuration loading
- TLS setup
- Listener initialization
- Worker initialization

### SMTP callbacks
- Authentication
- Domain filtering
- Rate limiting
- Path validation

### Worker system
- Parse email
- DKIM sign
- MX lookup
- Send via SMTP

### Outbound pool
- Per-domain pooling
- TLS configuration
- Connection limits

## Data flow

### Inbound flow
1. Client connection
2. SMTP negotiation
3. Email stored in queue
4. Processing job created

### Outbound flow
1. Worker receives job
2. Parse email, remove BCC, sign DKIM
3. Resolve MX records
4. Deliver via SMTP pool

## Storage architecture

The storage trait supports multiple backends. Current implementation is filesystem-based.

Directory structure:

```
/base_path/
  queued/
  deferred/
  bounced/
  meta/
```

## Security

- Inbound TLS per listener
- Optional SMTP AUTH
- DKIM signing (RSA or Ed25519)
- Domain allow/deny filters

## Performance

- Tokio-based async runtime
- Multi-listener concurrency
- Per-domain connection pooling
- MX record caching
- Bounded channels for backpressure

## Monitoring

- Structured logging via tracing
- Prometheus metrics when enabled
- Operational signals for queue depth and delivery rates

## Deployment

- File-based configuration
- Environment override for log level
- Graceful shutdown and queue recovery
- File system permissions for storage and keys

## Extension points

- Additional storage backends (DB, S3)
- Alternative auth methods (LDAP, OAuth2)
- External filtering integrations
