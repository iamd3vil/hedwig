---
layout: ../../layouts/DocLayout.astro
title: Architecture
description: Hedwig SMTP server architecture and data flow.
---

# Architecture

## Overview

Hedwig is a high-performance, async SMTP server written in Rust that provides
email relay functionality with DKIM signing, retry mechanisms, MTA-STS
enforcement, and a modular storage layer.

For the deep, diagrammed walkthrough of the durable log queue — on-disk
formats, scheduling, crash recovery, garbage collection, and the durability
model — see [`ARCHITECTURE.md`](https://github.com/iamd3vil/hedwig/blob/main/ARCHITECTURE.md)
in the repository root. This page is the short orientation.

## Two queue architectures

Hedwig has two queueing paths, selected by `storage.storage_type`:

### Log queue (`storage_type = "log"`)

```
SMTP listeners → callbacks → append writers → segmented log on disk
                                                    │
                                     dispatcher (discovery, retries,
                                     rate gating, GC/compaction)
                                                    │
                                          workers pull claims
                                                    │
                                          outbound SMTP pool
```

Complete messages are appended to sharded, segmented logs; `250 OK` is
returned as soon as the record reaches the kernel page cache. A single
dispatcher discovers appended records via per-shard cursors, hands
payload-free claims to pulling workers, schedules retries by due time, and
reclaims disk (fully delivered segments are deleted immediately; partially
dead ones are compacted). Inbound acceptance is bounded by disk append
throughput — slow or stalled outbound cannot block it.

- Retries: exponential backoff scheduled in-process (no directory scans);
  after `max_retries` the message bounces terminally.
- Partial multi-recipient failures re-send only to recipients that have not
  yet accepted the message.
- Bounced messages are archived as plain files under `bounced/` and honor
  `[storage.cleanup]` retention.
- Durability: process crashes lose nothing; a machine crash or power loss
  may lose the most recently acknowledged messages (documented tradeoff).
  Destructive operations are fsync-guarded, so older queued mail is never
  at risk.
- Inspect a live spool with `hedwig queue list|show|stats`; migrate a legacy
  spool with `hedwig queue migrate`.

### Legacy queue (`storage_type = "fs"`)

```
SMTP listeners → callbacks → storage (one file/row per message)
                                  │
                       bounded in-memory job channel
                                  │
                          workers consume jobs
```

One file per message plus a bounded channel between acceptance and
workers. Acceptance waits for a channel slot, so sustained slow outbound
eventually backpressures inbound. Deferred messages are re-queued by a
periodic scan. This path is unchanged and remains the default.

## Core components

- **Main server** — configuration, TLS setup, listeners, worker/dispatcher
  startup, graceful shutdown.
- **SMTP callbacks** — authentication, domain filtering, disk-reserve check,
  queue admission.
- **Workers** — parse, strip Bcc, DKIM-sign, resolve MX, apply MTA-STS,
  deliver through the per-domain connection pool, classify outcomes.
- **Outbound pool** — per-domain pooling, TLS, connection limits, MX caching.

## Security

- Inbound TLS per listener (implicit or STARTTLS)
- Optional SMTP AUTH
- DKIM signing (RSA or Ed25519)
- MTA-STS policy enforcement
- Domain allow/deny filters

## Monitoring

- Structured logging via tracing (JSON or plain)
- Prometheus metrics when enabled, including queue depth, dispatcher lag,
  segment/GC statistics, and delivery outcomes

## Deployment

- File-based configuration (TOML or HUML)
- Environment override for log level
- Graceful shutdown with state checkpointing and queue recovery
- Exclusive spool lock: one process per spool root
