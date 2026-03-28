---
layout: ../layouts/DocLayout.astro
title: Introduction
description: What Hedwig is, what it does, and what it does not.
---

# Introduction

Hedwig is a high-performance, minimalist SMTP server implemented in Rust. It provides a streamlined solution for receiving, queuing, and forwarding emails to destination SMTP servers.

Configuration is supported in TOML (default) and HUML formats.

## What Hedwig is

- A fast SMTP relay focused on receiving and forwarding mail.
- A durable queue backed by the filesystem.
- A clean TOML configuration surface for listeners, auth, and policy.

## What Hedwig is not

- A full mail server suite (no mailbox delivery, IMAP/POP, or user management).
- A feature-heavy MTA; it stays intentionally small.

## Key features

- Fast and efficient processing with an async core.
- Persistent queue for reliability across restarts.
- Forward-only behavior focused on delivery.
- DKIM, TLS, MTA-STS (RFC 8461), and SMTP authentication support.
- Per-domain rate limiting to protect sender reputation.

## Where to go next

- Start with [Installation](/installation) and [Quickstart](/quickstart).
- See [Configuration](/configuration) for detailed setup.
- Dive into [Architecture](/architecture/overview) for internals.
