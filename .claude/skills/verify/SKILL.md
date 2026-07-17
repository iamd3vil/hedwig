---
name: verify
description: Verify hedwig changes end-to-end by driving real SMTP delivery through the dev DNS + fake-MTA docker harness and observing spool/log state.
---

# Verifying hedwig end-to-end

Hedwig's outbound path needs MX resolution + a destination MTA on port 25,
so verification runs on the `smtp_test` docker network from `dev/`.
`net.ipv4.ip_unprivileged_port_start=53` on this host means port 25 can't
be bound locally — everything runs in containers.

## Build

Host toolchain differs from the container's; build inside the dev image with
an isolated target dir so the host `target/` cache isn't clobbered:

```sh
docker run --rm -v "$PWD":/app -v <scratch>/target:/app/target-e2e \
  -e CARGO_TARGET_DIR=/app/target-e2e -w /app dev-smtp:latest \
  cargo build --release --bin hedwig
```

(`dev-smtp:latest` is the compose-built image from `dev/Dockerfile.dev`;
`docker compose -f dev/docker-compose.yml build smtp` if missing.)

## Harness

- DNS: `docker start dev-dns-1` (or compose up the `dns` service) —
  CoreDNS at 172.30.0.2; `*.throttle.test` MX → 172.30.0.4.
- Destination MTA: run a python container pinned to 172.30.0.4 on
  `smtp_test`. For retry-lifecycle tests, use a script that keys behavior
  on recipient local part at RCPT TO (421 defer / 555 bounce / 250 accept /
  hang) with a per-recipient attempt counter, and logs every interaction.
  `dev/fake-mta/throttle.py` is the always-421 original to crib from.
- Hedwig: run the built binary in `dev-smtp:latest` with
  `--network smtp_test --dns 172.30.0.2`, publish 2526, and bind-mount a
  scratch spool dir to inspect `queued/`/`deferred/`/`bounced/` from the
  host. Config essentials: `outbound_local = true` (plaintext SMTP),
  `disable_outbound = false`, `storage_type = "fs"`, `format = "json"` logs.

## Timing constants (not configurable)

- Deferred scan interval: 30s; retry backoff: 60s × 2^attempts.
  With `max_retries = 2` a full defer→exhaust→bounce cycle is ~4 min.
- Hung outbound connections time out after ~60s (lettre default) and defer —
  a hang recipient freezes a retry in `queued/` for that window (useful for
  kill-mid-retry restart tests; use SIGKILL for crash semantics).

## What to read

- Delivery outcomes: `docker logs <hedwig> | rg '"email delivery"'` —
  fields `recipient`, `status` (delivered/deferred/bounced/dropped),
  `attempt`, `smtp_response`.
- Retry schedule ground truth: the fake MTA's own log.
- Spool state: the bind-mounted dir; meta files are
  `deferred/<msg_id>.meta.json` and carry the attempt counter.

Alpine (musl) containers misreport DNS from the CoreDNS templates —
use glibc images (`python:3.12-slim`) for probe scripts; hedwig itself
(hickory-resolver) is unaffected.
