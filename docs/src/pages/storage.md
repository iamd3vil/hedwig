---
layout: ../layouts/DocLayout.astro
title: Storage
description: Configure filesystem storage and retention policies.
---

# Storage

```toml
[storage]
storage_type = "log"                     # "log" (default) or "fs" (legacy filesystem)
base_path = "/var/spool/hedwig"          # Base directory for email storage
auto_migrate = false                     # Migrate legacy fs queued/deferred mail on startup when true

[storage.cleanup]
bounced_retention = "7d"                 # Remove bounced messages after 7 days
deferred_retention = "2d"                # Remove deferred messages after 2 days
interval = "1h"                          # Run the cleanup task hourly
```

- All keys inside `[storage.cleanup]` are optional; omit them to disable specific cleanups
- Retention values accept human-readable durations (e.g., `"24h"`, `"5m"`)
- The cleanup task runs on a background interval and also executes once during startup

## Log queue backend

`storage_type = "log"` — the default when `storage_type` is omitted —
selects the durable log queue: complete messages are
stored in segmented append-only logs under `<base_path>/spool/`, and SMTP
`250 OK` is returned as soon as the record is written — inbound acceptance
is bounded by disk append throughput, not by outbound delivery speed.
Retries are scheduled by due time (no periodic spool scans), and retries
after a partial multi-recipient failure re-send only to the recipients that
have not yet accepted the message.

```toml
[storage]
storage_type = "log"
base_path = "/var/spool/hedwig"          # spool/ (queue) + bounced/ (archive)

[queue]                                   # all optional; defaults shown
append_writers = 1                        # log shards; change requires an empty queue
pending_append_bytes = 134217728          # in-memory admission buffer bound (bytes)
segment_target_bytes = 67108864           # seal active segments at this size
compaction_dead_ratio = 0.5               # compact sealed segments this dead
compaction_min_age = "60s"                # leave fresh segments alone
disk_reserve_bytes = 1073741824           # reject mail when free disk drops below
checkpoint_interval_bytes = 8388608       # checkpoint cadence per shard
```

**Durability tradeoff:** acknowledged mail is durable against process
crashes and restarts, but the queue does not `fsync` per message — a machine
crash or power loss can lose the most recently acknowledged messages. This
is a deliberate throughput tradeoff. Destructive operations (segment
deletion, compaction, checkpoint truncation) do use `fsync` barriers, so a
power loss can never destroy older queued mail.

**Disk behavior:** disk use is proportional to the live backlog plus
not-yet-reclaimed garbage. Fully delivered segments are deleted as soon as
their last message completes; partially dead segments are compacted once
`compaction_dead_ratio` is exceeded. When free space falls below
`disk_reserve_bytes`, new mail is rejected with a transient `452`.

Bounced messages are archived as regular files under `bounced/` (same layout
as the filesystem backend) and honor `[storage.cleanup]` retention.

Inspect a spool — including a live one — with the built-in CLI:

```sh
hedwig queue list  --spool /var/spool/hedwig/spool
hedwig queue show  --spool /var/spool/hedwig/spool <MESSAGE_ID>
hedwig queue stats --spool /var/spool/hedwig/spool
```

### Migrating from the legacy filesystem spool

Before migrating, stop any Hedwig instance still running with `storage_type = "fs"` (the legacy filesystem spool has no file lock).

You can migrate in either of two ways:

1. **Opt-in startup migration:** set `storage_type = "log"` and `auto_migrate = true` under `[storage]` and start Hedwig. On startup, if legacy `queued/` or `deferred/` messages exist, Hedwig migrates them into `<base_path>/spool/` before accepting traffic and renames the legacy directories to timestamped `.migrated-*` backups. If any message fails to migrate or unexpected non-mail entries are found in `queued/` or `deferred/`, startup fails and leaves the legacy directories intact so you can fix the issue and restart (migration is idempotent). Once legacy directories are absent, empty, or contain only recognized housekeeping files (`.keep`, `.gitkeep`, `.DS_Store`) or orphaned `.meta.json` files (which log a warning), `auto_migrate = true` is a fast no-op on future restarts.
2. **Offline CLI migration:** set `storage_type = "log"`, run `hedwig queue migrate --config <config>`, and then start Hedwig.

In both modes, the `queued.migrated-*` and `deferred.migrated-*` backup directories are never deleted automatically; `bounced/` stays in place as the live bounce archive and continues to honor `storage.cleanup.bounced_retention`.
