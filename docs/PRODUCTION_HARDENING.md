# Production Hardening Checklist

Issues identified during a codebase audit for high-volume (millions of emails) production use.

Ordered by priority. Each item includes the problem, where it lives in the code, and a suggested fix.

---

## 🔴 Critical

### 1. Queue channel is `bounded(1)`

**Problem:** The work queue between inbound acceptance and outbound workers is `async_channel::bounded(1)`. Under load, `on_data` blocks waiting for a worker to drain, causing SMTP timeouts for sending clients.

**Location:** `smtp-server/src/main.rs:108`
```rust
let (sender_channel, receiver_channel) = async_channel::bounded(1);
```

**Fix:** Increase to `bounded(1000)` or make it configurable via `config.toml`. The filesystem storage already provides durability — the channel just needs enough buffer to decouple inbound acceptance from worker processing.

---

### 2. No inbound message size limit

**Problem:** The `smtp` crate accumulates the entire DATA body in memory with no cap. A malicious or misbehaving client can send an arbitrarily large message and OOM the server.

**Location:** `smtp/src/lib.rs` — the `handle_data()` / DATA accumulation loop appends to an unbounded `String`.

**Fix:** Add a configurable `max_message_size` (e.g. 25MB default). Reject with `552 5.3.4 Message too big` when exceeded. Advertise the limit via `SIZE` in the EHLO response.

---

### 3. No inbound connection/read timeouts

**Problem:** `handle_client()` reads from the socket with no timeout. Slowloris-style attacks can hold connections open indefinitely, exhausting file descriptors and memory.

**Location:** `smtp/src/lib.rs` — `handle_client()` reads in a loop with no `tokio::time::timeout` wrapper.

**Fix:** Add configurable timeouts:
- Idle timeout between commands: ~5 minutes (RFC 5321 recommends 5 min)
- DATA transfer timeout: ~10 minutes
- Total connection timeout: ~30 minutes

Wrap each read with `tokio::time::timeout()`. On timeout, send `421 4.4.2 Connection timed out` and close.

---

### 4. No inbound connection limit

**Problem:** No cap on concurrent inbound connections. Under a spam flood or DDoS, the server will accept connections until it runs out of file descriptors or memory.

**Location:** `smtp-server/src/main.rs` — listener accept loop spawns a task per connection with no limit.

**Fix:** Add a configurable `max_connections` (e.g. 1000 default). Use a `tokio::sync::Semaphore` in the accept loop. When full, either stop accepting or respond with `421 4.7.0 Too many connections` and close immediately.

---

## 🟡 Important

### 5. Filesystem storage lacks durability guarantees

**Problem:** `fs_storage.rs` uses `tokio::fs::write()` directly — no temp-file + rename, no fsync. On crash or power loss:
- Partially written files can corrupt the queue
- Acknowledged emails can be lost

**Location:** `smtp-server/src/storage/fs_storage.rs` — `put()` method.

**Fix (short-term):**
1. Write to a temp file in the same directory
2. `fsync` the temp file
3. `rename` to the final path (atomic on the same filesystem)
4. `fsync` the parent directory

**Fix (long-term):** Consider SQLite (`rusqlite`) as a storage backend for transactional durability and indexed queries.

---

### 6. Filesystem storage doesn't scale to millions of files

**Problem:** Flat directories (`queued/`, `deferred/`, `bounced/`) with millions of files means very slow `readdir()` calls. Startup replay and cleanup become directory-walk bound. ext4 performance degrades significantly past ~100K files per directory.

**Location:** `smtp-server/src/storage/fs_storage.rs` — all methods use flat `base_path/status/` directories.

**Fix:** Shard by ULID prefix. ULIDs start with a timestamp-based component, so sharding by the first 2 characters gives 1,296 buckets (36²), keeping each directory under ~1K files even at 1M total. Structure: `base_path/queued/0A/01J5K3...json`.

---

### 7. STARTTLS is broken on plaintext listeners

**Problem:** Two issues:
1. `main.rs` never calls `SmtpServer::with_tls()`, so the SMTP session never has a `tls_acceptor` and STARTTLS is never advertised on plaintext listeners.
2. `upgrade_to_tls()` in `smtp/src/lib.rs` uses `unsafe { TcpStream::from_raw_fd() }` which creates two owners of the same FD — a use-after-free risk.

Implicit TLS (port 465) works fine via the TLS acceptor in the listener. But STARTTLS upgrade (port 587 plaintext → TLS) does not work.

**Location:**
- `smtp-server/src/main.rs` — `SmtpServer::new()` is called but `with_tls()` is not
- `smtp/src/lib.rs` — `upgrade_to_tls()` on `TcpStream`

**Fix:**
1. For plaintext listeners, pass the TLS cert/key to `SmtpServer::with_tls()` so STARTTLS is advertised and functional.
2. Rewrite `upgrade_to_tls()` to avoid the raw FD trick. Use `tokio_rustls::TlsAcceptor::accept()` directly with the owned stream (requires restructuring `handle_client` to take ownership rather than `&mut`).

---

### 8. Retry backoff has no jitter

**Problem:** `defer_email()` uses `initial_delay * 2^attempts` with no randomization. All deferred emails retry at the same wallclock times, creating "thundering herd" retry storms against the same MX servers.

**Location:** `smtp-server/src/worker/mod.rs` — `defer_email()` method.
```rust
let delay = self.initial_delay * (2_u32.pow(job.attempts));
let delay = std::cmp::min(delay, self.max_delay);
```

**Fix:** Add ±25% random jitter:
```rust
use rand::Rng;
let jitter_factor = rand::thread_rng().gen_range(0.75..=1.25);
let delay_secs = (delay.as_secs_f64() * jitter_factor) as u64;
let delay = Duration::from_secs(delay_secs);
```

---

### 9. Rate limiter blocks worker threads

**Problem:** When a domain is rate-limited, the worker sleeps inline with `tokio::time::sleep(retry_after)`. With 4 workers all sending to the same popular domain (e.g. gmail.com), all 4 can sleep simultaneously, halting all outbound delivery.

**Location:** `smtp-server/src/worker/mod.rs` — inside `send_email()`:
```rust
RateLimitResult::RateLimited { retry_after } => {
    tokio::time::sleep(retry_after).await;
}
```

**Fix:** Instead of sleeping, defer the job with `next_attempt = now + retry_after` so the worker can process other domains. Alternatively, maintain per-domain queues so rate-limited domains don't block unrelated traffic.

---

### 10. `is_retryable()` treats permanent 5xx errors as retryable

**Problem:** The retry logic retries SMTP codes like 550 (mailbox not found), 551 (user not local), 553 (bad address syntax), and 554 (transaction failed). These are permanent errors per RFC 5321 — retrying them wastes resources, delays bounce notification, and can harm sender reputation.

**Location:** `smtp-server/src/worker/mod.rs`:
```rust
const ADDITIONAL_RETRYABLE_CODES: &[u16] =
    &[500, 501, 502, 503, 504, 521, 530, 550, 551, 552, 553, 554];
```

**Fix:** Only retry genuinely transient codes:
```rust
// 4xx are transient by definition.
// 421 = service not available (explicit transient).
// 450, 451, 452 = mailbox/system temporarily unavailable.
fn is_retryable(code: u16) -> bool {
    (400..500).contains(&code)
}
```
Bounce immediately on 5xx — these are permanent failures.

---

### 11. AUTH advertised without TLS

**Problem:** When auth is enabled, `AUTH PLAIN LOGIN` is advertised even on plaintext listeners. Clients may send credentials in cleartext over the wire.

**Location:** `smtp/src/lib.rs` — EHLO response includes `AUTH PLAIN LOGIN` when `auth_enabled` is true, regardless of TLS state.

**Fix:** Only advertise `AUTH` after TLS is established (either implicit TLS listener or post-STARTTLS). This is required by RFC 4954 §4:
> A server MUST NOT advertise the AUTH extension on a non-TLS connection if the server requires TLS for authentication.

---

## 🟢 Nice to Have

### 12. No bounce/DSN generation

When delivery permanently fails, the original sender is never notified. Real MTAs generate a Delivery Status Notification (RFC 3461/3464) bounce message back to the envelope sender. Without this, senders have no way to know their email was lost.

---

### 13. No recipient grouping per domain

Emails to multiple recipients at the same domain are sent as separate SMTP transactions (one per recipient). Grouping them into a single transaction with multiple `RCPT TO` would reduce connection overhead and be more MX-friendly.

---

### 14. No queue prioritization

All emails are treated equally. No way to prioritize transactional email (password resets, receipts) over bulk/marketing email. A large bulk send can delay time-sensitive transactional mail.

---

### 15. Rate limiter buckets are never evicted

`rate_limiter.rs` creates a `TokenBucket` per domain in a `HashMap` behind a `RwLock`. Buckets are never removed, so memory grows with every unique domain ever seen. At millions of emails across diverse domains, this becomes significant.

**Fix:** Use a moka cache with TTL (same pattern as MX cache) instead of a plain HashMap.

---

### 16. Hardcoded outbound transport parameters

`pool.rs` hardcodes connection pool settings (`min_idle(10)`, `max_size(100)`), SMTP port (25), and timeout (10s). These should be configurable for different deployment environments.

---

### 17. `process_job` uses `println!` instead of tracing

`DeferredWorker::process_deferred_jobs()` uses `println!` for its startup message instead of structured `tracing::info!`. Minor but inconsistent with the rest of the codebase.

**Note:** Fixed for the `run()` method but the internal `process_deferred_jobs()` still has a `println!`.
