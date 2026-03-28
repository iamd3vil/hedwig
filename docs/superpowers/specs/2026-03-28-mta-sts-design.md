# MTA-STS Implementation Design (Sending MTA)

**Date:** 2026-03-28
**RFC:** [8461 — SMTP MTA Strict Transport Security](https://datatracker.ietf.org/doc/html/rfc8461)
**Scope:** Sending-side MTA-STS enforcement during outbound delivery. No TLSRPT (RFC 8460) in this iteration.

## Overview

Hedwig will look up and enforce MTA-STS policies published by recipient domains before delivering outbound email. This prevents STARTTLS downgrade attacks and MX impersonation by verifying that recipient mail servers offer valid TLS with PKIX-authenticated certificates.

MTA-STS is always active — no configuration toggle. It's a sending-side standard that degrades gracefully: if a recipient domain doesn't publish an MTA-STS policy, delivery proceeds as today.

## Architecture

New module: `smtp-server/src/mta_sts/`

```
mta_sts/
├── mod.rs          # Public API: MtaStsResolver
├── policy.rs       # Policy types, parsing, MX pattern matching
├── cache.rs        # Moka-backed policy cache with TTL
├── fetcher.rs      # DNS TXT lookup + HTTPS policy fetch
└── refresher.rs    # Background task for proactive cache refresh
```

### Key Types

```rust
pub enum PolicyMode {
    Enforce,
    Testing,
    None,
}

pub struct MtaStsPolicy {
    pub version: String,        // "STSv1"
    pub mode: PolicyMode,
    pub mx_patterns: Vec<String>, // e.g. ["mail.example.com", "*.example.net"]
    pub max_age: u64,           // seconds
}

pub struct CachedPolicy {
    pub policy: MtaStsPolicy,
    pub txt_id: String,         // TXT record id for change detection
    pub fetched_at: Instant,
}

pub struct MtaStsResolver {
    cache: Cache<String, CachedPolicy>,  // moka, keyed by domain
    resolver: TokioAsyncResolver,         // shared DNS resolver
    http_client: reqwest::Client,         // connection-pooled HTTPS client
}
```

## Policy Discovery & Fetching

### Step 1: DNS TXT Lookup

Query `_mta-sts.<recipient-domain>` for a TXT record.

- Parse for `v=STSv1; id=<policy-id>` format
- If no valid TXT record found → domain doesn't participate, skip MTA-STS
- If multiple TXT records, discard those not starting with `v=STSv1;`; if not exactly one remains, treat as no policy
- Use the existing `hickory_resolver::TokioAsyncResolver` (already available in `Worker`)

### Step 2: Cache Check

Before fetching via HTTPS:
- If a cached policy exists for this domain AND the cached `txt_id` matches the DNS result → use cached policy (no HTTPS fetch needed)
- If `txt_id` differs → new policy available, proceed to HTTPS fetch

### Step 3: HTTPS Policy Fetch

Fetch `https://mta-sts.<recipient-domain>/.well-known/mta-sts.txt`

Requirements (from RFC 8461):
- HTTP response code MUST be 200 (any other code = failure)
- HTTP 3xx redirects MUST NOT be followed
- HTTP caching MUST NOT be used
- Validate `Content-Type: text/plain` (SHOULD)
- Timeout: 60 seconds (suggested by RFC)
- Max response body: 64KB (suggested by RFC)
- TLS certificate must be valid for `mta-sts.<domain>` (handled by reqwest + system CA roots)

Parse the response body as CRLF-separated `key: value` pairs:
- `version: STSv1` (required)
- `mode: enforce|testing|none` (required)
- `mx: <pattern>` (required at least once, except when mode=none)
- `max_age: <seconds>` (required, max 31557600)
- Unknown fields: ignored

### Fetch Failure Handling

- If DNS lookup fails or returns no valid record AND no cached policy exists → no MTA-STS, deliver normally
- If DNS lookup fails but a valid (non-expired) cached policy exists → use cached policy (RFC requirement)
- If TXT record exists but HTTPS fetch fails AND no cached policy → deliver normally (RFC requirement)
- If TXT record exists but HTTPS fetch fails AND cached policy exists → use cached policy
- Rate-limit HTTPS fetch failures: 5-minute cooldown per domain (RFC SHOULD)

## Policy Cache

In-memory moka cache (consistent with existing MX cache pattern).

- **Key:** recipient domain (String)
- **Value:** `CachedPolicy` (policy + txt_id + fetch timestamp)
- **TTL:** policy's `max_age` value
- **Capacity:** 10,000 entries (same as MX cache)
- **Lost on restart:** acceptable per design decision; policies re-fetched on first delivery to each domain

## Background Refresher

A tokio task spawned at server startup:

- **Interval:** runs every 24 hours (RFC suggests daily refresh)
- **Logic:** iterates all cached entries, for each:
  1. Query DNS TXT record for current `id`
  2. If `id` changed, fetch new HTTPS policy and update cache
  3. If `id` unchanged, update cache TTL (extend freshness)
  4. On failure, log warning (per RFC SHOULD for admin alerting), keep existing cached policy
- **Shutdown:** listens on the global `CancellationToken` for graceful stop
- Does NOT refresh policies with mode `none` (per RFC guidance for clean opt-out)

## Policy Enforcement in Delivery Path

Modified flow in `Worker::send_email`, per recipient:

```
1. Extract recipient domain from email address
2. policy = mta_sts_resolver.get_policy(domain).await
3. For each MX candidate (in priority order):
   a. If policy.mode == Enforce:
      - Verify MX hostname matches at least one policy mx: pattern
      - If no match → skip this MX (log as MTA-STS failure), continue to next
      - Connect via STARTTLS with strict PKIX certificate validation
      - If STARTTLS not offered or cert invalid → skip this MX, continue
   b. If policy.mode == Testing:
      - Perform same validation checks
      - Log any failures as warnings
      - Deliver regardless of validation result
   c. If policy.mode == None OR no policy:
      - Deliver as current behavior (opportunistic TLS via pool.rs)
4. If ALL MXes fail in Enforce mode:
   - Re-query DNS TXT for possibly updated policy (RFC MUST before permanent failure)
   - If new policy id found → re-fetch HTTPS policy and retry delivery
   - If same policy or no new policy → defer email (transient failure, existing retry mechanism)
   - MUST NOT bounce — treat as temporary failure
```

### MX Pattern Matching (RFC 6125 + MTA-STS restrictions)

```rust
fn mx_matches_pattern(mx_host: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        // Wildcard: matches exactly one left-most label
        // "*.example.com" matches "mail.example.com" but NOT "example.com" or "a.b.example.com"
        let suffix = &pattern[1..]; // ".example.com"
        let parts: Vec<&str> = mx_host.splitn(2, '.').collect();
        parts.len() == 2 && format!(".{}", parts[1]) == suffix
    } else {
        // Exact match (case-insensitive)
        mx_host.eq_ignore_ascii_case(pattern)
    }
}
```

## TLS Configuration Changes

### Current State

`pool.rs` creates outbound connections with:
```rust
AsyncSmtpTransport::builder_dangerous(domain)
    .port(25)
    .tls(Tls::Required(TlsParameters::new(domain.into())))
    .build()
```

This already does STARTTLS with certificate validation against the MX hostname.

### Changes Needed

The `PoolManager::get` method needs to know whether MTA-STS enforcement is active for a given connection:

1. **No policy / mode=none / mode=testing:** Use current `Tls::Required` behavior (opportunistic — if TLS fails, lettre's behavior applies). For `testing` mode, we log the failure.

2. **mode=enforce:** Use `Tls::Required` with strict validation. If TLS connection fails (cert invalid, no STARTTLS), the `send_raw` call returns an error, and we skip to the next MX. This is already how errors work — the key change is in the caller (`send_email`) which decides whether to skip to the next MX or bounce.

Since the current `PoolManager` already uses `Tls::Required` with certificate validation for all outbound connections, MTA-STS enforce mode doesn't require different TLS parameters — it only affects the *caller's* reaction to failures (skip MX vs. bounce). No changes to pool keying are needed.

## New Dependency

- `reqwest` (with `rustls-tls` feature, no default features): for HTTPS policy fetching
  - Already uses tokio runtime, aligns with existing async stack
  - Configured with: no redirects, 60s timeout, 64KB body limit

## Integration Points

### Worker Initialization

`Worker::new` receives an `Arc<MtaStsResolver>` (created in `Callbacks::new` alongside the MX cache):

```rust
pub struct Worker {
    // ... existing fields ...
    mta_sts: Arc<MtaStsResolver>,
}
```

### Server Startup (main.rs)

```rust
// Create shared MTA-STS resolver
let mta_sts_resolver = Arc::new(MtaStsResolver::new(resolver.clone()));

// Spawn background refresher
let mta_sts_refresher = mta_sts_resolver.clone();
let refresher_shutdown = shutdown_token.clone();
let handle = tokio::spawn(async move {
    mta_sts_refresher.run_refresh_loop(refresher_shutdown).await;
});
background_tasks.push(handle);
```

### Metrics (optional, but recommended)

New Prometheus counters/histograms:
- `hedwig_mta_sts_policy_fetch_total{result="success|failure|cached"}`
- `hedwig_mta_sts_enforcement_total{mode="enforce|testing|none", result="pass|fail"}`
- `hedwig_mta_sts_cache_size` gauge

## Testing Strategy

### Unit Tests

- **Policy parsing:** valid policies, missing fields, unknown fields, mode variations
- **MX pattern matching:** exact match, wildcard match, wildcard edge cases (no match for bare domain, no match for nested subdomain)
- **TXT record parsing:** valid records, multiple records, invalid format
- **Fetch failure handling:** DNS failure with/without cache, HTTPS failure with/without cache

### Integration Tests

- Mock DNS + HTTPS server to test full flow: policy discovery → cache → enforcement
- Test enforce mode: delivery fails when MX doesn't match policy
- Test testing mode: delivery succeeds despite MX mismatch, with log output
- Test cache behavior: second delivery uses cached policy without HTTPS fetch
- Test policy update: changed TXT id triggers re-fetch

## Non-Goals (This Iteration)

- TLSRPT (RFC 8460) reporting — planned as follow-up
- Receiving-side MTA-STS (publishing our own policy)
- DANE (RFC 7672) integration
- Persistent on-disk policy cache
- Configuration toggles for MTA-STS behavior
