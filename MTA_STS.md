# MTA-STS Support in Hedwig

## Background

### How SMTP TLS Works Today

SMTP server-to-server delivery happens on port 25 using plaintext by default. STARTTLS (RFC 3207) was added as an optional upgrade — the receiving server advertises STARTTLS in its EHLO response, and the sender can choose to upgrade the connection to TLS.

This is **opportunistic** by design. RFC 3207 explicitly states that a client MUST NOT require STARTTLS unless configured by policy. Without such a policy, if the server doesn't offer STARTTLS (or an attacker strips it from the EHLO response), the sender delivers over plaintext.

### The Problem

Opportunistic TLS is vulnerable to active attacks:

1. **STARTTLS stripping**: A man-in-the-middle removes the STARTTLS advertisement from the EHLO response. The sender sees "no TLS offered" and sends in plaintext.
2. **MX spoofing**: An attacker poisons DNS to redirect mail to a rogue server that doesn't offer TLS.

There was no way for a receiving domain to signal "I definitely support TLS — don't fall back to plaintext" until MTA-STS.

### What is MTA-STS (RFC 8461)?

MTA-STS (Mail Transfer Agent Strict Transport Security) allows a receiving domain to publish a policy declaring:

- TLS is required for inbound mail delivery.
- Only specific MX hostnames are valid.
- The sender should cache this policy for a specified duration.

It works via two mechanisms:

1. **DNS TXT record** at `_mta-sts.<domain>` — signals that a policy exists and includes a version ID for cache invalidation.
2. **HTTPS policy file** at `https://mta-sts.<domain>/.well-known/mta-sts.txt` — contains the actual policy (mode, allowed MX patterns, max age).

Example DNS record:
```
_mta-sts.example.com. IN TXT "v=STSv1; id=20240101T000000"
```

Example policy file:
```
version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.com
max_age: 604800
```

### Policy Modes

| Mode | Behavior |
|---|---|
| `enforce` | Sender MUST use TLS with valid certs. MUST only deliver to MX hosts matching the policy. If TLS fails, defer/bounce — do NOT deliver in plaintext. |
| `testing` | Sender SHOULD try TLS but MAY fall back to plaintext. Failures should be reported via TLSRPT. |
| `none` | Policy is effectively disabled. Treat as if no policy exists. |

### TLSRPT (RFC 8460)

A companion standard. The receiving domain publishes a `_smtp._tls.<domain>` TXT record specifying where to send aggregate TLS failure reports (via email or HTTPS). This is optional but recommended alongside MTA-STS.

---

## Current Hedwig Behavior

### TLS Configuration (`smtp-server/src/worker/pool.rs`)

```rust
let tls_params = TlsParameters::new(domain.into())?;
let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(domain)
    .port(25)
    .tls(lettre::transport::smtp::client::Tls::Required(tls_params))
    .build();
```

Hedwig currently uses `Tls::Required` for all outbound connections. This means:

- ✅ Emails are always encrypted in transit (when the server supports STARTTLS).
- ❌ Emails to servers that don't support STARTTLS will **bounce** instead of being delivered.
- ❌ No MTA-STS policy lookup — TLS is required regardless of the recipient's policy.
- ❌ No MX hostname validation against a published policy.

### Problems With Current Approach

1. **Too strict without policy basis**: Requiring TLS unconditionally causes delivery failures to legitimate servers that don't support STARTTLS. While most major providers support it, many smaller/older mail servers do not.
2. **No MTA-STS awareness**: The TLS requirement is hardcoded, not driven by the recipient's published policy.
3. **`builder_dangerous` usage**: This builder name indicates relaxed certificate hostname verification, which undermines the security that `Tls::Required` is supposed to provide.

---

## What Hedwig Needs To Do

### Phase 1: Fix TLS Behavior (Immediate)

Change the default TLS mode from `Tls::Required` to `Tls::Opportunistic`:

```rust
// Before (too strict):
.tls(lettre::transport::smtp::client::Tls::Required(tls_params))

// After (correct default):
.tls(lettre::transport::smtp::client::Tls::Opportunistic(tls_params))
```

This matches standard MTA behavior:
- Try STARTTLS if the server offers it.
- Fall back to plaintext if it doesn't.
- Emails are delivered either way.

### Phase 2: Implement MTA-STS Policy Lookup

Add a new module (`smtp-server/src/worker/mta_sts.rs`) that handles policy discovery and caching.

#### 2.1 DNS Lookup

Before delivering to a domain, query `_mta-sts.<domain>` for a TXT record:

```
_mta-sts.example.com. IN TXT "v=STSv1; id=20240101T000000"
```

- If no record exists → no MTA-STS policy → use opportunistic TLS (Phase 1 behavior).
- If a record exists → proceed to fetch the policy.

Use the existing `hickory_resolver` (already a dependency) for DNS resolution.

#### 2.2 Policy Fetch

HTTP GET `https://mta-sts.<domain>/.well-known/mta-sts.txt` and parse:

```
version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.com
max_age: 604800
```

Requires an HTTP client dependency (e.g., `reqwest`).

#### 2.3 Policy Cache

Cache fetched policies keyed by domain, respecting `max_age`. Use the existing `moka` cache (already a dependency for MX caching):

```rust
struct MtaStsPolicy {
    mode: PolicyMode,        // enforce | testing | none
    mx_patterns: Vec<String>, // allowed MX hostnames/wildcards
    max_age: Duration,
    fetched_at: Instant,
    policy_id: String,        // from DNS TXT record, for cache invalidation
}

// Cache<String, MtaStsPolicy> keyed by domain
```

Re-fetch when:
- Cache entry has expired (`fetched_at + max_age`).
- DNS TXT record `id` has changed (check periodically or on each delivery).

#### 2.4 Policy Enforcement

Integrate into `send_email()` in `smtp-server/src/worker/mod.rs`:

```
For each recipient domain:
  1. Look up MTA-STS policy (DNS TXT → HTTPS fetch → cache)
  2. Based on policy mode:
     - enforce:
       a. Filter MX records to only those matching policy's mx: patterns
       b. Use Tls::Required with strict certificate validation
       c. If no valid MX matches or TLS fails → defer/bounce, do NOT deliver
     - testing:
       a. Try TLS with MX validation (same as enforce)
       b. If it fails → deliver anyway (opportunistic), log the failure
     - none / no policy:
       a. Use Tls::Opportunistic (default behavior)
```

### Phase 3: TLSRPT (Optional, Future)

Implement RFC 8460 to send aggregate TLS failure reports:

1. Look up `_smtp._tls.<domain>` TXT record for reporting endpoints.
2. Collect TLS negotiation failures during delivery.
3. Send daily aggregate JSON reports to the specified endpoint (email or HTTPS POST).

This is not required for MTA-STS to work but is recommended by the RFC and expected by large providers.

---

## Implementation Checklist

- [ ] **Phase 1**: Change `Tls::Required` → `Tls::Opportunistic` in `pool.rs`
- [ ] **Phase 2.1**: Add `_mta-sts.<domain>` DNS TXT lookup using `hickory_resolver`
- [ ] **Phase 2.2**: Add HTTPS policy fetcher (add `reqwest` dependency)
- [ ] **Phase 2.3**: Add policy parser and `moka`-based cache
- [ ] **Phase 2.4**: Integrate policy enforcement into `send_email()` flow
- [ ] **Phase 2.5**: Add configuration toggle (`mta_sts.enabled` in `config.toml`)
- [ ] **Phase 2.6**: Add metrics (policy fetch latency, cache hit/miss, enforce/testing counts)
- [ ] **Phase 2.7**: Add tests (policy parsing, MX pattern matching, cache expiry, mode enforcement)
- [ ] **Phase 3**: TLSRPT support (optional, future)

---

## References

- [RFC 8461 — SMTP MTA Strict Transport Security (MTA-STS)](https://datatracker.ietf.org/doc/html/rfc8461)
- [RFC 8460 — SMTP TLS Reporting (TLSRPT)](https://datatracker.ietf.org/doc/html/rfc8460)
- [RFC 3207 — SMTP Service Extension for Secure SMTP over TLS (STARTTLS)](https://datatracker.ietf.org/doc/html/rfc3207)
- [RFC 7672 — SMTP Security via Opportunistic DANE TLS](https://datatracker.ietf.org/doc/html/rfc7672)
