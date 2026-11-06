---
layout: ../layouts/DocLayout.astro
title: MTA-STS
description: Automatic TLS enforcement for outbound delivery via MTA-STS (RFC 8461).
---

# MTA-STS

Hedwig implements [MTA-STS (RFC 8461)](https://datatracker.ietf.org/doc/html/rfc8461) on the sending side. When delivering outbound email, Hedwig automatically looks up recipient domain TLS policies and enforces them — preventing STARTTLS downgrade attacks and MX impersonation.

MTA-STS is always active. No configuration is needed. A valid, unexpired
`enforce` policy requires authenticated TLS. Otherwise, outbound delivery uses
opportunistic TLS as described in [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207#section-4.1):
Hedwig uses STARTTLS when offered, accepting self-signed, expired, or
hostname-mismatched certificates. If STARTTLS is not offered, delivery proceeds
in plaintext. An actual TLS handshake failure still defers delivery; Hedwig
does not reconnect in plaintext after a failed handshake.
The server must still present a parseable X.509 v3 certificate and support a
compatible TLS 1.2 or later connection; relaxing certificate verification does
not enable older TLS versions or malformed certificates.

Opportunistic TLS encrypts traffic against passive eavesdropping, but does not
authenticate the receiving server or prevent an active attacker from stripping
STARTTLS. Hedwig does not currently implement DANE; MTA-STS is its mechanism for
requiring authenticated outbound TLS.

## How it works

When Hedwig delivers mail to a recipient domain (e.g. `gmail.com`):

1. **DNS lookup** — checks for a `_mta-sts.gmail.com` TXT record
2. **Policy fetch** — downloads the policy from `https://mta-sts.gmail.com/.well-known/mta-sts.txt`
3. **MX validation** — verifies that each MX server matches the policy's allowed patterns
4. **TLS selection** — requires valid, PKIX-authenticated TLS for `enforce` policies; otherwise uses opportunistic TLS

## Policy modes

Recipient domains publish their policy in one of three modes:

| Mode | Behavior |
|------|----------|
| **enforce** | MX servers that don't match the policy are skipped. STARTTLS and a trusted, unexpired certificate matching the MX hostname are required. Failures defer delivery and remain subject to the queue's retry limit. |
| **testing** | MX mismatches are logged as warnings. Delivery uses opportunistic TLS. Certificate validation is not enforced or reported via TLSRPT. |
| **none** | No enforcement — delivery uses opportunistic TLS. |

Connection pools are separated by MX hostname and TLS mode. Domains sharing an
MX cannot cause an enforced delivery to reuse an unauthenticated connection,
and newly enforced policies use a separate pool. `outbound_local = true` skips
TLS for development only when no `enforce` policy applies.

## Caching

Policies are cached only in memory to avoid repeated DNS and HTTPS lookups:

- Cache respects each policy's `max_age` (TTL set by the recipient domain)
- The cache holds up to 10,000 policy domains; capacity pressure can evict policies before `max_age`, and a process restart loses all cached policies
- While an unexpired `enforce` policy remains in the cache, it stays mandatory even if DNS or policy refresh fails
- A background task checks cached `enforce` and `testing` policy TXT identifiers every hour and fetches updated policies when identifiers change
- `none` policies are not refreshed proactively; a switch to `enforce` is discovered only after cache expiry, eviction, or restart
- If a fresh policy can't be fetched, an existing, unexpired cached version is used
- Failed fetches trigger a 5-minute cooldown before retrying

On a cache miss, including after restart or capacity eviction, Hedwig attempts
policy discovery again. If discovery or fetching fails and no valid cached
policy remains, delivery uses opportunistic TLS. An active attacker who blocks
discovery in this state can prevent enforcement; policies are not persisted
across restarts.

## Major providers with MTA-STS

Most major email providers publish MTA-STS policies:

| Provider | Mode | max_age |
|----------|------|---------|
| Gmail | enforce | 1 day |
| Outlook / Hotmail | enforce | 7 days |
| Microsoft | enforce | 7 days |
| ProtonMail | enforce | 7 days |
| Yahoo | testing | 1 day |
| Fastmail | testing | 1 day |

## Metrics

When [metrics](/metrics) are enabled, Hedwig exports MTA-STS counters:

- `hedwig_mta_sts_policy_fetch_total{result}` — policy fetch attempts (`success`, `failure`, `cached`)
- `hedwig_mta_sts_enforcement_total{mode,result}` — enforcement decisions (`pass`, `fail`) by mode
- `hedwig_mta_sts_cache_size` — number of cached policies

## Verify it's working

Check the logs for MTA-STS activity:

```bash
# Policy fetched and cached
INFO cached MTA-STS policy domain=gmail.com mode=enforce max_age=86400

# Enforce mode: MX validated
DEBUG MTA-STS policy found domain=gmail.com mode=enforce

# Testing mode: would-be failure logged
WARN MTA-STS testing: MX host does not match policy domain=example.com mx=bad.example.com
```

Or query the Prometheus metrics:

```bash
curl -s http://localhost:9090/metrics | grep mta_sts
```
