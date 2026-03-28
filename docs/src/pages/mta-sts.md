---
layout: ../layouts/DocLayout.astro
title: MTA-STS
description: Automatic TLS enforcement for outbound delivery via MTA-STS (RFC 8461).
---

# MTA-STS

Hedwig implements [MTA-STS (RFC 8461)](https://datatracker.ietf.org/doc/html/rfc8461) on the sending side. When delivering outbound email, Hedwig automatically looks up recipient domain TLS policies and enforces them — preventing STARTTLS downgrade attacks and MX impersonation.

MTA-STS is always active. No configuration is needed. If a recipient domain doesn't publish a policy, delivery proceeds normally.

## How it works

When Hedwig delivers mail to a recipient domain (e.g. `gmail.com`):

1. **DNS lookup** — checks for a `_mta-sts.gmail.com` TXT record
2. **Policy fetch** — downloads the policy from `https://mta-sts.gmail.com/.well-known/mta-sts.txt`
3. **MX validation** — verifies that each MX server matches the policy's allowed patterns
4. **TLS enforcement** — ensures the connection uses valid, PKIX-authenticated TLS

## Policy modes

Recipient domains publish their policy in one of three modes:

| Mode | Behavior |
|------|----------|
| **enforce** | MX servers that don't match the policy are skipped. If all MXes fail, the email is deferred (never bounced). |
| **testing** | Validation failures are logged as warnings but delivery proceeds normally. |
| **none** | No enforcement — the domain is opting out of MTA-STS. |

## Caching

Policies are cached in memory to avoid repeated DNS and HTTPS lookups:

- Cache respects each policy's `max_age` (TTL set by the recipient domain)
- A background task refreshes cached policies every 24 hours
- If a fresh policy can't be fetched, the cached version is used (per RFC requirement)
- Failed fetches trigger a 5-minute cooldown before retrying

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
