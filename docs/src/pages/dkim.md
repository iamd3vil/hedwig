---
layout: ../layouts/DocLayout.astro
title: DKIM
description: Configure DKIM signing and generate keys.
---

# DKIM

DKIM (DomainKeys Identified Mail) allows receiving mail servers to verify that emails were sent by an authorized sender.

## Sign all messages with one domain

```toml
[server.dkim]
domain = "yourdomain.com"
selector = "default"
private_key = "/path/to/dkim/private.key"
```

With `[server.dkim]`, Hedwig signs every outgoing message using the configured
domain and key, regardless of the sender’s `From:` address. In this example,
all messages are signed as `yourdomain.com`.

If you omit DKIM configuration, Hedwig does not add a signature. Any signatures
already present on the message are kept.

## Multiple sending domains

Replace the single table with an array of tables to select a signer using the
message's **`From:` header**, independently of the SMTP `MAIL FROM` address:

```toml
[[server.dkim]]
domain = "example.com"
selector = "default"
private_key = "/etc/hedwig/dkim/example.com.key"

[[server.dkim]]
domain = "another.com"
selector = "default"
private_key = "/etc/hedwig/dkim/another.com.key"
key_type = "ed25519"
```

`alice@example.com` uses the first key; `bob@another.com` uses the second.
Publish the corresponding DKIM TXT record for each domain. Listeners, the SMTP
hostname, queue, workers, and outbound connections remain shared.

- Matching is case-insensitive and exact. Configure subdomains separately;
  wildcard and parent-domain fallback are not supported.
- Use ASCII DNS names (punycode/A-label form for internationalized domains).
- Exactly one `From:` header with one mailbox is required. Missing, malformed,
  multiple-mailbox, and unconfigured senders receive `550 5.7.1` after DATA,
  before the message is queued. The connection remains usable.
- Even a one-entry array enables these checks. Do not combine `[server.dkim]`
  and `[[server.dkim]]` in the same configuration.
- Empty lists, duplicate domains, invalid domains, and unreadable or invalid
  keys prevent startup or reject a reload. Failed reloads retain all previous
  signers. These identities do not restrict individual SMTP users to domains.

SIGHUP reloads all signers atomically. Queued messages use the current key when
attempted, so rotation applies to pending mail too. When a domain is removed
from the array, its queued messages are deferred under the normal bounded retry
policy, eventually bouncing if the domain is not restored. Disabling DKIM
entirely stops Hedwig from adding signatures, including to pending mail.
Already-running signing operations may finish using the previous snapshot.

When switching from a single signer or unsigned relaying to domain-based
signing, queued messages also undergo the stricter `From:` validation. Messages
with malformed or ambiguous `From:` headers bounce on their next attempt;
messages with a valid but unconfigured domain retry. Drain the queue before
switching if you need pending messages delivered under the previous rules.

For a multi-domain configuration, select the entry when generating its key:

```bash
hedwig --config config.toml dkim-generate --domain example.com
hedwig --config config.toml dkim-generate --domain another.com
```

The entry supplies its selector, private-key path, and key type; flags can
override them. `--domain` is required in this mode, even with one entry. An
unconfigured domain requires explicit `--selector` and `--private-key` flags.
Key generation writes the configured private-key file; publish its DNS record
before enabling a new identity or rotating the active signer.

## Generating keys

When overriding a selector or key path, the configured key type remains the
default. Changing it with `--key-type` requires an explicit `--private-key` path.
Update the configured key type, key path, and DNS record before enabling the new
key. With a single signing domain,
overriding `--domain` with a different domain also requires `--private-key` so
the command does not overwrite the configured domain’s key by default.

```bash
./target/release/hedwig dkim-generate
```

Override config values with flags:

```bash
./target/release/hedwig dkim-generate \
  --domain yourdomain.com \
  --selector default \
  --private-key /path/to/dkim/private.key \
  --key-type rsa
```

Available flags:
- `--domain`: Domain for DKIM signature
- `--selector`: DKIM selector
- `--private-key`: Path to save the private key
- `--key-type`: Key type (rsa or ed25519, default: configured key type, or rsa if none)

Add the DNS TXT record output by the command:

```
default._domainkey.yourdomain.com. IN TXT "v=DKIM1; k=rsa; p=[public_key]"
```
