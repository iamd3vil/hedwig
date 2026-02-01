---
layout: ../layouts/DocLayout.astro
title: DKIM
description: Configure DKIM signing and generate keys.
---

# DKIM

DKIM (DomainKeys Identified Mail) allows receiving mail servers to verify that emails were sent by an authorized sender.

## Configuration

```toml
[server.dkim]
domain = "yourdomain.com"
selector = "default"
private_key = "/path/to/dkim/private.key"
```

## Generating keys

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
- `--key-type`: Key type (rsa or ed25519, default: rsa)

Add the DNS TXT record output by the command:

```
default._domainkey.yourdomain.com. IN TXT "v=DKIM1; k=rsa; p=[public_key]"
```
