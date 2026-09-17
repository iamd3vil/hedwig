<div align="right">
  <a href="https://zerodha.tech">
    <img src="https://zerodha.tech/static/images/github-badge.svg" width=140 />
  </a>
</div>

<div align="center">
  <img src="logo.png" alt="Hedwig" width="75"/>
  <h1>Hedwig</h1>
</div>

<p align="center">
  Hedwig - A high-performance, minimalist SMTP server implemented in Rust.
</p>

---

## Features

- Async SMTP relay with persistent filesystem queue
- DKIM signing (RSA and Ed25519)
- MTA-STS (RFC 8461) — automatic TLS policy enforcement for outbound delivery
- SMTP authentication (PLAIN, LOGIN, CRAM-MD5; multiple users)
- TLS/STARTTLS support with multiple listeners
- Per-domain rate limiting
- Prometheus metrics and health checks
- Domain-based sender/recipient filtering

## Docs

Documentation lives at https://hedwig-mail.dev

## Install (recommended)

Download the latest release binary from GitHub Releases:

```bash
curl -L -o hedwig.zip https://github.com/iamd3vil/hedwig/releases/download/v0.12.3/hedwig-v0.12.3-linux-x86_64.zip
unzip hedwig.zip
chmod +x hedwig
```

Checksums:

```
https://github.com/iamd3vil/hedwig/releases/download/v0.12.3/checksums.txt
```

## Docker

Images are published at `ghcr.io/iamd3vil/hedwig` for Linux AMD64 and ARM64.
Docker selects the matching architecture automatically:

```bash
docker pull ghcr.io/iamd3vil/hedwig:0.12.3
```

Use an exact version for a pinned deployment. The `0.12` and `latest` tags are
updated by release builds. See the [Docker quickstart](https://hedwig-mail.dev/quickstart#run-with-docker)
for configuration and persistent storage mounts, and the
[release workflow guide](https://hedwig-mail.dev/reference/releases) for publishing.

## Build from source

```bash
git clone https://github.com/iamd3vil/hedwig.git
cd hedwig
cargo build --release
```

## License

AGPL v3. See `LICENSE`.
