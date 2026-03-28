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
- SMTP authentication (multiple users)
- TLS/STARTTLS support with multiple listeners
- Per-domain rate limiting
- Prometheus metrics and health checks
- Domain-based sender/recipient filtering

## Docs

Documentation lives at https://hedwig.sarat.dev

## Install (recommended)

Download the latest release binary from GitHub Releases:

```bash
curl -L -o hedwig.zip https://github.com/iamd3vil/hedwig/releases/download/v0.5.2/hedwig-v0.5.2-linux-x86_64.zip
unzip hedwig.zip
chmod +x hedwig
```

Checksums:

```
https://github.com/iamd3vil/hedwig/releases/download/v0.5.2/checksums.txt
```

## Build from source

```bash
git clone https://github.com/iamd3vil/hedwig.git
cd hedwig
cargo build --release
```

## License

AGPL v3. See `LICENSE`.
