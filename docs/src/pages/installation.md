---
layout: ../layouts/DocLayout.astro
title: Installation
description: Install Hedwig from release binaries, Docker images, or source.
---

# Installation

## Prerequisites

- A domain name (for DKIM setup)

## Install from GitHub Releases (recommended)

Latest release: `v0.12.3`

Linux x86_64 (statically linked with glibc):

```bash
curl -L -o hedwig.zip https://github.com/iamd3vil/hedwig/releases/download/v0.12.3/hedwig-v0.12.3-linux-x86_64.zip
unzip hedwig.zip
chmod +x hedwig
```

Checksums are available at:

```
https://github.com/iamd3vil/hedwig/releases/download/v0.12.3/checksums.txt
```

## Install with Docker

Published images are available from `ghcr.io/iamd3vil/hedwig` for `linux/amd64`
and `linux/arm64`. Docker selects the matching architecture when pulling:

```bash
docker pull ghcr.io/iamd3vil/hedwig:0.12.3
docker run --rm ghcr.io/iamd3vil/hedwig:0.12.3 --version
```

Available tags include the exact version (`0.12.3`), major/minor (`0.12`), and
`latest`. Pin an exact version to control upgrades; the other tags change when
release builds publish. Image tags omit the Git release tag's `v` prefix.

The runtime uses Debian Trixie Slim with CA certificates. Supply your own
configuration and persist the mail queue in a volume. See
[Run with Docker](/quickstart#run-with-docker) for a complete command.

## Build from source

```bash
git clone https://github.com/iamd3vil/hedwig.git
cd hedwig
cargo build --release
```

The binary will be at `./target/release/hedwig`.

### Build a local Docker image

From the repository root:

```bash
docker build -t hedwig:local .
docker run --rm hedwig:local --version
```

The Dockerfile uses Rust 1.98.0 and `cargo build --release --locked`.
The `.dockerignore` allowlist includes only the workspace manifests, lockfile,
and crate source trees. Configuration, keys, and queue data are supplied at runtime.

See [Release workflows](/reference/releases) for native multi-platform publishing
and rebuilding images for an existing release.
