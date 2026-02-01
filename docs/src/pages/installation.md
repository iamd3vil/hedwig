---
layout: ../layouts/DocLayout.astro
title: Installation
description: Build and install Hedwig from source.
---

# Installation

## Prerequisites

- A domain name (for DKIM setup)

## Install from GitHub Releases (recommended)

Latest release: `v0.5.2`

Linux x86_64:

```bash
curl -L -o hedwig.zip https://github.com/iamd3vil/hedwig/releases/download/v0.5.2/hedwig-v0.5.2-linux-x86_64.zip
unzip hedwig.zip
chmod +x hedwig
```

Checksums are available at:

```
https://github.com/iamd3vil/hedwig/releases/download/v0.5.2/checksums.txt
```

## Build from source

```bash
git clone https://github.com/iamd3vil/hedwig.git
cd hedwig
cargo build --release
```

The binary will be at `./target/release/hedwig`.
