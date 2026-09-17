---
layout: ../../layouts/DocLayout.astro
title: Release workflows
description: Publish release binaries and native multi-platform Docker images.
---

# Release workflows

Pushing a `v*` Git tag triggers two independent workflows:

- **Release** uses `rlsr.yml` and `just build-linux` to publish the Linux x86_64
  binary archive and checksums to GitHub Releases. The binary targets
  `x86_64-unknown-linux-gnu` with static glibc linking.
- **Docker** publishes `ghcr.io/iamd3vil/hedwig` for Linux AMD64 and ARM64.
  AMD64 builds on `ubuntu-24.04`; ARM64 builds on `ubuntu-24.04-arm`.
  Each job builds natively, pushes by digest, and uses its own architecture's
  build cache. A merge job publishes the multi-platform tags only after both
  builds succeed.

For `v0.12.3`, Docker publishes `0.12.3`, `0.12`, and `latest`. The Docker
workflow checks out the release tag, so the image contains the tagged source.
A successful binary release does not imply that Docker publishing has finished;
check both workflows.

## Rebuild Docker images for an existing release

The Docker workflow also accepts a manual `tag` input. Run the workflow from
`main` to use the current workflow while building the existing tagged source:

```bash
gh workflow run docker.yml --ref main -f tag=v0.12.3
gh run list --workflow docker.yml
```

In GitHub's Actions UI, select **Docker**, then **Run workflow**, choose `main`,
and enter the existing release tag. This does not move the Git tag or create
another GitHub release. It republishes the image's version, major/minor, and
`latest` tags, so rebuilding an older release also moves those floating tags
to that release. Base images and system packages may have changed since the
original build.

If replacing a running build from an older workflow, cancel that run first to
prevent it from publishing over the replacement. New runs for the same release
are serialized by the workflow's concurrency group.

## Verify publication

```bash
docker buildx imagetools inspect ghcr.io/iamd3vil/hedwig:0.12.3
docker run --rm ghcr.io/iamd3vil/hedwig:0.12.3 --version
```

The image index should contain `linux/amd64` and `linux/arm64`. Additional
attestation entries may appear as `unknown/unknown`.
