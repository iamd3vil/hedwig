default: run

run:
    cargo run

run-release:
    cargo run --release

build:
    cargo build

build-linux $RUSTFLAGS="-C target-feature=+crt-static":
    cargo build --release --target x86_64-unknown-linux-musl

build-macos $RUSTFLAGS="-C target-feature=+crt-static":
    #!/usr/bin/env sh
    if [ "$(uname)" = "Darwin" ]; then
        # Running on macOS
        cargo build --release --target aarch64-apple-darwin
    else
        # Running on non-macOS (Linux, Windows)
        docker run --rm \
        --volume ${PWD}:/io \
        --workdir /io \
        ghcr.io/rust-cross/cargo-zigbuild:latest \
        sh -c 'rustup update stable && rustup target add aarch64-apple-darwin && cargo zigbuild --release --target aarch64-apple-darwin'
    fi

build-windows $RUSTFLAGS="-C target-feature=+crt-static":
    docker run --rm \
    --volume ${PWD}:/io \
    --workdir /io \
    ghcr.io/rust-cross/cargo-zigbuild:latest \
    sh -c 'rustup update stable && rustup target add x86_64-pc-windows-gnu && cargo zigbuild --release --target x86_64-pc-windows-gnu'

dev:
    #!/usr/bin/env sh
    cd dev && docker compose up
    cd ..

test:
    cargo test
