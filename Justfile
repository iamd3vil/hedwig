default: run

run:
    cargo run

build:
    cargo build

build-linux $RUSTFLAGS="-C target-feature=+crt-static":
    cross build --release --target x86_64-unknown-linux-musl

build-macos $RUSTFLAGS="-C target-feature=+crt-static":
    #!/usr/bin/env sh
    if [ "$(uname)" = "Darwin" ]; then
        # Running on macOS
        cargo build --release --target aarch64-apple-darwin
    else
        # Running on non-macOS (Linux, Windows)
        docker run --rm \
        --volume ${PWD}:/root/src \
        --workdir /root/src \
        joseluisq/rust-linux-darwin-builder:1.81.0 \
        sh -c 'CC=aarch64-apple-darwin22.4-clang CXX=aarch64-apple-darwin22.4-clang++ TARGET_CC=aarch64-apple-darwin22.4-clang TARGET_AR=aarch64-apple-darwin22.4-ar cargo build --release --target aarch64-apple-darwin'
    fi

dev:
    #!/usr/bin/env sh
    cd dev && docker compose up
    cd ..
