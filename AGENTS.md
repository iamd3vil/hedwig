# Repository Guidelines

## Repository Structure
- `Cargo.toml` – Rust workspace root referencing the `smtp-server` binary crate and the reusable `smtp` library crate.
- `smtp-server/` – main application (`src/main.rs`, `config.rs`, `callbacks.rs`, `storage/`, `worker/`).
- `smtp/` – protocol library with parsers and shared types (`src/lib.rs`, `src/parser.rs`).
- `dev/` – Docker and Mailpit sandbox (`docker-compose.yml`, TLS fixtures under `certs/`).
- `docs/` – configuration and architecture guides.
- `dist/` – published binaries and checksums; `tmp/`, `target/` should remain untracked in commits.

## Project Structure & Module Organization
Keep module-level documentation near the code: crate-specific guides belong in the respective `src/` tree, and tests sit next to the logic they cover (`smtp/src`, `smtp-server/src/**`). Configuration templates (`config.example.toml`) should mirror real deployments while keeping secrets out of the repo.

## Build, Test, and Development Commands
Use `just run` or `cargo run` for debug execution, and `just build` or `cargo build --release` for optimized binaries. `just test` wraps `cargo test` across the workspace; `just build-linux` and `just build-macos` produce portable targets. Start the Docker sandbox with `just dev`, and finish every change with `cargo fmt` plus `cargo clippy --workspace --all-targets`.

## Coding Style & Naming Conventions
Follow idiomatic Rust with four-space indentation, `snake_case` for modules and functions, `UpperCamelCase` for types, and `SCREAMING_SNAKE_CASE` for constants. Let `rustfmt` handle layout, keep worker logic scoped under `smtp-server/src/worker`, and return `miette::Result<T>` so diagnostics remain uniform.

## Testing Guidelines
Embed `#[cfg(test)] mod tests` in the same file as the code, mirroring `smtp/src/parser.rs` and `smtp-server/src/worker/*.rs`. Cover success and error paths, reuse existing fixtures, and run `cargo test` (via `just test`) before opening a pull request; when adding async flows, drive the Tokio runtime explicitly.

## Commit & Pull Request Guidelines
Use the conventional commit prefixes present in history (`feat:`, `fix:`, `docs:`, `test:`) and keep messages imperative and focused. Pull requests should state motivation, summarize the approach, reference linked issues, list configuration or migration steps, and note the commands used for verification (e.g. `cargo test`, `just dev`), attaching evidence when behaviour changes.

## Configuration & Security Tips
Keep environment-specific settings in untracked copies of `config.toml`; rely on `config.example.toml` and `dev/certs/` for local scaffolding. Never commit real keys or credentials—generate DKIM or TLS material locally and store it according to `docs/CONFIGURATION.md`.
