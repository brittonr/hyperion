# Agent Notes

## Scope
- Hyperion is a Rust workspace for a Minecraft game server/proxy stack.
- Shared engine and protocol crates live under `crates/`.
- Game-specific code currently lives under `events/bedwars`.
- Helper binaries and tooling live under `tools/`.
- Repo has both `.git/` and `.jj/`. Check `jj` state before assuming git-only workflow.

## Toolchain and config
- `rust-toolchain.toml` pins `nightly-2025-02-22` with `rustfmt` and `clippy`.
- `.cargo/config.toml` adds `--cfg tokio_unstable` and `-Ctarget-cpu=native`. Run cargo from repo root so those flags apply.
- `Cargo.toml` defines custom profiles worth knowing:
  - `release-debug` -> release build with debug info
  - `release-full` -> fat LTO, single codegen unit, `panic = 'abort'`

## Fast checks
- `just fmt`
- `just lint`
- `just test` -> `cargo nextest run`
- `just ci` -> runs `fmt`, `unused-deps`, and `deny` in parallel, then `lint`, `test`, and `doc-once`
- `just unused-deps` -> `cargo machete`
- `just deny` -> `cargo deny check`

## Running locally
- `just debug` and `just release` use GNU `parallel` plus `cargo watch` to rebuild `bedwars` while keeping the proxy running.
- `just proxy` connects to `127.0.0.1:35565` and listens on `0.0.0.0:25565`.
- `just bedwars-full` runs the Bedwars server with profile `release-full`.
- `just bots <ip> <count>` installs and runs `rust-mc-bot` for load testing.
- `justfile` still has an `extract` recipe, but this checkout does not currently contain `extractor/` or `extracted/` directories. Verify before relying on that path.

## CI
- CI checks formatting, clippy, docs, coverage, and tests.
- Coverage job uses nightly plus `cargo llvm-cov --all-features --workspace --branch`.
- Test job runs `cargo test --all-features` on Ubuntu and Windows.

## Architecture
- `README.md` describes one game server running game logic, with one or more proxies in front of it.
- Shared or reusable engine work usually belongs under `crates/hyperion*` or sibling crates in `crates/`.
- Bedwars-only mechanics belong under `events/bedwars`.
- Packet debugging and bot tooling live under `tools/packet-inspector` and `tools/rust-mc-bot`.
