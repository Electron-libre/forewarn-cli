---
priority: high
depends_on: [set_the_version_of_the_binary_on_release, run_the_project_check_in_ci]
why: 'a beta tester must be able to install forewarn without cloning the repository and building it'
---
# Distribute the forewarn binary

# Goal
Today the only install is `cargo install --path crates/forewarn` from a clone (`README.md`, `docs/user-guide.md`),
which needs a Rust toolchain: a vendor's CI using `syft` or `cdxgen` may have none. A beta tester should install a
released version in one command, and a CI job should pin it.

# Findings
* `Cargo.toml`: `publish = false` in `[workspace.package]`, with the comment that the `forewarn` names are free on
  crates.io (2026-11-12) and that publishing waits for its own decision.
* `CLAUDE.md`: the path dependencies need a `version` before a publication; six crates, the domain and the adapters
  are libraries the hosted service may depend on.
* No GitHub release holds a binary; tags `v0.1.0` and `v0.2.0` exist.

# Approach
A decision to take at step 1 (an ADR):
1. Publish the crates on crates.io (`cargo install forewarn`, `cargo binstall`): needs a `version` on each path
   dependency, a publication order, and makes the library crates a public API.
2. Build release binaries (Linux x86_64 and aarch64, macOS, Windows) in a workflow on each tag and attach them to a
   GitHub release, with checksums (e.g. `cargo-dist` or a hand-written matrix).
3. Both; and optionally a container image for CI.
Then update the install sections of `README.md` and `docs/user-guide.md`.

# Milestone
Beta

# Resources
* `Cargo.toml`, `crates/*/Cargo.toml`, `README.md` (Quick start), `docs/user-guide.md` (Install).
* ADR 0001 (crate layout), `CLAUDE.md` (Public repository, License).

# Hints
* The release workflow only runs on a pushed tag; `cardinal run release --tag` never pushes it.
* Every dependency must stay compatible with `MIT OR Apache-2.0`, including what the release tooling bundles.
