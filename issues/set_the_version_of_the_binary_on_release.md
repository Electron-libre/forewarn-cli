---
priority: high
why: 'a beta user reports bugs against a version; today every build says 0.0.0'
---
# Set the version of the binary on each release

# Goal
`forewarn --version` must print the version of the release it was built from. Today the tags `v0.1.0` and `v0.2.0`
exist, but `[workspace.package] version` stays `0.0.0`, so every build prints `forewarn 0.0.0`. A beta tester cannot
say which version they run, and a published crate or binary would carry the wrong number.

# Findings
* 2026-11-16, at `4341437` (after `v0.2.0`): `target/debug/forewarn --version` prints `forewarn 0.0.0`.
* `Cargo.toml`: `[workspace.package] version = "0.0.0"`; every crate has `version.workspace = true`.
* `crates/forewarn/src/main.rs` uses clap's `#[command(version)]`, i.e. `CARGO_PKG_VERSION`.
* `cardinal run release <version>` writes the `CHANGELOG.md` section and `--tag` creates the tag; it does not touch
  `Cargo.toml` (unknown whether Cardinal offers a hook for it).

# Approach
1. Set the workspace version to `0.2.0` now (the last release), so `main` stops claiming `0.0.0`.
2. Then make each release bump it, candidates:
   1. a documented manual step before `cardinal run release <version> --tag`, checked by a test that compares the
      workspace version with the newest section of `CHANGELOG.md`;
   2. a hook or option of Cardinal's `release` that writes the version (a change to Cardinal, not to this repo).
3. Optionally, a test running the binary with `--version`.

# Milestone
Beta

# Resources
* `Cargo.toml`, `CHANGELOG.md`, `cardinal.just` (`release`).
* `crates/forewarn/tests/workspace_policy.rs` (where a version check could live).

# Hints
* `Cargo.lock` changes with the version: commit it too.
