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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
`forewarn --version` must print the release it was built from. Cardinal already has the hook the issue wondered about:
`release_version_command` (REL-5 of Cardinal's `specs/release.md`), run by `cardinal run release <version>` after the
changelog with the version as last argument. Out of scope: publishing, a spec (build metadata, no domain behaviour).

## Plan
1. [x] Version on release: `[workspace.package] version = "0.2.0"` and `Cargo.lock`; a `just set-version <version>`
   recipe (sed of `[workspace.package]`, `cargo update --workspace --offline`) named as `release_version_command` in
   `.claude/cardinal.toml`; a test in `workspace_policy.rs` that the workspace version is the newest `CHANGELOG.md`
   section, and a test running the binary with `--version` that it prints `forewarn <workspace version>`; docs
   (CLAUDE.md, `docs/architecture.md` or user guide where releases are described); verified by those two tests and a
   dry run of `just set-version` restored afterwards. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 99fa116036ecf3b77c87536410f123099b528e89
- No spec: release tooling, no behaviour of the domain (answer 1 a).
- The version is written by a `just set-version` recipe (sed + `cargo update`), not cargo-edit (answer 2 a).

## Deliverable 1 summary
- done: workspace version `0.2.0`; `just set-version` named as the `release_version_command`; two tests (workspace
  version = newest changelog section, `forewarn --version` prints it); CLAUDE.md and the docs map.
- checks: tests ok, lint ok, specs n/a, docs ok; dry run `just set-version 9.9.9` then `0.2.0` rewrote `Cargo.toml` and
  `Cargo.lock` and back.
- red: none (no spec): `left: Some("0.0.0") right: Some("0.2.0")`.
- Code review: no findings
