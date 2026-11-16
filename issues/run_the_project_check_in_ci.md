---
priority: high
why: 'a beta opens the repository to outside pull requests; nothing checks that they build and pass the tests'
---
# Run the project check in CI

# Goal
The only workflow, `.github/workflows/cardinal.yml`, checks the specs, the synced harness files and the commit
messages; it never builds the code nor runs `cargo fmt`, `cargo clippy` or `cargo test`. Every push to `main` and
every pull request should run the project check (`check_command` of `.claude/cardinal.toml`) and fail on a red one.

# Findings
* 2026-11-16, at `4341437`: `.github/workflows/` holds only `cardinal.yml` (jobs `cardinal` and `commits`).
* Locally, the project check passes: `cargo fmt --all --check`, `cargo clippy -q --all-targets -- -D warnings`,
  `cargo test -q` (513 tests, 0 failed).
* Workspace `rust-version = "1.89"`, edition 2024.
* Some tests reach the network or not: unknown whether all of them run offline (the fetching tests use local
  servers or fixtures; to verify on a runner).

# Approach
1. Add a workflow (or a job) on `push` to `main` and `pull_request` that installs the stable toolchain with
   `rustfmt` and `clippy`, caches the cargo registry and `target`, and runs the `check_command`.
2. Candidates to combine: also build on the MSRV (`1.89`) to keep `rust-version` true; also run on macOS and
   Windows, where the file lock of the cache (ADRs 0005, 0007) and the paths differ.
3. Run `cargo deny` or an equivalent for the licenses (no copyleft dependency, `CLAUDE.md`) and the advisories:
   optional, may be its own issue.

# Milestone
Beta

# Resources
* `.github/workflows/cardinal.yml`, `.claude/cardinal.toml` (`check_command`).
* ADRs 0005 and 0007 (file lock), `CLAUDE.md` (license and lint policy).

# Hints
* `cardinal.yml` is synced by Cardinal (`cardinal check` fails when it is edited): put the new job in a file of its own.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
Add a workflow of its own (`.github/workflows/check.yml`, `cardinal.yml` being synced) on `push` to `main` and
`pull_request` that runs the `check_command` read from `.claude/cardinal.toml` (one source of truth), with the cargo
cache. Out of scope: `cargo deny` (its own issue), publishing, releases.

## Plan
1. [x] Project check in CI: `.github/workflows/check.yml` with a job `check` (ubuntu, stable with `rustfmt` and
   `clippy`, the `check_command` of `.claude/cardinal.toml`), a job `msrv` (`cargo check --all-targets --locked` on
   the toolchain of `rust-version`), a job `test` on macOS and Windows (`cargo test --locked`); verified by
   `actionlint`, the `check_command` and the MSRV build run locally, then the first run on GitHub (after the push, the
   user's); makes true no requirement (CI, no spec).

## Decisions
- Mode: autonomous
- Base commit: 1178af9dd3392f845c02a208b5e7a92af5bd06a9
- Tests on macOS and Windows (`cargo test --locked`) besides the full check on Linux.
- MSRV: `cargo check --all-targets --locked` on 1.89, verified locally before the commit.
- `cargo deny` (licenses, advisories): its own issue.

## Summary of deliverable 1
- done: `.github/workflows/check.yml` (jobs `check`, `msrv`, `test` on macOS and Windows); `CLAUDE.md` names it.
- checks: project check passes; the `check_command` extracted by the workflow's `sed` and run locally passes;
  `cargo +1.89 check --all-targets --locked` passes; the YAML parses.
- red: none (CI configuration, no test).
- Code review: no findings
- not verified: `actionlint` (its container was refused locally); the macOS and Windows jobs (a cross build for
  Windows needs a MinGW compiler for `ring`): the first run on GitHub tells.
