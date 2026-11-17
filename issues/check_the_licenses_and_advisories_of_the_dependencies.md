---
priority: medium
depends_on: [run_the_project_check_in_ci]
why: 'outside pull requests may add a copyleft or vulnerable dependency; nothing checks it'
---
# Check the licenses and advisories of the dependencies in CI

# Goal
`CLAUDE.md` forbids copyleft dependencies (GPL, AGPL, LGPL-only) so the crates stay `MIT OR Apache-2.0`, and a tool
that reports vulnerabilities should not ship known ones. Nothing checks either: every push to `main` and every pull
request should fail on a dependency whose license is not allowed or that a RustSec advisory names.

# Findings
* 2026-11-16: `.github/workflows/check.yml` runs format, lint, tests, the MSRV build and the macOS tests; no license
  nor advisory check. Split out of `run_the_project_check_in_ci`.
* No `deny.toml` in the repository.

# Approach
1. `cargo deny check licenses advisories bans sources` with a `deny.toml` allowing the permissive licenses the tree
   uses (to list with `cargo deny list`), in a job of `.github/workflows/check.yml`.
2. Candidates: `cargo audit` for the advisories only; a scheduled run so that a new advisory turns `main` red without
   a push.

# Milestone
Beta

# Resources
* `CLAUDE.md` (License), `.github/workflows/check.yml`, `crates/forewarn/data/ucd-16.0.0` (vendored data, Unicode
  License v3).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-17

## Understanding
Every push to `main`, every pull request and a daily schedule fail on a dependency whose license `deny.toml` does not
allow, that a RustSec advisory names, that is yanked, or that comes from a source other than crates.io. Out of scope:
the license notices of the release (`about.toml`, already checked by `release.yml`), `cargo audit` (cargo-deny covers it).
Found while preparing: the tree fails today, `time 0.3.45` (RUSTSEC-2026-0009) and `zip 7.3.0` (RUSTSEC-2026-0367,
-0368, -0369, -0429; `extract` is not called, but the check fails all the same): fixed by upgrading, not ignored.

## Plan
1. [x] Upgrade the vulnerable dependencies: `zip` 7 → 9 (`ZipFile::name` now returns a `Result`, in
   `forewarn-osv/src/fetch.rs`), `time` ≥ 0.3.47 in `Cargo.lock`; verified by the existing tests (the archive
   extraction and its unsafe-entry refusals) and `cargo deny check advisories` clean; ~100 lines (mostly `Cargo.lock`).
2. [ ] `deny.toml` (licenses = the `accepted` of `about.toml`, advisories, yanked denied, wildcard paths allowed for
   the unpublished workspace crates, crates.io only) and a job `dependencies` in `.github/workflows/check.yml`
   running `cargo deny --locked check licenses advisories bans sources` (`EmbarkStudios/cargo-deny-action`, pinned),
   plus a daily `schedule` running that job alone; verified by a test of `workspace_policy.rs` that the licenses
   `deny.toml` allows are those `about.toml` accepts, a local `cargo deny check` green, CLAUDE.md (License) and
   `docs/architecture.md` updated; ~150 lines.

## Decisions
- Mode: autonomous
- Base commit: e8f9d5723d29308abfc7e368e21d4890a7897c5e
- 1 a: the daily `schedule` lives in `check.yml` and runs the job `dependencies` alone.
- 2 a: `deny.toml` allows the licenses `about.toml` accepts; a test keeps them equal.

## Deliverable 1
- done: `zip` 9.6.1 (a name that does not decode now fails the archive as not a zip), `time` 0.3.55.
- checks: project-check green, `cargo +1.89 check --all-targets --locked` green, `cargo deny check advisories` ok
  (5 advisories before).
- red: none (no new test: the extraction tests of `forewarn-osv/tests/fetching.rs` cover the change).
- Code review: no findings
