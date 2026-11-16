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
