---
priority: high
depends_on: [read_cyclonedx_sbom, check_sbom_completeness]
why: 'the milestone is only usable once the CLI exposes it'
---
# Add the `rollcall check` command

# Goal
A user runs `rollcall check <sbom>` and sees the spec version (and the flag when it is older than 1.6) and the
components missing the fields the CRA expects. The output must suit both a human and a CI job.

# Approach
1. CLI parsing with `clap` (derive), in the binary crate only.
2. Human-readable output by default, `--format json` for machines; the JSON shape belongs to an adapter.
3. Exit codes to settle at step 1, e.g. 0 complete, a distinct code for gaps found, another for an unreadable file;
   an option to make gaps non-fatal in CI is a candidate.
4. Reading from standard input (`-`) is a candidate for piping the output of an SBOM generator.

# Specs
* `specs/cli-check.md` (to write at step 1): arguments, output formats, exit codes.

# Milestone
Read and check an SBOM

# Resources
* `CLAUDE.md`: hexagonal architecture (formats are adapters).
* The issues `read_cyclonedx_sbom` and `check_sbom_completeness`.

# Hints
* Keep the command name open to later subcommands (`match`, `report`, `upload`).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-12

## Understanding
`rollcall check <sbom|->` prints the spec version (flagged below 1.6) and the incomplete components, as text or
`--format json`, with exit codes 0 / 1 gaps / 2 usage / 3 unreadable, and `--allow-incomplete` for CI.
Out of scope: matching, reports, upload, several SBOMs. The report formats are modules of the binary crate (ADR 0001:
adapters start as modules), `clap` derive with a `check` subcommand.

## Plan
1. [x] `check` subcommand: clap parsing, path or `-`, human report, exit codes, errors on stderr; verified by tests
   through the binary (`crates/rollcall/tests/check.rs`); makes true CHK-1, CHK-2, CHK-3, CHK-4, CHK-7, CHK-8, CHK-9,
   CHK-11 (`human`), CHK-12. (autonomous)
2. [x] JSON report adapter behind `--format json`; verified by tests through the binary parsing stdout; makes true
   CHK-5, CHK-10, CHK-11. (autonomous)
3. [x] `--allow-incomplete`, README usage section; verified by tests through the binary; makes true CHK-6, sets the
   spec `accepted`. (autonomous)
4. [x] Fixes of the `high` review and the docs of the whole issue; verified by tests through the binary; makes true
   CHK-13, CHK-14. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 863ffc1e5b32f8909761d39ea70060d15e33af85
- Exit codes: 0 complete, 1 incomplete, 2 usage, 3 unreadable SBOM.
- Non-fatal gaps: `--allow-incomplete`.
- JSON: an absent `version` or `purl` is `null`.
- Report formats: modules of the binary crate (ADR 0001), commit scope `cli`.

## Deliverable 1
- done: `rollcall check <sbom|->` with clap, human report (module `report`), exit codes 0/1/2/3, errors on stderr;
  README usage, CLAUDE.md status and layout.
- red: CHK-H1, CHK-H3, CHK-1, CHK-2, CHK-3, CHK-4, CHK-7, CHK-8, CHK-9, CHK-11, CHK-12: 10 tests failed, the empty
  binary exits with 0 and prints nothing (`left: 0, right: 1`).
- Code review: no findings
- not verified: none. Decisions needed: none.

## Deliverable 2
- done: `--format json`, the JSON report adapter in the module `report` (members of CHK-10, `null` for an absent
  version or purl); README.
- red: CHK-5, CHK-8, CHK-10, CHK-11: 3 tests failed, `invalid value 'json' for '--format <FORMAT>'` (exit 2).
- Code review: no findings
- not verified: none. Decisions needed: none.

## Deliverable 3
- done: `--allow-incomplete` (exit 0 on gaps, still 3 on an unreadable SBOM); README; spec `cli-check` accepted.
- red: CHK-H2, CHK-4, CHK-5, CHK-6, CHK-7, CHK-10: 3 tests failed, `unexpected argument '--allow-incomplete' found`.
- Code review: no findings
- not verified: none. Decisions needed: none.

## Deliverable 4 (high review of the issue)
- done: exit code 4 and a stderr line when the report cannot be written (CHK-13, a closed pipe aside); control
  characters of a component escaped in the human report (CHK-14); a non-UTF-8 path read, not refused; singular
  `1 component`; `./-` documented; help text no longer claims vulnerability matching; README install line; SBC
  non-goal links the spec instead of the issue.
- red: CHK-3, CHK-7, CHK-13, CHK-14: 5 tests failed, e.g. `/dev/full` exited 0 instead of 4, a non-UTF-8 path exited 2.
- High review: 8 findings; 7 fixed as above; not fixed: moving `File::open` into the adapter, as SBR's non-goals
  leave reading from disk to the command line.
- not verified: the closed-pipe case of CHK-13 (exit unchanged when `head` closes stdout) has no test: the report
  fits the pipe buffer, so a test would be timing-dependent.
- Code review: no findings
- Decisions needed: none.
