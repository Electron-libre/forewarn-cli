---
priority: medium
why: 'once a VEX verdict silences a match, the draft of an earlier run stays in the drafts directory, and a CI job uploading it publishes an early warning the vendor no longer stands by'
---
# Stop leaving the stale draft early warnings of an earlier run in the drafts directory

# Goal
`forewarn match --drafts <dir>` replaces the draft of each CVE it drafts again (MXL-29) and writes nothing when no
match is actively exploited (MXL-30), but never touches the draft of a CVE it no longer drafts. A vendor who sets a
match aside with a VEX verdict, or upgrades the component, keeps the `<product>-<CVE>.md` of the earlier run in the
directory; a CI job that publishes the directory as an artifact then ships an early warning for a vulnerability that
no longer affects the product. A rerun should leave in the directory only what it stands by, or say what is stale.

# Findings
* Found by the `high` review of `issues/done/read_vex_verdicts.md`: with a `not_affected` verdict added, the second run
  exits with 0, lists no draft, and the file of the first run is still there.
* `crates/forewarn/src/drafts.rs` names a file `<product>-<CVE>.md` and replaces it atomically (MXL-34); it lists no
  file of the directory.
* The same happens without VEX when a component is upgraded out of the vulnerable range.

# Approach
1. Remove, at each run with `--drafts`, the files of the same product named like a draft (`<product>-CVE-*.md`) that
   the run does not write again, and name them in the report.
2. Or keep them and list them as stale in the report (human and JSON), with no removal.
3. Either way, decide what happens to a file a person edited by hand.

# Specs
* `specs/cli-match-exploited.md` (MXL-29, MXL-30, new requirements), `specs/cli-match.md` (MCH-16 if the JSON report
  names them).

# Milestone
Beta

# Resources
* `crates/forewarn/src/drafts.rs`, `crates/forewarn/src/main.rs` (`write_drafts`).
* ADR 0013, `specs/cli-match-vex.md` (MVX-5).

# Hints
* A draft may hold the fields a person completed: removing it loses their work.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-17

## Understanding
A rerun with `--drafts` names, in the human and JSON reports, the drafts of the same product it no longer writes
(stale), with their CVE, and leaves them in place: approach 2, since a draft may hold fields a person completed.
Out of scope: removing them, a new exit code, other products sharing the directory.

## Plan
1. [x] Stale drafts: `drafts` lists the files of the directory named `<product>-CVE-….md` (MXL-31) the run did not
   write, `main` lists them also with no exploited match, the human report and `staleDrafts` of the JSON report name
   them, a directory that cannot be listed exits with 7; verified by tests of `crates/forewarn/tests/drafts.rs` through
   the binary; makes true MXL-36 to MXL-40, MCH-16 (`staleDrafts`), MCH-10 (row 7). (autonomous)
2. [x] Fixes of the `high` review: list before writing (a listing failure writes no draft), a path naming a file or
   under one holds no stale draft, entries filtered by name before their type, one prefix for the names written and
   listed, the CVE grammar of the domain (`forewarn_domain::is_cve`), `Written` renamed `DraftFile`; verified by the
   tests of MXL-40 in `crates/forewarn/tests/drafts.rs`. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 53a5194e36fa55d8dc70c686db3e05365779407c
- Stale drafts are listed, never removed; no exit code for them (a CI job reads `staleDrafts`); sorted by file name.

## Summary of deliverable 1
done: `forewarn match --drafts` lists the stale drafts of the product (human report and `staleDrafts`), leaves them in
place, exits with 7 on a directory it cannot list; specs back to `accepted`.

| check | result |
|---|---|
| tests | `cargo test` green (7 new tests in `crates/forewarn/tests/drafts.rs`) |
| lint | `cargo clippy --all-targets -- -D warnings` clean |
| specs | `check-specs` clean, MXL-36 to MXL-40 traced |
| docs | user guide, architecture, CLAUDE.md |
| code review | `low`, no findings |

red: MXL-H7, MXL-36, MXL-37, MXL-38, MXL-39, MXL-40: `staleDrafts` was `null`, the human report had no stale heading, and a draft directory that is a file exited with 0.

Code review: no findings

not verified: a directory unreadable through its permissions (the test uses a regular file, portable to a root CI).

decisions needed: none

## Summary of deliverable 2
done: the 8 findings of the `high` review fixed; MXL-40 reworded (exit 7 before any draft; a path naming a file holds no
stale draft).

| check | result |
|---|---|
| tests | `cargo test` green; MXL-40 tested on a directory of mode 0300 and on a path naming a file |
| lint | clean |
| specs | `check-specs` clean |
| docs | user guide (exit 7 writes no draft), architecture (order of the output) |
| code review | `low`, no findings |

red: MXL-40: the earlier run wrote the draft before failing on the listing, and exited with 7 on a path naming a file with no exploited match (the high review's findings 1 and 5).

Code review: 0 findings

High review of the issue: 8 findings, all fixed in this deliverable (ENOTDIR read as absent, `file_type` after the name
filter and `NotFound` skipped, one prefix for both lists, listing before writing, the 0300 test, the domain's
`is_cve`, `DraftFile`, the prefix computed once).

not verified: the 0300 test on macOS CI and as root (it returns early when the directory can still be listed).

decisions needed: none
