---
priority: high
depends_on: [write_the_early_warning_in_an_adapter]
why: 'what the user runs: without it the milestone delivers nothing a vendor can use'
---
# Write a draft early warning for each actively exploited match from the CLI

# Goal
A vendor runs `forewarn match` in CI or by hand; when a match is actively exploited they should get, in the same run,
a draft CRA early warning for it, ready to complete and copy into the ENISA Single Reporting Platform.

# Approach
1. The command: an option of `match` (e.g. `--draft <dir>`, writing one file per exploited match) or a subcommand
   (`forewarn draft`) taking the same inputs; to decide at step 1.
2. The file name: stable and unique per match (product, CVE), so that a rerun overwrites the draft of the same
   vulnerability rather than piling copies.
3. The report of `match` names the files written; the exit codes stay those of `specs/cli-match.md` and
   `specs/cli-match-exploited.md` (6 on an exploited match), a draft that cannot be written exiting with a code of its
   own.

# Specs
* `specs/cli-match-exploited.md` (MXL-n) or a new `specs/cli-draft.md`, depending on step 1.

# Milestone
Draft the CRA early warning

# Resources
* `crates/forewarn/src/main.rs` (arguments, `--aware-since`, `--measure-available`, `--now`).
* `specs/cli-match.md`, `specs/cli-match-exploited.md`.

# Hints
* `--aware-since` and `--now` already give a deterministic run: the drafts of the tests should use them.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
`forewarn match --drafts <dir>` writes, in the same run, one Markdown early warning draft per CVE of the exploited
matches (`<product>-<CVE>.md`, replaced on a rerun), names the files in the report and exits with 7 when one cannot be
written. Out of scope: removing stale drafts, printing a draft on standard output, another format.

## Plan
1. [x] Write the drafts: `--drafts <dir>`, drafting with `draft_early_warnings` and `early_warning::markdown`, the file
   name, the directory created, the write through a temporary file and a rename, exit 7; verified by tests through the
   binary in `crates/forewarn/tests/drafts.rs`; makes true MXL-27, MXL-29, MXL-30, MXL-31, MXL-32, MXL-33, MXL-34. (autonomous)
2. [ ] Name the drafts in the report: a line per draft in the human report, the member `drafts` in the JSON report;
   verified by tests through the binary; makes true MXL-28, MXL-35, MXL-H6, the `drafts` row of MCH-16.

## Decisions
- Command: an option `--drafts <dir>` of `match`, not a subcommand: the same inputs, one run, one exit code.
- Mode: autonomous
- File name: `<product>-<CVE>.md`, no version, so that a rerun after a version bump replaces the draft.
- The drafts are written before the report: a failure prints nothing on standard output and exits with 7.
- Drafts of a CVE no longer exploited stay in the directory (non-goal): never remove a file the vendor may have completed.
- Base commit: 84ac14045c180180f74a673315b3dc036c778d37

## Deliverable 1: write the drafts
- done: `forewarn match --drafts <dir>` writes `<product>-<CVE>.md` per exploited CVE (module `drafts`), through a
  temporary file and a rename, the directory created only when there is a draft; exit 7 when one cannot be written.
- checks: tests ok, clippy ok, fmt ok, specs ok, docs (README, CLAUDE.md, EWD non-goal) ok, code review low done.
- red: MXL-27, MXL-29, MXL-30, MXL-31, MXL-32, MXL-33, MXL-34: `error: unexpected argument '--drafts' found`
- Code review: 1 findings
  - a CVE id holding `/` could name a path out of the directory: already refused upstream (EXF-7 reads only
    `CVE-<year>-<digits>`), the CVE id is now also kept to the safe characters, as defence in depth.
- not verified: a directory without write permission (the test uses a regular file and a directory in place of the
  draft instead, the tests may run as root).
