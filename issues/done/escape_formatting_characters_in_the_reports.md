---
priority: medium
why: 'a component name from an untrusted SBOM or feed can reorder or hide what a person reads in the report; no milestone needs it to work'
---
# Escape the bidirectional and invisible characters of the text reports

# Goal
The human reports of `forewarn check` and `forewarn match` escape the control characters of a value read from the
SBOM or a feed (CHK-14, MCH-23), not the bidirectional overrides and isolates, the zero-width characters nor the line
and paragraph separators. Such a value can reorder or hide the name or version of a component in a terminal (the
"Trojan Source" trick). The reports should escape them as the written early warning does.

# Findings
* `crates/forewarn/src/report.rs`, `push_escaped`: escapes `char::is_control` (Unicode category Cc) only.
* `crates/forewarn/src/early_warning.rs`, `is_formatting` (EWD-16): already escapes U+061C, U+200B to U+200F, U+2028
  to U+202E, U+2060 to U+2069 and U+FEFF as `\u{…}`.
* Found by the `high` review of `write_the_early_warning_in_an_adapter` (2026-11-13).

# Approach
1. Share one predicate of the characters to escape between `report` and `early_warning` (a small module of the CLI
   crate), so that the two writers cannot drift.
2. Escape them in the text reports and in the error lines of standard error (MCH-23); the JSON report already
   escapes through `serde_json` only what JSON requires: decide whether it should too.

# Specs
* `specs/cli-check.md` (CHK-14) and `specs/cli-match.md` (MCH-23): amend the escaping requirement.

# Resources
* `crates/forewarn/src/report.rs`, `crates/forewarn/src/early_warning.rs`, `specs/early-warning-draft.md` (EWD-16).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-14

## Understanding
Escape the bidirectional and invisible formatting characters of EWD-16 in the human reports of `check` and `match`
and in the error lines of standard error, with one predicate shared with the early warning writer. The JSON reports
stay as `serde_json` writes them (a non-goal of both specs).

## Plan
1. [x] Shared escaping: a module `escape` of the CLI crate owns the predicate of the formatting characters, used by
   `report::push_escaped` (reports and error lines) and `early_warning::push_escaped`; verified by a new test file
   `crates/forewarn/tests/formatting_characters.rs` driving `check`, `match` and an error through the binary
   (`tests/matching.rs` is already over the file-size limit); makes true CHK-14, MCH-18, MCH-23. (autonomous)
2. [x] Fixes of the `high` review: the whole escaping policy (`escape_char`, `push_escaped`, `escaped`) moves to
   `escape`, used by `report`, `main` and `early_warning`; the tests assert that no injected character prints raw;
   verified by `tests/formatting_characters.rs`; makes true CHK-14, MCH-18, MCH-23. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 62aa4afb0c3a12cf3cdcefe2abe41e8e68623df4
- JSON reports: not escaped (1 a), a non-goal of CHK and MCH.
- Follow-up: the other invisible characters, the backslash and the joiners go to
  `issues/done/widen_the_escaping_of_the_writers.md` (findings 1 to 3 of the `high` review).

## Summary of deliverable 1
- Code review: no findings
- done: module `escape` (the predicate of EWD-16) shared by `report` and `early_warning`; the human reports and the
  error lines escape the formatting characters as `\u{…}`; CHK-14, MCH-18, MCH-23 amended, specs accepted.
- checks: tests, fmt, clippy, specs pass; docs: CLAUDE.md layout table.
- red: CHK-14, MCH-18, MCH-23: the report and the error printed U+202E, U+200B, U+2066 and U+FEFF raw
  (`left: "  evil 1\u{202e}0\u{200b}: …"` written as the characters themselves).
- file size: `main.rs` grows from 809 to 810 lines (the `mod escape;` line); its split is not this issue's.
- not verified: the rendering in a real terminal.

## Summary of deliverable 2
- Code review: no findings
- done: findings 4 to 7 of the `high` review fixed (one escaping policy in `escape`, stricter assertions);
  findings 1 to 3 (other Cf characters, the backslash, the joiners) filed as `issues/done/widen_the_escaping_of_the_writers.md`.
- checks: tests, fmt, clippy, specs pass.
- red: none (a refactor under green tests, assertions added).
- not verified: nothing beyond deliverable 1.
