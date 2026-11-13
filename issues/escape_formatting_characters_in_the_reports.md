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
