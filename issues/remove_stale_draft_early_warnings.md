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
