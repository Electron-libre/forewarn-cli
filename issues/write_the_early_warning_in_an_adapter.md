---
priority: high
depends_on: [draft_the_early_warning_in_the_domain]
why: 'the milestone requires the format to live in an adapter so that a regulatory format change only touches it'
---
# Write a draft early warning in a format an adapter owns

# Goal
The domain builds a draft early warning; a vendor needs it as a document to copy into the ENISA Single Reporting
Platform form. An adapter should write it, so that a change of the SRP glossary or of the regulatory format only
touches that adapter.

# Findings
* With no SRP API at launch (secondary sources, 2026-11-13), the reader of the draft is a person filling a web form.
* `crates/forewarn/src/report.rs` (659 lines) already holds the human and JSON reports of `check` and `match`.

# Approach
1. Where the adapter lives: a module of the CLI crate beside `report`, or a crate of its own (e.g.
   `forewarn-report`) the hosted service could reuse; the choice is an ADR.
2. A Markdown draft listing the fields in the order and with the names of the SRP glossary recorded by
   `draft_the_early_warning_in_the_domain`, each field to complete marked so it cannot be missed, the deadlines and
   the evidence at the top.
3. Candidate: a JSON form of the same draft, for an internal workflow; only if step 1 finds a reader for it.

# Specs
* `specs/early-warning-draft.md`: the requirements of the written format (amended at step 1).

# Milestone
Draft the CRA early warning

# Resources
* `crates/forewarn/src/report.rs`, ADR 0001 (crate layout), `CLAUDE.md` ("Hexagonal architecture", "Public repository":
  the service may depend on crates of this repository, never the reverse).
* The ADR of the SRP glossary version written by `draft_the_early_warning_in_the_domain`.

# Hints
* A value from the SBOM or a feed written into Markdown must be escaped (a component name may hold `|`, `*` or a
  newline).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Write a domain `EarlyWarning` as a Markdown document in the order and with the labels of the SRP glossary 1.6, the
fields to complete marked `**TO COMPLETE**`, every SBOM or feed value escaped. Out of scope: the CLI option or command
and the files (`cli_draft_early_warnings`), a JSON form (no reader found, ADR 0013).

## Plan
1. [x] Markdown writer: module `crates/forewarn/src/early_warning.rs`, `markdown(&EarlyWarning) -> String`, with ADR
   0013 and the amended spec; verified by internal tests (no command prints a draft before `cli_draft_early_warnings`);
   makes true EWD-12 to EWD-16. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 4a939e2407733d4526191ef4fabebd9626afdac8
- Adapter: a module `early_warning` of the CLI crate (ADR 0013), not a crate of its own.
- No JSON form of the draft.
- Escaping: a backslash before every ASCII punctuation character, control characters written as their escape.

## Deliverable 1 summary
- done: `early_warning::markdown` writes a draft in Markdown (title, fields to complete, deadlines, evidence, glossary
  fields), ADR 0013, spec EWD-12 to EWD-16 accepted, CLAUDE.md updated.
- red: EWD-12, EWD-13, EWD-14, EWD-15, EWD-16: the 5 tests failed on a stub (`left: ""`, fields missing).
- Code review: no findings
- not verified: the rendering in a Markdown viewer (the tests check the source); no command prints a draft yet
  (`cli_draft_early_warnings`), the module carries an `expect(dead_code)` until then.
