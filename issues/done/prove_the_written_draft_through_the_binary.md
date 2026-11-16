---
priority: low
why: 'the escaping is proven by internal tests of the writer; only the wiring of `--drafts` to it is unproven'
---
# Prove the escaping of the written draft through `forewarn match --drafts`

# Goal
The tests of the written draft live in `crates/forewarn/src/early_warning.rs` and give as their reason `internal: no
command writes a draft before cli_draft_early_warnings`, which is false since `forewarn match --drafts` writes drafts.
No test through the binary drives a character that hides text into a written draft, so a change of the module
`drafts` that bypassed the escaping would pass. Prove EWD-16 at the boundary, and give the internal tests a reason
that is true.

# Findings
* Found by the `high` review of `escape_the_other_characters_drawn_as_blank` (2026-11-16).
* 12 tests of `early_warning.rs` carry the stale reason; `crates/forewarn/tests/drafts.rs` writes drafts through the
  binary but checks no escaped value.

# Approach
1. Add to `tests/drafts.rs` a test whose SBOM names a component with U+202E, U+13441 and a Markdown punctuation
   character, and read the written file.
2. Reword the reason of the internal tests that stay (e.g. the samples a fixture would not walk through), or move
   those the binary proves cheaply.

# Specs
* `specs/early-warning-draft.md`: EWD-16 (traced again through the binary), no requirement changed.

# Resources
* `crates/forewarn/src/early_warning.rs` (its tests), `crates/forewarn/tests/drafts.rs`.
* `specs/README.md` (placement of `// spec:` and the internal reason).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
Prove EWD-16 through `forewarn match --drafts`: an SBOM component named with U+202E, U+13441 and Markdown punctuation
reaches the written file escaped. Then give the 12 internal tests of `early_warning.rs` a true reason. No requirement
and no production code change.

## Plan
1. [x] Binary test and true reasons: a test of `tests/drafts.rs` reads the written draft of a component named
   `a|b` U+202E `log4j` U+13441 `-core` and finds each escaped; the internal tests keep their samples (one per class
   of character, drafts the domain does not build, the exact whole text) with a reason saying so; verified by
   `cargo test` and `check-specs`; makes true EWD-16 (traced through the binary). (autonomous)
2. [x] Fixes of the `high` review: the binary test also drives a newline and `#` and checks no raw `a|b` is
   left; the internal reasons say only what is true; the module doc of `tests/drafts.rs` names the draft spec;
   verified by `cargo test` and `check-specs`; makes true EWD-16. (autonomous)

## Decisions
- Mode: autonomous
- 1 a: the internal tests stay, with a true reason.
- Base commit: 5722d2978c31db71200abc0d667d87afd80c9d5b

## Summary of deliverable 1
- done: `tests/drafts.rs` drives a component named `a|b` U+202E `log4j` U+13441 `-core` through `forewarn match
  --drafts` and finds it escaped in the written file; the 12 internal tests of `early_warning.rs` give a true reason.
- red: EWD-16: the test passed at once (the behaviour exists); with `push_escaped` bypassed it failed at
  `drafts.rs:451` (the escaped name missing from the draft).
- Code review: no findings (low).
- not verified: none.
- decisions needed: none.

## Summary of deliverable 2
- done: the `high` review's findings on the test and the reasons fixed; the ambiguity of an escape and its literal
  text (outside EWD-16 as written) became `issues/done/tell_an_escape_from_its_literal_text_in_a_draft.md`.
- red: none (stronger assertions of a passing test, comments).
- Code review: no findings (low).
- not verified: none.
- decisions needed: none.
