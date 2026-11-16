---
priority: low
why: 'a crafted name can pass for, or mask, a hidden character in a draft a person rereads before sending it; no draft is sent unread'
---
# Tell an escaped character from the same text typed in the SBOM in a written draft

# Goal
In a written draft, a value holding U+202E and a value holding the six characters `\u{202e}` are written alike:
`\\u\{202e\}`, read `\u{202e}` once rendered. A reader of the draft cannot tell a hidden bidi control from harmless
text, so a crafted component name can pass for, or mask, a hidden character in what goes to the ENISA platform. The
reports of `check` and `match` already tell them apart (`escape::push_escaped` doubles a literal backslash, CHK-14,
MCH-18); the Markdown writer does not. Make each escape of EWD-16 read differently from any literal text.

# Findings
* Found by the `high` review of `prove_the_written_draft_through_the_binary` (2026-11-16).
* `early_warning::push_escaped` passes each character through `escape::escape_char`, then puts a backslash before
  each ASCII punctuation character: the backslash of a literal `\u{202e}` and that of the escape of U+202E both
  become `\\`.
* `crates/forewarn/tests/drafts.rs` (`a_component_name_that_hides_text_or_forges_markdown_is_written_escaped`) and
  the EWD-16 tests of `early_warning.rs` assert the current form.

# Approach
1. Amend EWD-16 first: the form of an escape that no literal value produces once rendered.
2. Candidates, to weigh against the readability of the draft: write a literal backslash as `\\\\` (rendered `\\`),
   as the reports do; or write each escape in an inline code span; or as a named marker (`[U+202E]`) whose brackets a
   literal value would have escaped.

# Specs
* `specs/early-warning-draft.md`: EWD-16 amended.

# Resources
* `crates/forewarn/src/early_warning.rs` (`push_escaped`), `crates/forewarn/src/escape.rs`.
* `issues/done/widen_the_escaping_of_the_writers.md` (how the reports settled the same ambiguity).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
A backslash of a value is written `\\\\` in the draft, rendered `\\`, as the reports print it (CHK-14): the text
`\u{202e}` then reads `\\u{202e}`, a real U+202E `\u{202e}`. Candidates 2 and 3 of the issue (code span, named marker)
are left out: they would make the draft and the reports disagree.

## Plan
1. [x] Double the backslash of a value in the draft: `early_warning::push_escaped` writes a literal backslash as
   `\\\\`; verified by a test of `tests/drafts.rs` on a component named with the text `\u{202e}` and a real U+202E;
   makes true EWD-16 (amended). (autonomous)
2. [x] Fixes of the `high` review: `escape::escape_char` doubles the backslash for the reports and the draft alike,
   its doc no longer says the draft treats it as punctuation only; the binary test also sends `\*`; verified by
   `cargo test`; makes true EWD-16, CHK-14, MCH-18. (autonomous)

## Decisions
- Mode: autonomous
- 1 a: a backslash doubled, as CHK-14.
- Base commit: 57c0d889cc605d29adbf20549cccd0110e199d9c

## Summary of deliverable 1
- done: a backslash of a value is written `\\\\` in the draft (read `\\`), so the text `\u{202e}` reads apart from a
  real U+202E; EWD-16 and its scenario amended, the spec `accepted` again; ADR 0013 says so.
- red: EWD-16: the draft held `a\\u\{202e\}b\\u\{202e\}c`, the text typed and the escape alike.
- Code review: no findings (low).
- not verified: none.
- decisions needed: none.

## Summary of deliverable 2
- done: the doubling of the backslash moved into `escape::escape_char`, shared by the reports and the draft; the
  binary test of EWD-16 also sends a backslash before `*`.
- red: none (a refactor under the green tests, a stronger assertion).
- Code review: no findings (low). Of the 4 findings of the `high` review, 3 fixed here; the one that a copied
  backslash reads `\\` in the form is the decision 1 a, as in the reports: not changed.
- not verified: none.
- decisions needed: none.
