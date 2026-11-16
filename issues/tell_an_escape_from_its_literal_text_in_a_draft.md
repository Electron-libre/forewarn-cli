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
