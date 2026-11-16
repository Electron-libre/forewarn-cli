---
priority: low
depends_on: [revise_the_set_of_the_characters_that_hide_text]
why: 'closes a residual gap of an escaping that already covers every Unicode property of hidden text; no milestone needs it'
---
# Escape the other characters a viewer draws as blank in EWD-16

# Goal
EWD-16 escapes the Default_Ignorable_Code_Point and White_Space characters (but U+0020) and U+2800. Some characters
outside these properties are also drawn as a blank, so a component name holding one reads as another name. Decide
which of them EWD-16 escapes, by a rule a reader can check, not one by one.

# Findings
* Found by the `high` review of `revise_the_set_of_the_characters_that_hide_text` (2026-11-16), not verified on a
  viewer.
* U+1D159 MUSICAL SYMBOL NULL NOTEHEAD and U+16FE4 KHITAN SMALL SCRIPT FILLER are named by lists of "invisible
  characters" and are neither Default_Ignorable_Code_Point nor White_Space in Unicode 16.0.
* A component named `log4j` U+1D159 `-core` would read as `log4j-core`.

# Approach
1. Measure first: gather the published lists of characters drawn as blank and render each in a terminal and a
   Markdown viewer.
2. Then either add the characters drawn as blank by a listed rule (with the source vendored next to the UCD extracts),
   or state in EWD-16 why they stay out.

# Specs
* `specs/early-warning-draft.md`: amends EWD-16 (the set); CHK-14, MCH-18, MCH-23 cite the same module.

# Resources
* `crates/forewarn/src/escape.rs` (`hides_text` and its test against the extracts).
* `crates/forewarn/data/ucd-16.0.0`.
* `issues/done/revise_the_set_of_the_characters_that_hide_text.md`.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
Measured on the installed fonts (fontTools, glyph outlines of every font under `/usr/share/fonts`, Noto included): outside
the set of EWD-16, only U+13441 and U+13442 EGYPTIAN HIEROGLYPH FULL/HALF BLANK are drawn with no ink (the other hits are
shaping artefacts: Duployan letters drawn by GSUB, two viramas, a Nerd Font gap). U+1D159 and U+16FE4 are drawn with
ink (Noto Music, Noto Serif Khitan Small Script); the flopp/invisible-characters list adds nothing else (its other
entries are already escaped, or misnamed: U+1D000…). Rule: the characters whose Unicode name ends in `BLANK`
(U+2800, U+13441, U+13442), which replaces the special case of U+2800.

## Plan
1. [x] Escape the characters named `… BLANK`: vendor the lines of `UnicodeData.txt` 16.0 whose name ends in ` BLANK`
   into `crates/forewarn/data/ucd-16.0.0` (a header line naming the file and the filter, the three lines verbatim),
   read them in the exhaustive test of `hides_text` instead of inserting U+2800 by hand, add U+13441..U+13442 to the
   table and the samples, U+1D159 and U+16FE4 to those that pass, a draft test of the two new EWD-16 scenarios;
   verified by `cargo test`; makes true EWD-16 (spec back to `accepted`). ~80 lines. (autonomous)
2. [x] Fixes of the `high` review of the issue: U+13441 and U+1D159 driven through `forewarn check`, the extract ends
   on its `# Total code points`, checked; the follow-up issue `prove_the_written_draft_through_the_binary`; verified
   by `cargo test`; traces EWD-16, CHK-14. (autonomous)

## Decisions
- Mode: autonomous
- 1 a: the three lines of `UnicodeData.txt` 16.0 whose name ends in ` BLANK`, verbatim, under a header line naming
  the file and the filter.
- Base commit: a3dce1a1f58b3649624d0b6ed2ba3c1ed8ef587d

## Deliverable 1
- done: `hides_text` escapes U+13441 and U+13442 too; the exhaustive test reads the characters named `… BLANK` from
  the new extract `UnicodeData-names-ending-in-BLANK.txt` instead of inserting U+2800; U+1D159 and U+16FE4 among the
  samples that pass; two draft tests for the new EWD-16 scenarios; EWD-16 amended, spec `accepted` again.
- red: EWD-16: `hides_text disagrees with Unicode 16.0 on ["U+13441", "U+13442"]`, `left: "𓑁" right: "\\u{13441}"`.
- Code review: no findings.
- not verified: the drawing in a terminal and a Markdown viewer (measured on the glyph outlines of the installed
  fonts). decisions needed: none.

## Deliverable 2
- done: `check_escapes_the_blank_characters_and_lets_the_visible_format_ones_read` drives U+13441 (escaped) and
  U+1D159 (read as written) through `forewarn check`; `named_blank` checks the `# Total code points: 3` the extract
  now ends on; follow-up issue written.
- red: none (the boundary test passed at once: it covers code delivered in deliverable 1).
- `high` review of the issue, 6 findings: 1 to the follow-up issue (the stale internal reason predates this issue);
  2 fixed (the `check` test); 3 kept (U+13440, U+13447..U+13455 are drawn marks, they hide no text); 4 fixed (the
  total); 5 kept (decision 1 a, the rule validated); 6 kept (two extract formats, two headers; one line each).
- Code review: no findings.
- not verified: the drawing in a terminal and a Markdown viewer. decisions needed: none.
