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
