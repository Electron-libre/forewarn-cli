---
priority: low
depends_on: [check_the_escape_table_against_the_ucd]
why: 'refines an escaping that already blocks every known forging trick; no milestone needs it'
---
# Revise the set of the characters that hide text in EWD-16

# Goal
EWD-16 escapes every character of the general category Cf, U+2028, U+2029 and every Default_Ignorable_Code_Point of
Unicode 16.0. That set escapes some characters a viewer draws, and lets through others a viewer draws as blank. The
set should match what hides text, so that legitimate names read as written and blank padding cannot pass unnoticed.

# Findings
* Found by the `high` review of `check_the_escape_table_against_the_ucd` (2026-11-16).
* Visible characters escaped: Cf holds the Prepended_Concatenation_Mark characters (U+0600..U+0605, U+06DD, U+070F,
  U+0890..U+0891, U+08E2, U+110BD, U+110CD), and U+FFF9..U+FFFB and U+13430..U+1343F; the derivation of
  Default_Ignorable_Code_Point subtracts them as "format characters that should be visible". A component name in Arabic,
  Syriac or Kaithi that holds one is written with `\u{600}`, `\u{6dd}`…
* Blank characters not escaped: U+2800 BRAILLE PATTERN BLANK, U+3000 IDEOGRAPHIC SPACE, U+2000..U+200A. Only a leading
  space is written `&#32;`.

# Approach
1. Drop the visible Cf characters from the set (keep Cf minus Prepended_Concatenation_Mark, U+FFF9..U+FFFB and
   U+13430..U+1343F, or keep Default_Ignorable_Code_Point only, plus U+2028 and U+2029 and the bidi controls).
2. Add the White_Space characters other than the ASCII space, and U+2800, escaped as their Unicode escape.
3. Either way, vendor the matching sections (e.g. `PropList.txt`: `White_Space`, `Prepended_Concatenation_Mark`) into
   `crates/forewarn/data/ucd-16.0.0` and extend the exhaustive test of `escape`.

# Specs
* `specs/early-warning-draft.md`: amends EWD-16 (the set); the reports share it (CHK-14, MCH-18, MCH-23 cite the same
  module).

# Resources
* `crates/forewarn/src/escape.rs` (`hides_text` and its test against the extracts).
* `crates/forewarn/data/ucd-16.0.0`.
* `issues/check_the_escape_table_against_the_ucd.md`, `issues/done/widen_the_escaping_of_the_writers.md`.
