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
* `issues/done/check_the_escape_table_against_the_ucd.md`, `issues/done/widen_the_escaping_of_the_writers.md`.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
`hides_text` becomes Default_Ignorable_Code_Point, U+2028 and U+2029, the White_Space characters other than U+0020,
and U+2800: the visible format characters (Prepended_Concatenation_Mark, U+FFF9..U+FFFB, U+13430..U+1343F) pass, the
blank ones are escaped. Out of scope: the leading-space rule, the control characters (already escaped).

## Plan
1. [ ] Revise the set: vendor the `White_Space` section of `PropList.txt` into `crates/forewarn/data/ucd-16.0.0`
   (verbatim, its total checked), drop the `General_Category=Format` extract the test no longer reads, rewrite the
   table of `hides_text` and its exhaustive test (Default_Ignorable_Code_Point + White_Space − U+0020 + U+2028,
   U+2029, U+2800, the control characters left to `is_control`), move U+0600 and U+FFF9 to the samples that pass and
   add U+3000, U+2800, U+00A0 to those escaped, plus a draft test of the two new EWD-16 scenarios; verified by
   `cargo test`; makes true EWD-16 (spec back to `accepted`). ~150 lines.
2. [x] Fixes of the `high` review of the issue: U+FFF9..U+FFFB and U+13430..U+1343F stay escaped (EWD-16, table,
   test), U+2028 and U+2029 named among White_Space, a `check` test of the new set through the binary, the
   follow-up issue `escape_the_other_characters_drawn_as_blank`; verified by `cargo test`; traces EWD-16, CHK-14. (autonomous)

## Decisions
- Mode: autonomous
- 1 a: every White_Space character but U+0020, the UCD section verbatim (U+00A0 and U+1680 escaped).
- A a (high review): the interlinear annotation characters and the Egyptian hieroglyph format controls stay escaped;
  only the Prepended_Concatenation_Mark characters pass.
- B a (high review): the other characters drawn as blank go to `escape_the_other_characters_drawn_as_blank`.
- Base commit: 10fb431c7c9171f2c3545ad5cb8c9bbac114d3e9

## Deliverable 1
- done: `hides_text` is Default_Ignorable_Code_Point, U+2028, U+2029, White_Space but U+0020, and U+2800; the
  `White_Space` extract of `PropList.txt` replaces the `General_Category=Format` one; the extract parser checks the
  property of each line; two draft tests for the new EWD-16 scenarios; EWD-16 amended, spec `accepted` again.
- red: EWD-16: `hides_text disagrees with Unicode 16.0 on ["U+00A0", "U+0600", …, "U+2800", "U+3000", "U+FFF9", …]`
  and `left: "\u{a0}" right: "\\u{a0}"`.

## Deliverable 2
- done: U+FFF9..U+FFFB and U+13430..U+1343F escaped again; U+2028 and U+2029 counted with White_Space in the test, the
  doc comment and EWD-16; `check_escapes_the_blank_characters_and_lets_the_visible_format_ones_read` drives the set
  through `forewarn check`; follow-up issue written.
- red: EWD-16: `hides_text disagrees with Unicode 16.0 on ["U+FFF9", …, "U+1343F"]`, `left: "\u{fff9}" right:
  "\\u{fff9}"`.
- `high` review of the issue, 7 findings: 1, 2 fixed (A a); 3 to the follow-up issue (B a); 4 kept (decision 1 a: the
  no-break spaces are escaped); 5 fixed (the `check` test); 6 fixed (U+2028, U+2029 within White_Space); 7 kept (the
  test names the carve-outs EWD-16 sets, from the spec, not from the code).
- Code review: no findings.
- not verified: how a viewer draws U+1D159 and U+16FE4 (left to the follow-up issue). decisions needed: none.
- Done: both deliverables committed; nothing left in this issue.
