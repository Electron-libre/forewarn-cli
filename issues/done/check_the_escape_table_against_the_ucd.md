---
priority: low
depends_on: [widen_the_escaping_of_the_writers]
why: 'guards a hand-transcribed table that already covers every known case; no milestone needs it'
---
# Check the table of the characters that hide text against the Unicode Character Database

# Goal
`hides_text` in the module `escape` of the CLI crate is a range table transcribed by hand from Unicode 16.0 (general
category Cf, U+2028, U+2029, Default_Ignorable_Code_Point). Its test checks samples only: a wrong bound, a forgotten
range or a new Unicode version would pass. The table should be checked against the UCD files of its version.

# Findings
* Found by the `high` review of `widen_the_escaping_of_the_writers` (2026-11-16).
* `crates/forewarn/src/escape.rs`, `hides_text`: about 25 ranges; its unit test checks 24 characters of about 4,000.

# Approach
1. Vendor `DerivedGeneralCategory.txt` and `DerivedCoreProperties.txt` of Unicode 16.0 (license: Unicode License v3,
   check it fits the repository) and add a test comparing every code point with `hides_text`.
2. Or generate the table from those files with a small generator kept in the repository, and test that the generated
   source is up to date.

# Specs
* `specs/early-warning-draft.md` (EWD-16): no change of the set; the test traces it.

# Resources
* `crates/forewarn/src/escape.rs`.
* `issues/done/widen_the_escaping_of_the_writers.md` (decision 1 a: a table, no dependency).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
Check `hides_text` against every code point (U+0000 to U+10FFFF) of the Unicode 16.0 data it was transcribed from, not
24 samples. Out of scope: changing the set of EWD-16 or generating the table. Means: vendor verbatim extracts, not the
whole files (17,685 lines, over the deliverable limit, almost all of it unrelated).

## Plan
1. [x] Vendor the UCD extracts and test the table against them: `crates/forewarn/data/ucd-16.0.0/` holds the header and
   the `General_Category=Format` section of `DerivedGeneralCategory.txt`, the header and the
   `Default_Ignorable_Code_Point` section of `DerivedCoreProperties.txt`, copied verbatim, with the Unicode License v3;
   the unit test of `escape` parses them, checks each section's `# Total code points` against its ranges (a dropped
   line fails) and its header's version `16.0.0`, then compares `hides_text` with the set plus U+2028 and U+2029 for
   every scalar value; the sample test keeps the letters around; verified by `cargo test` (and by breaking a bound
   by hand, which must fail); traces EWD-16. (autonomous)
2. [x] Fixes of the `high` review of the issue: the test checks the section of each extract; the doc comment of
   `hides_text` no longer says every character it escapes is drawn as nothing; verified by `cargo test` (and by naming
   another section, which fails); traces EWD-16. (autonomous)

## Decisions
- Mode: autonomous
- 1 a: verbatim extracts of the two UCD files, the total of each section checked.
- 2 a: the Unicode License v3 fits (permissive, no copyleft; test data only), kept next to the extracts.
- Base commit: 0f738f49c5d7e8b245737d6d6e22be3887566c6b

## Deliverable 1
- done: `hides_text` is compared with the Unicode 16.0 extracts (Cf, Default_Ignorable_Code_Point, plus U+2028 and
  U+2029) for every scalar value; each extract's total and version are checked.
- red: EWD-16: with the bound U+1D17A lowered to U+1D179, `hides_text disagrees with Unicode 16.0 on ["U+1D17A"]`
  (the table already agreed with the data: no bound was wrong).
- Code review: no findings.
- not verified: none. decisions needed: none.

## Deliverable 2
- done: `code_points_of` asserts the extract holds the one expected section; the doc comment of `hides_text` names the
  visible format characters (U+0600, U+06DD) that EWD-16 escapes with the rest of Cf.
- red: EWD-16: with the heading `# General_Category=Control` expected, `the extract holds another section`.
- `high` review of the issue, 5 findings:
  1. Cf holds visible characters (Prepended_Concatenation_Mark, U+FFF9..FFFB, U+13430..1343F): doc comment fixed; the
     set itself is EWD-16's, a change of the spec for the user to decide.
  2. Generate the table from the extracts: not done, option 1 c rejected at validation.
  3. The vendored LICENSE reads 1991-2026: not changed, the 16.0.0 release ships no license file of its own; the
     current notice of unicode.org covers 2024 and the extracts keep their own `© 2024` header verbatim.
  4. The section of an extract is not checked: fixed.
  5. Other blank characters (U+2800, U+3000, U+2000..U+200A) pass unescaped: outside the set of EWD-16, for the user to
     decide.
- not verified: none. decisions needed: findings 1 and 5 (whether to open an issue amending EWD-16).
- Code review (low): no findings.
