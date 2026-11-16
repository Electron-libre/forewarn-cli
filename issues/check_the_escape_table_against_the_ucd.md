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
* `issues/widen_the_escaping_of_the_writers.md` (decision 1 a: a table, no dependency).
