---
priority: low
depends_on: [escape_formatting_characters_in_the_reports]
why: 'hardening against a crafted SBOM or feed beyond the Trojan Source characters already escaped; no milestone needs it'
---
# Widen the escaping of the writers to every invisible character and make it reversible

# Goal
The module `escape` of the CLI crate escapes the control characters and the bidirectional and invisible formatting
characters of EWD-16 in the human reports, the error lines and the early warning draft. Other invisible characters
still pass raw, a literal escape cannot be told from a real one in the reports, and the joiners some scripts need
are escaped. The writers should escape every character that hides text, in a form a reader can reverse.

# Findings
* Found by the `high` review of `escape_formatting_characters_in_the_reports` (2026-11-14).
* `crates/forewarn/src/escape.rs`, `is_formatting`: misses invisible format characters (category Cf) such as the tag
  characters U+E0000 to U+E007F ("ASCII smuggling"), U+206A to U+206F, U+00AD, U+180E, U+FFF9 to U+FFFB, the
  variation selectors (U+FE00 to U+FE0F, U+E0100 to U+E01EF) and the Hangul fillers U+115F, U+1160, U+3164,
  U+FFA0, which a terminal draws as nothing.
* The human reports do not escape the backslash: a value holding the text `\u{202e}` prints like a value holding a
  real U+202E, and the text `\n` like a newline (already so before the issue above). The draft escapes it as ASCII
  punctuation.
* U+200C and U+200D (zero-width non-joiner and joiner) are escaped, though Persian, Indic scripts and emoji
  sequences need them: a legitimate name in such a script prints with `\u{200c}`.

# Approach
1. Escape by Unicode category (Cf, plus the fillers) rather than a hand-written list; this needs a table of the
   category (a small dependency such as `unicode-properties`, its license checked, or a generated table).
2. Escape the backslash in the reports and the error lines (`\\`), so that each escape reads back to one value.
3. Decide whether the joiners U+200C and U+200D stay escaped (safer) or pass (readable names in those scripts).

# Specs
* `specs/early-warning-draft.md` (EWD-16), `specs/cli-check.md` (CHK-14), `specs/cli-match.md` (MCH-18, MCH-23):
  amend the set of characters escaped and the escape of the backslash.

# Resources
* `crates/forewarn/src/escape.rs`, `crates/forewarn/src/report.rs`, `crates/forewarn/src/early_warning.rs`.
* `crates/forewarn/tests/formatting_characters.rs`.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
Escape every character that hides or reorders text (Cf, U+2028/U+2029, Default_Ignorable_Code_Point of Unicode 16.0)
in the reports, the error lines and the draft, and the backslash as `\\` in the reports and the error lines. Means: a
range table transcribed from the UCD in `escape.rs`, its Unicode version cited, rather than a dependency
(`unicode-properties` gives the category, not Default_Ignorable, so the fillers and selectors would stay by hand).

## Plan
1. [x] Widen and make reversible: `escape.rs` escapes the Cf ∪ Default_Ignorable set and the backslash (the draft
   keeps its own backslash before the ASCII punctuation); verified by `tests/formatting_characters.rs` and the unit
   tests of `early_warning.rs`; makes true CHK-14, MCH-18, MCH-23, EWD-16 as amended. (autonomous)
2. [x] Fixes of the `high` review: the adapters quote the values of their errors with `"{}"` instead of `{:?}`, so
   that `escaped` alone escapes them (MCH-23); the backslash of a component traced in `match` (MCH-18); verified by
   `tests/formatting_characters.rs`. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 4cf2acaba61db670cffeffc1059ce9d0c74a01e1
- 1 a: a range table of Cf ∪ Default_Ignorable_Code_Point (Unicode 16.0) in `escape.rs`, no dependency.
- 2 a: U+200C and U+200D stay escaped.
- High review 1 a: Display, quoted, in the errors of the adapters; 2 a: the backslash of a Windows path is escaped
  like any other, no exception; 3: follow-up `issues/done/check_the_escape_table_against_the_ucd.md`; 4: fixed.

## Deliverable 1
- done: `escape.rs` escapes Cf ∪ U+2028/U+2029 ∪ Default_Ignorable_Code_Point (Unicode 16.0) and, in the reports and
  the error lines, the backslash as `\\`; the draft keeps its Markdown escape of the backslash.
- red: CHK-14, MCH-18, MCH-23, EWD-16: `left: "  evil 1\u{e0041}0\u{3164}\u{fe0f}\u{ad}: …"` (tag, filler, selector
  and soft hyphen printed raw) and the literal `a\u{202e}` / `EVIL\n-1` / `a\nb.json` printed without `\\`.
- Code review: no findings
- not verified: the table against the UCD files themselves (transcribed, no network check); decisions needed: none.
- Docs: n/a (README and CLAUDE.md do not list the escaped characters; the specs carry them).

## Deliverable 2
- done: the errors of the adapters (cyclonedx, osv, osv api and fetch, kev, cache) quote their value with Display;
  `match` traces a backslash in a component's name.
- red: MCH-23: `unsupported spec version "1.6\\u{202e}"`, the value escaped twice (Debug, then `escaped`).
- Code review: 3 findings, not fixed: each says an adapter error now prints a value of a feed raw (fetch.rs:86,
  api.rs:84/191/215, kev.rs:66/69/73, cyclonedx lib.rs:47, osv lib.rs:46). Decision 1 a of the high review: the writer
  escapes, once; every error line of the CLI goes through `escaped` (main.rs:305, 660, 684), which the MCH-23 tests
  prove. A future consumer of the adapters (the hosted service) escapes what it writes, as the CLI does.
- not verified: none; decisions needed: none.
- Docs: n/a (the specs say "quoting it", still true).
