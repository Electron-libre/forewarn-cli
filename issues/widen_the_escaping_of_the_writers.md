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
