---
priority: low
why: 'the escaping is proven by internal tests of the writer; only the wiring of `--drafts` to it is unproven'
---
# Prove the escaping of the written draft through `forewarn match --drafts`

# Goal
The tests of the written draft live in `crates/forewarn/src/early_warning.rs` and give as their reason `internal: no
command writes a draft before cli_draft_early_warnings`, which is false since `forewarn match --drafts` writes drafts.
No test through the binary drives a character that hides text into a written draft, so a change of the module
`drafts` that bypassed the escaping would pass. Prove EWD-16 at the boundary, and give the internal tests a reason
that is true.

# Findings
* Found by the `high` review of `escape_the_other_characters_drawn_as_blank` (2026-11-16).
* 12 tests of `early_warning.rs` carry the stale reason; `crates/forewarn/tests/drafts.rs` writes drafts through the
  binary but checks no escaped value.

# Approach
1. Add to `tests/drafts.rs` a test whose SBOM names a component with U+202E, U+13441 and a Markdown punctuation
   character, and read the written file.
2. Reword the reason of the internal tests that stay (e.g. the samples a fixture would not walk through), or move
   those the binary proves cheaply.

# Specs
* `specs/early-warning-draft.md`: EWD-16 (traced again through the binary), no requirement changed.

# Resources
* `crates/forewarn/src/early_warning.rs` (its tests), `crates/forewarn/tests/drafts.rs`.
* `specs/README.md` (placement of `// spec:` and the internal reason).
