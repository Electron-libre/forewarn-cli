---
priority: medium
depends_on: [cli_list_affected_components]
why: 'the default cache is shared per user, so two CI jobs on one runner can break each other''s fetch'
---
# Lock the OSV cache against concurrent runs

# Goal
`forewarn match` caches the OSV archives in one directory per user by default (`$XDG_CACHE_HOME/forewarn/osv`, else
`$HOME/.cache/forewarn/osv`). Two runs that refresh the same ecosystem at the same time share the scratch paths of the
download and can delete each other's files. A second run must wait for the first, or fail clearly, and never damage
the snapshot.

# Findings
* `crates/forewarn-osv/src/fetch.rs` names the scratch paths after the ecosystem only (`.download-<ecosystem>`,
  `.staging-<ecosystem>`, `.former-<ecosystem>`), so that a run clears what a stopped one left (ADR 0004).
* Sharing one cache between runs is a non-goal of `specs/osv-reading.md` and ADR 0004. The default cache of
  `specs/cli-match.md` (MCH-12) now makes such sharing common: two CI jobs on one self-hosted runner, or two terminals
  (high review of `cli_list_affected_components`, 2026-11-13).

# Approach
1. A lock file per ecosystem in the cache, held for the whole fetch of that ecosystem. Compare an advisory file lock
   (a crate compatible with `MIT OR Apache-2.0`) with a lock directory created atomically.
2. Choose whether a run blocks while another holds the lock (with a bound) or fails at once with an error of OSR-18.
3. A stale lock left by a killed run must not block the cache for good.

# Specs
* `specs/osv-reading.md` (amended): a requirement on concurrent fetches, which removes the non-goal.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `crates/forewarn-osv/src/fetch.rs`, ADR 0004, `specs/osv-reading.md`, `specs/cli-match.md` (MCH-12).
