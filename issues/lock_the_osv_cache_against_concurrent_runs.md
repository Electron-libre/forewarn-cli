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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Two fetches of one ecosystem into a shared cache run one after the other, through an advisory lock per ecosystem
(`std::fs::File::try_lock`, Rust 1.89, no crate), polled up to a bound (40 min by default) then "cache locked"; the
system releases the lock of a killed run. Out of scope: caches shared over a network file system, a notice while waiting.

## Plan
1. [x] Lock each ecosystem of the cache: `.lock-<ecosystem>` taken for the whole fetch of the ecosystem, a `lock_wait`
   bound on `Archives`, `FetchCause::Locked`, `rust-version` 1.89, ADR 0005, ADR 0004 and CLAUDE.md updated; verified
   by tests in `crates/forewarn-osv/tests/fetching.rs` (a lock held by the test, a second thread waiting on it); makes
   true OSR-19 to OSR-23. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: bcc6cbfa67e373c8aa3e0053253142de9277ab95
- Wait: block up to a bound (40 min by default, set by the caller), then fail (answer 1 a).
- Lock: `std::fs::File::try_lock`, `rust-version` 1.89 (answer 2 a).
- `offline` on a cache it cannot write in: read without the lock (answer 3 a).

## Deliverable 1

done: a fetch takes `.lock-<ecosystem>` (std `File::try_lock`, polled every 200 ms) for the whole fetch of the
ecosystem, gives up after `Archives::lock_wait` (40 min by default) with "cache locked by another run"; `offline`
reads without the lock a cache it cannot write in; `rust-version` 1.89; spec `accepted`, ADR 0005 accepted.

| check | result |
|---|---|
| tests | pass (`cardinal run project-check`) |
| lint | pass |
| specs | pass, OSR-19 to OSR-23 traced |
| docs | CLAUDE.md, README.md, ADR 0004, ADR 0005 |
| code review | low, clean |

red: OSR-H5, OSR-19, OSR-22, OSR-23: the second run failed with "cannot use the cache: No such file or directory"
(both runs downloaded into the same scratch paths); the bounded wait returned a snapshot instead of failing; no lock
file was created. OSR-20 and OSR-21 passed before the lock (they guard against a lock that blocks too much).
Code review: no findings

not verified: Windows (`LockFileEx`), a cache on a network file system (non-goal).
decisions needed: none.
