---
priority: low
depends_on: [lock_the_osv_cache_against_concurrent_runs]
why: 'a comfort for runners with many parallel jobs; one job at a time is already correct'
---
# Share the OSV cache lock between readers

# Goal
A fetch holds the exclusive lock of `.lock-<ecosystem>` for the whole fetch of the ecosystem, also when it only reads
a snapshot (`offline`, `if-missing` with a snapshot, a fresh `older-than`). Runs that only read should read the same
snapshot in parallel, and wait only for a run that downloads.

# Findings
* `Archives::lock` in `crates/forewarn-osv/src/fetch.rs` takes `File::try_lock` (exclusive) before reading the
  freshness, and the lock is held while `read_records` parses the whole snapshot (high review of
  `lock_the_osv_cache_against_concurrent_runs`, 2026-11-13).
* N parallel jobs reading a large snapshot (npm, PyPI: many record files) then parse one after another, and a job at
  the back of the queue can reach the 40-minute bound of OSR-22 although no run is stuck (ADR 0005, consequences).

# Approach
1. Take `File::try_lock_shared` to read the freshness and the records; when the policy asks for a download, release
   it, take the exclusive lock, and read the freshness again (another run may have downloaded meanwhile).
2. Check what a shared lock does on the read-only fallback of OSR-23 and on Windows (`LockFileEx` without
   `LOCKFILE_EXCLUSIVE_LOCK`).

# Specs
* `specs/osv-reading.md`: a requirement that two fetches reading the same snapshot do not wait for each other,
  beside OSR-19 and OSR-22.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `crates/forewarn-osv/src/fetch.rs`, ADR 0005, `specs/osv-reading.md` (OSR-19, OSR-22, OSR-23).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Fetches that only read a cached snapshot take the shared lock and read in parallel; a fetch that downloads (or puts
back a former snapshot) releases it, takes the exclusive lock and decides again on the freshness read under it. One
wait bound across both locks (OSR-22). Fairness between a waiting download and new readers is out of scope.

## Plan
1. [x] Shared lock for reads: `Archives::lock` takes a mode, `snapshot` reads under the shared lock and upgrades by
   release then exclusive, one deadline; OSR-19 reworded, ADR 0007; verified by tests in
   `crates/forewarn-osv/tests/fetching.rs` (a held shared lock does not block a reader, blocks a download, two stale
   `older-than` runs download once); makes true OSR-32, OSR-33, OSR-19. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 424595d730ce7b3d2753f424a2de4151008161ce
- Writer fairness: accepted as a non-goal (answer 1 a), documented in ADR 0007.

## Deliverable 1 summary
- done: fetches read a snapshot under the shared lock of `.lock-<ecosystem>`; a download (or putting a snapshot back)
  releases it, takes the exclusive lock and reads the freshness again, one wait bound for both; OSR-19 reworded,
  OSR-32 and OSR-33 added, ADR 0007, CLAUDE.md and README.md updated.
- checks: tests pass, clippy pedantic clean, `check-specs` clean, docs updated.
- red: OSR-32: `a reader does not wait for a reader: FetchError { ecosystem: "crates.io", cause: Locked { waited: 0ns } }`
  (OSR-33 and the re-check test passed before the change, the exclusive lock already serialised them; the re-check
  test fails with 3 downloads instead of 2 when the second freshness read is removed).
- Code review: no findings
- not verified: Windows (`LockFileEx` shared), reasoned in ADR 0007 only.
