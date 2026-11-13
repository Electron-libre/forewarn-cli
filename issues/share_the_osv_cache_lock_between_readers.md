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
