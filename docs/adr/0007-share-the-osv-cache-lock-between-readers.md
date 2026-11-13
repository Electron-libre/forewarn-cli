# 0007. Share the lock of an OSV ecosystem between fetches that only read

- Status: accepted
- Date: 2026-11-13

## Context

ADR 0005 makes a fetch take the exclusive lock of `.lock-<ecosystem>` before it reads the freshness of the snapshot,
and keep it until it is done with the ecosystem, also when it only reads the snapshot (`offline`, `if-missing` with a
snapshot, a fresh `older-than`). N parallel jobs of one runner reading a large snapshot (npm, PyPI: many record
files) then parse it one after another, and a job at the back of the queue can reach the 40-minute bound although no
run is stuck.

## Decision

A fetch takes the shared lock of the lock file (`File::try_lock_shared`, polled as the exclusive one) to read the
freshness and, when its refresh policy reads the snapshot, the records. When the policy asks for a download, or a
stopped run left the former snapshot aside (`.former-<ecosystem>` to put back), it releases the shared lock, takes the
exclusive one, and reads the freshness again before deciding: another run may have downloaded meanwhile, and the
fetch then releases the exclusive lock and reads that snapshot under the shared one, beside the other readers. A
fetch under `always`, which never reads the snapshot, takes the exclusive lock first. The bound of
the wait covers both locks: one deadline, set when the fetch first asks for the lock.

Releasing then taking, rather than converting the lock in place: `flock` converts a shared lock non-atomically
anyway, and `LockFileEx` cannot convert one. The fallbacks of ADR 0005 stay: a lock file another user created is
locked through a read-only handle, which `flock` and `LockFileEx` (with or without `LOCKFILE_EXCLUSIVE_LOCK`) accept
on a handle open for reading; an `offline` fetch that cannot open the lock file reads without it; a platform without
file locks reads and writes without them.

## Consequences

- Fetches that only read a snapshot read it in parallel; they wait only for a fetch that downloads it.
- A download waits for the fetches reading the snapshot it replaces, so no reader sees it half replaced.
- A download is not served before the reads that start after it: reads that keep overlapping can hold it back until
  its bound is over. Runners mixing `always` with reading policies on one cache are the case; the next run downloads.
- Two fetches that both find the snapshot too old download it once: the second reads the freshness again under the
  exclusive lock, finds it fresh, and parses the records under the shared lock.
