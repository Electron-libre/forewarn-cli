---
priority: low
why: 'only a copy damaged outside forewarn (a cleanup, a disk error) is concerned, and `always` or deleting it recovers'
---
# Download again a cached copy whose content is damaged

# Goal
`forewarn-cache` decides whether an entry is cached from its freshness file only. An entry whose freshness file is
valid but whose content is missing or corrupt is taken as fresh: every run under `if-missing` or a fresh
`older-than` reads it, fails, and never downloads it again. Such a run should download the entry again, as a
damaged freshness file already makes it do (OSR-13), or say how to recover.

# Findings
* Found by the `high` review of `read_cisa_kev_catalog` (2026-11-13), from the code, not from a run: deleting or
  truncating `cisa-kev/known_exploited_vulnerabilities.json` while `cisa-kev/forewarn-freshness` stays makes every
  `if-missing` fetch fail with "cannot use the cache" or "not JSON".
* The same holds for an OSV ecosystem whose record file is corrupt: the fetch fails naming the entry (OSR-18).
* The copy is written by renaming a fully read staging directory (ADR 0004), so forewarn itself does not leave a
  damaged copy; only an outside change does.

# Approach
1. Decide whether a read failure of a cached copy is a cache miss (download again, under the exclusive lock) or an
   error whose message names the way out (`--refresh always`, the directory to delete).
2. A cache miss: the cache retries once under the exclusive lock when the source's read of a cached copy fails, and
   never under `offline`, which keeps failing.
3. Amend `specs/osv-reading.md` (OSR-13) and `specs/kev-reading.md` (KEV-9) with the chosen behaviour.

# Specs
* `specs/osv-reading.md` (OSR-13), `specs/kev-reading.md` (KEV-9): a scenario for a damaged copy.

# Resources
* `crates/forewarn-cache/src/lib.rs`: `Cache::fetch`, `cached`.
* ADRs 0004, 0007 and 0008.

# Hints
* A retry must not loop: one download at most per fetch.
* Under the shared lock another run may be reading the copy: replacing it needs the exclusive lock (ADR 0007).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
A cached copy whose freshness is valid but whose content the source cannot read is a cache miss: the fetch takes the
exclusive lock, reads the copy again (another run may have replaced it meanwhile), and downloads it once if it still
fails; `offline` keeps failing with the read error. Out of scope: detecting a damage before a read (checksums).

## Plan
1. [x] Retry a failed read of a cached copy in `Cache::fetch`: a read failure under the shared lock switches to the
   exclusive lock, which reads once more then downloads, one download at most; verified by tests in the OSV, KEV and
   EUVD fetching suites (truncated or removed copy under `if-missing` downloads once, `offline` fails with no request,
   a 503 after a damaged copy fails after one request); makes true OSR-37, KEV-18, EUV-21. (autonomous)
2. [x] Fixes of the `high` review: skip the second read when the damaged copy is unchanged (same freshness), OSR-37
   and README no longer promise a removed OSV record file is detected (a non-goal), EUV-21 traced under `offline`;
   verified by the fetching suites; makes true OSR-37, EUV-21. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 5362145096989d41f59fc90a737cabaa8695590a
- Answer 1 a: a copy that cannot be read is a cache miss, downloaded again.

## Summary of deliverable 1
- done: `Cache::fetch` takes a copy the source fails to read as a miss: exclusive lock, one more read, then one
  download; `offline` returns the read error. OSR-37, KEV-18, EUV-21 added and traced, specs back to `accepted`; README.
- red: OSR-37, KEV-18, EUV-21: "the archive is fetched again: FetchError { ecosystem: \"crates.io\", cause: Record(ReadError { path: \"RUSTSEC-2020-0071.json\", cause: NotJson(..) }) }"; "the catalog is fetched: Cache(\"No such file or directory (os error 2)\")"; "the list is fetched: List(ReadError { path: \"exploited.json\", cause: NotJson(..) })"

- Code review: no findings
- checks: project-check green (fmt, clippy, tests, specs); deliverable-size 199 lines.
- not verified: none. decisions needed: none.

## High review (5362145..e5473d4): 8 findings
1. Any read error is taken as damage (a record a newer forewarn refuses downloads again each run): kept, the run fails
   either way; told apart by `issues/check_the_integrity_of_a_cached_copy.md`.
2. A removed OSV record file is not detected, as OSR-37 and the README said: fixed in the wording, non-goal pointing
   to the new issue.
3. The read error is dropped when the download that follows fails: kept, the download error is the one to act on and
   the scenario of OSR-37 states it.
4. The damaged copy is read twice: fixed, the exclusive lock reads it again only when its freshness changed.
5. A permission error is taken as damage: kept, as 1; the new issue tells it apart.
6. A manifest would check the integrity rather than infer it: `issues/check_the_integrity_of_a_cached_copy.md`.
7. No test of a copy replaced by another run while this one waited: not fixed, it needs two runs racing on the lock;
   the branch is the read of OSR-19's waiting run.
8. EUV-21 untested under `offline`: fixed, a test added.

## Summary of deliverable 2
- done: the fixes of findings 2, 4, 8 above; follow-up issue `check_the_integrity_of_a_cached_copy`.
- red: EUV-21: none, the `offline` test passed at once (the branch is shared with KEV-18).
- Code review: no findings
- checks: project-check green. not verified: finding 7 (a copy replaced while waiting). decisions needed: none.

