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
