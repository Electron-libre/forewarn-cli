---
priority: low
why: 'only a copy changed outside forewarn is concerned; a removed OSV record file is the one case that goes unnoticed'
---
# Check the integrity of a cached copy before reading it

# Goal
`forewarn-cache` takes a cached copy as damaged when the source's read of it fails (OSR-37, KEV-18, EUV-21). That
heuristic misses a record file removed from an OSV snapshot (the snapshot reads the files left, so `forewarn match`
silently misses its vulnerabilities), and takes for damage what is not: a record a newer forewarn refuses (every run
then downloads the archive again and still fails) or an I/O error such as a permission refused or too many open
files. Recording what a download stored and checking it before a read would tell a damaged copy apart.

# Findings
* Found by the `high` review of `issues/recover_a_damaged_cached_copy.md` (2026-11-13), from the code, not from a run.
* `read_directory` lists the `.json` files that exist: deleting `crates.io/RUSTSEC-2020-0071.json` from a cache, its
  `forewarn-freshness` intact, makes an `if-missing` fetch return the other records with no request (non-goal of
  `specs/osv-reading.md`).
* `Cache::fetch` takes any `Err` of `source.read` on a cached copy as damage, whatever its cause.

# Approach
1. Record in `forewarn-freshness`, at download, a manifest of the entry: each file name with its size, or its hash.
2. Check the manifest before reading a cached copy: a file missing, added or of another size (or hash) is damage,
   downloaded again as OSR-37 says; a read error on a copy that matches its manifest is reported as it is.
3. Decide how a freshness file without a manifest (written by an older forewarn) is taken: trusted, or downloaded
   again once.

# Specs
* `specs/osv-reading.md` (OSR-37 and the non-goal on removed files), `specs/kev-reading.md` (KEV-18),
  `specs/euvd-reading.md` (EUV-21).

# Resources
* `crates/forewarn-cache/src/lib.rs`: `Cache::fetch`, `Freshness`, `read_freshness`.
* ADRs 0004, 0007 and 0008.

# Hints
* Hashing a large ecosystem (tens of thousands of files) at each read costs; sizes may be enough against truncation
  and removal.
