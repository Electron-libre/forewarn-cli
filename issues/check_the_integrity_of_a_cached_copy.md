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
* Found by the `high` review of `issues/done/recover_a_damaged_cached_copy.md` (2026-11-13), from the code, not from a run.
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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
A download records in `forewarn-freshness` the name and size of each file it stored; a fetch checks them before
reading a cached copy: a difference is damage (downloaded again, or "damaged cached copy" under `offline`), a read
error on a matching copy is reported as it is. Out of scope: hashes, edits that keep a file's size.

## Plan
1. [x] Manifest in `forewarn-cache` and the OSV snapshots: recorded at download, checked before a read, new error
   `damaged cached copy`, an older freshness downloaded again once; verified by the tests of `crates/forewarn-osv/tests/fetching.rs`
   (the OSR-37 ones moved to the new ids); makes true OSR-38, OSR-39, OSR-40, OSR-41 (ADR 0010 draft committed with it). (autonomous)
2. [x] KEV catalog and EUVD list: their fetch errors carry the damage, tests moved off KEV-18/EUV-21; verified by
   `kev_fetching.rs` and `euvd_fetching.rs`; makes true KEV-19 to KEV-22, EUV-22 to EUV-24; specs set `accepted`. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: d621b74840eca667d1a9edf423a19f979b096b60
- Manifest: the name and the size of each file (no hash, no modification time), ADR 0010.
- A freshness without manifest: downloaded again once; read as it is under `offline`.
- A copy that matches its manifest and cannot be read: its error reported, no download.

## Deliverable 1

- done: `forewarn-freshness` records the size of each file of a download; a fetch checks them before reading a cached
  copy (new `Error::Damaged`, "damaged cached copy" under `offline`); a matching copy that fails to read reports its
  error; a freshness without files is downloaded again (read as is offline). The three sources map the new error.
- red: OSR-38, OSR-39, OSR-40, OSR-41: a removed record went unnoticed (1 request, not 2); `fetch_error` got `Ok`;
  the freshness held no `files`.
- KEV-20 and EUV-22: their offline tests moved from "not JSON" to "damaged cached copy"; the rest of KEV and EUVD is
  deliverable 2.
- Code review: no findings
- not verified: the permission test of OSR-40 returns early when run as root.

## Deliverable 2

- done: tests of KEV-19, KEV-21, KEV-22, EUV-23, EUV-24 added, KEV-18/EUV-21 tests re-cited; the three specs `accepted`.
- red: none: the behaviour came with deliverable 1, these tests passed at once.
- Code review: no findings
- not verified: nothing.
