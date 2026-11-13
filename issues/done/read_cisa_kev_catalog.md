---
priority: high
depends_on: [flag_exploited_vulnerabilities]
why: 'KEV is the reference list of actively exploited vulnerabilities: without it the milestone flags nothing'
---
# Read the CISA KEV catalog, local or fetched into a cache

# Goal
The domain flags the matches an exploited list names (`flag_exploited_vulnerabilities`); the list must come from
somewhere. CISA publishes its Known Exploited Vulnerabilities catalog as one public JSON file. An adapter should read
that file from a local path, or download it into a cache under a refresh policy, recording when it was downloaded, and
give the domain its entries (CVE id, date added) and the catalog's version and release date as its freshness.

# Approach
1. Measure first: download the current catalog once, note its size, its top-level members (expected: `catalogVersion`,
   `dateReleased`, `count`, `vulnerabilities`) and the members of an entry (expected: `cveID`, `dateAdded`,
   `vendorProject`, `product`, `knownRansomwareCampaignUse`…), and the HTTP headers the server sends
   (`Last-Modified`, `ETag`).
2. Where the adapter lives, recorded in an ADR: a crate per list (`forewarn-kev`), or one crate for the exploited lists
   (KEV and EUVD) with a module each.
3. The cache: reuse the refresh policy (`offline`, `if-missing`, `always`, an age) and the per-entry file lock of the
   OSV cache (ADRs 0004, 0005, 0007), either by moving that code into a crate both adapters use, or by duplicating the
   little they need; to settle in the ADR.
4. Errors: an unreadable file, a malformed catalog, an entry without a valid CVE id or date, a failed download, each
   with its own error, as the OSV adapter does (OSR-9, OSR-18).
5. Tests against fixture files and a loopback HTTP server: no network.

# Specs
* A new spec of the KEV reading (e.g. `specs/kev-reading.md`), written at step 1.

# Milestone
Flag actively exploited vulnerabilities (KEV, EUVD)

# Resources
* ADRs 0003 to 0005 and 0007: the OSV adapter's own serde model, its cache, its lock.
* `crates/forewarn-osv/src/fetch.rs`: the archive fetch, its refresh policy, its `ureq` agent, its lock.
* `specs/osv-reading.md`: OSR-10 to OSR-18, the shape of a cache spec to follow.
* CISA KEV catalog: the JSON feed linked from the catalog page of cisa.gov.

# Hints
* Only the request for a public file leaves the CI: no inventory is sent, unlike the OSV API (ADR 0006).
* The catalog is a single file of a few megabytes: no archive, no per-ecosystem split.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Read the CISA KEV catalog (local file, or fetched into a cache under the OSV refresh policy and lock) into the domain's
`ExploitedList` named `CISA KEV`, with its version and release date. Out of scope: CLI wiring
(`cli_flag_exploited_matches`), EUVD. Measured 2026-11-13: 1.85 MB, 1,779 entries, 12 members each, `Last-Modified`
and `ETag` sent; every `cveID` and `dateAdded` valid.

## Plan
1. [x] Read a local KEV catalog: new crate `forewarn-exploited`, module `kev`, its serde model and errors (spec and
   ADR 0008 drafts committed with it); verified by fixture tests; makes true KEV-1, KEV-2, KEV-16, KEV-17. ~450 lines. (autonomous)
2. [x] Move the cache machinery of `forewarn-osv/src/fetch.rs` (refresh policy, freshness, shared/exclusive lock,
   scratch paths, replacement) into a new crate `forewarn-cache`; OSV keeps its API and errors; verified by the OSV
   fetch tests unchanged and green (pure refactor, no new requirement). ~700 lines. (autonomous)
3. [x] Fetch the KEV catalog into a cache through `forewarn-cache`; verified by loopback-server and lock tests; makes
   true KEV-3 to KEV-15, spec `accepted`. ~600 lines. (autonomous)
4. [x] Fixes of the `high` review of the whole issue; verified by the checks and a `low` review. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 570bbdfd1cc2ba8f93fda6cd532ec4c66988a728
- Adapter in one crate `forewarn-exploited`, a module per list (1 a).
- Cache machinery extracted into a crate `forewarn-cache` shared with OSV (2 a).
- Default lock wait of 40 minutes, as OSV (3 a).

## Deliverable 1: read a local KEV catalog
done: crate `forewarn-exploited`, `kev::read_file` reads a catalog file into the list `CISA KEV`, its version and
release date; spec `kev-reading` (draft) and ADR 0008.

| check | result |
|---|---|
| tests | 15 new, all green |
| lint | clean |
| specs | `check-specs` clean |
| docs | `CLAUDE.md` status and layout |
| code review | see below |

red: KEV-H1, KEV-1, KEV-2, KEV-16, KEV-17: `not yet implemented` (the stub `read_file` panicked in every test).

Code review: no findings

not verified: none. decisions needed: none.

## Deliverable 2: move the cache machinery into `forewarn-cache`
done: new crate `forewarn-cache` (refresh policy, freshness, shared/exclusive lock per entry, scratch paths,
replacement, download agent), its source-specific part handed in as an unpack and a read function; `forewarn-osv`
re-exports `Refresh`, `Freshness` and `DEFAULT_LOCK_WAIT` and keeps its API, errors and cache layout.

| check | result |
|---|---|
| tests | OSV fetch, API and CLI tests unchanged, all green |
| lint | clean |
| specs | clean, no requirement changed |
| docs | `CLAUDE.md` layout |
| code review | see below |

red: none (refactor under the existing tests).

Code review: no findings

not verified: none. decisions needed: none.

## Deliverable 3: fetch the KEV catalog into a cache
done: `kev::Feed` downloads the catalog (`KEV_CATALOG` by default) into the entry `cisa-kev` of a cache through
`forewarn-cache`, returns it with the freshness of the download, and its errors (`FetchError`); spec `kev-reading`
accepted.

| check | result |
|---|---|
| tests | 18 new loopback-server and lock tests, all green |
| lint | clean |
| specs | `check-specs` clean, every KEV requirement traced |
| docs | `CLAUDE.md` status and layout |
| code review | see below |

red: KEV-H2, KEV-H3, KEV-3, KEV-4, KEV-5, KEV-6, KEV-7, KEV-8, KEV-9, KEV-10, KEV-11, KEV-12, KEV-13, KEV-14, KEV-15:
`not yet implemented` (the stub `Feed::new` and `Feed::fetch` panicked; 17 of 18 failed, the lock holder helper passed).

Code review: no findings

not verified: the real CISA URL is not requested by the tests (measured once by hand at planning). decisions needed: none.

## Deliverable 4: fixes of the `high` review
done: `Cache::fetch` refuses an entry name that could escape the cache or reach a scratch path (new test
`forewarn-cache/tests/entry_name.rs`); `forewarn_cache::Error` gives its source's error as `source()`; the KEV-5 test
proves the second run started while the first was downloading. Issue `recover_a_damaged_cached_copy` filed.

| check | result |
|---|---|
| tests | all green, 1 new |
| lint | clean |
| specs | clean |
| docs | n/a: no documented behaviour changed |
| code review | see below |

red: none (review fixes; the entry-name test passes only with the new check).

High review of `570bbdf..HEAD`: 8 findings.
1. Unchecked entry name in `forewarn-cache`: fixed.
2. A damaged cached copy is never downloaded again: outside the requirements, filed as
   `issues/recover_a_damaged_cached_copy.md`.
3. Cache messages repeated in each adapter's error: not fixed; each adapter keeps a flat public error, as OSV's
   `FetchCause` (OSR-18), and its messages are tested per spec.
4. `Feed` and `Archives` copy the fields of `Cache`: not fixed; `Archives` keeps its public API (ADR 0008), `Feed`
   follows it for one shape across adapters.
5. A CVE id checked twice in `kev::parse`: not fixed; the domain's constructor is the only way to date an entry, and a
   setter in the domain for this is not worth it.
6. No tests of `forewarn-cache` of its own: not fixed; the adapters' tests prove the spec requirements through it, the
   cache has no spec of its own.
7. The KEV-5 test did not prove the wait: fixed.
8. `source()` missing on `forewarn_cache::Error`: fixed.

Code review: no findings

not verified: none. decisions needed: none.
