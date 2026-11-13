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
3. [ ] Fetch the KEV catalog into a cache through `forewarn-cache`; verified by loopback-server and lock tests; makes
   true KEV-3 to KEV-15, spec `accepted`. ~600 lines.

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
