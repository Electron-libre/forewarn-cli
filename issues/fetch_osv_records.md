---
priority: high
depends_on: [read_osv_records]
why: 'a vendor cannot be asked to download OSV records by hand; the milestone needs them fetched'
---
# Fetch the OSV records relevant to an SBOM

# Goal
`forewarn` must obtain the OSV records that may affect the components of an SBOM without the user downloading them,
in a way that keeps the matching deterministic and lets a run be reproduced.

# Approach
Settle the source at step 1; candidates (can be combined):
1. The OSV API (`querybatch` by package URL, then the full record of each id): little data, but the result depends
   on the network and the moment of the query.
2. The archive of each ecosystem the SBOM uses (`<ecosystem>/all.zip`), downloaded into a cache directory and read by
   `read_osv_records`: works offline once cached, and the cached snapshot makes a run reproducible.
3. An option to point at a local directory of records, for air-gapped CI and for the tests.
Either way, record when the data was fetched, so that a report can say how fresh it is. The HTTP client must be
compatible with `MIT OR Apache-2.0` and tests must not need the network.

# Specs
* `specs/osv-reading.md` (amended at step 1): the source, the cache, the freshness recorded.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* OSV API documentation (`/v1/querybatch`, `/v1/vulns/<id>`) and the OSV data dumps.
* `CLAUDE.md`: only inventories leave the user's CI; deterministic matching.

# Hints
* Sending package URLs to the OSV API sends part of the inventory out of the CI: say so in the docs, and keep a mode
  that sends nothing.
* `querybatch` returns only ids and paginates; the full records need further requests.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Download the OSV archive `<ecosystem>/all.zip` of each ecosystem the caller names into a cache, read it with
`read_directory`, and return each ecosystem's freshness (download time, URL, `Last-Modified`), under a refresh policy.
Out of scope: the OSV API (sends package URLs out; a follow-up issue if wanted), the CLI flags, the default cache
directory and the local-directory option (wired by `cli_list_affected_components`, `read_directory` already reads one).

## Plan
1. [x] Download and extract: `forewarn-osv` fetches the archives (`ureq`, `zip`) into the cache under `if-missing` and
   `always`, refuses bad names, unsafe entries and failed downloads without touching the former snapshot; verified by
   tests against a loopback HTTP server; makes true OSR-10, OSR-11, OSR-14, OSR-16, OSR-17, OSR-18. ADR 0004 accepted.
   (autonomous)
2. [ ] Read the cache: the policies `offline` and `older-than <age>`, the snapshot read back with its freshness;
   verified by tests on a cache filled by deliverable 1, the server counting the requests; makes true OSR-12, OSR-13,
   OSR-15; the spec `accepted`.

## Decisions
- Mode: autonomous
- Base commit: 06194ece51aedb5cda048b2812c65fd1916435bc
- Source: the archive of each ecosystem into a cache; the OSV API, which sends package URLs out, is a follow-up issue
  of its own, opt-in.
- An unreadable record of an archive fails the fetch of its ecosystem, the former snapshot kept.
- TLS: `rustls` with `webpki-roots`, no system dependency.
- An archive entry in a subdirectory is skipped, as `read_directory` skips subdirectories; only an absolute name, a
  `\` or a `..` component is refused as unsafe (OSR-18, settled at deliverable 1).
- `zip`: the latest version compatible with the workspace `rust-version` 1.86.

## Summary of deliverable 1
- done: module `forewarn_osv::fetch` (`Archives::fetch`, policies `if-missing` and `always`), `ureq` 3 with `rustls`,
  `zip` 7 with `zlib-rs`; ADR 0004 accepted; CLAUDE.md updated.
- checks: tests pass (13 new, loopback server), clippy pedantic clean, `check-specs` passes.
- red: OSR-H3, OSR-10, OSR-11, OSR-14, OSR-16, OSR-17, OSR-18: `unresolved import forewarn_osv::fetch`.
- Code review: no findings
- not verified: a download of a real OSV archive (tests use no network).
