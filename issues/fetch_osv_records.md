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
