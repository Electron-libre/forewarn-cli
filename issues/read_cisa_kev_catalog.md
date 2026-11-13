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
