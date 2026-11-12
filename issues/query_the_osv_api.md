---
priority: low
depends_on: [fetch_osv_records, cli_list_affected_components]
why: 'a comfort for large ecosystems: the archives already cover the milestone without sending the inventory out'
---
# Query the OSV API as an opt-in source of records

# Goal
`forewarn` fetches the OSV archive of each ecosystem the SBOM uses (ADR 0004), which can mean downloading a large
archive (npm) for a few components. Querying the OSV API moves little data instead, but sends the package URLs and
versions of the inventory out of the CI and gives an answer that depends on the moment of the query. The user should
be able to choose it knowingly, never by default.

# Approach
1. `/v1/querybatch` with the package URL and version of each component, following its pagination, then
   `/v1/vulns/<id>` for each id returned, read with the record model of `forewarn-osv`.
2. An opt-in of its own (a flag, and maybe an environment variable), off by default; the docs say which data leaves
   the CI.
3. Record the time of the query and the source URL as the freshness of the records, like a downloaded archive.
4. Tests against a loopback HTTP server, as `crates/forewarn-osv/tests/fetching.rs` does: no network.

# Specs
* `specs/osv-reading.md` (amended): the API source, its requests, its freshness, its errors.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* ADR 0004 (`docs/adr/0004-fetch-osv-ecosystem-archives-into-a-cache.md`): why the archives are the default.
* `crates/forewarn-osv/src/fetch.rs`: the archive source, its `ureq` agent and its errors.
* OSV API documentation (`/v1/querybatch`, `/v1/vulns/<id>`).

# Hints
* `CLAUDE.md`: only inventories leave the user's CI; this source sends part of one to a third party, which is why it
  is opt-in.
* `querybatch` returns only ids and paginates per query (`next_page_token`).
