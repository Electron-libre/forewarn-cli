# 0006. Query the OSV API as an opt-in source of records

- Status: accepted
- Date: 2026-11-13

## Context

ADR 0004 fetches the OSV archive of each ecosystem the SBOM uses: only ecosystem names leave the CI, and a cached
snapshot makes a run reproducible. Some archives are large (npm), which costs a first run time and disk space for a
few components. The OSV API answers for the packages of an SBOM alone (`/v1/querybatch`, then `/v1/vulns/<id>`), but
it receives the ecosystem, name and version of each component, part of the inventory, and its answer depends on the
moment of the query, with nothing kept to replay it.

## Decision

The OSV adapter (`forewarn-osv`) gains a second source, a query of the OSV API: one `querybatch` request per 1000
distinct packages, following the `next_page_token` of each query, then one `/v1/vulns/<id>` request per id, read with
the record model of ADR 0003. A query sends the ecosystem, the name and the version of each package, never its package
URL (whose qualifiers and subpath could say more about the build), and returns the time it started and the URL of the
API as the freshness of its records. It reuses the `ureq` agent configuration and the timeouts of ADR 0004, and keeps
no cache.

`forewarn match` uses it only with `--osv-api` on its command line; no environment variable turns it on, so that
sending the inventory out is always visible where the job is defined. Its help says which data leaves the CI.

## Consequences

- The archives stay the default; a user who opts in trades the inventory staying in the CI for a small download.
- A run with `--osv-api` is not reproducible: the report gives the time of the query instead of a snapshot.
- The API filters the records by version itself: a record it does not return for a version is neither matched nor
  listed as not affecting it, unlike with an archive.
- A failed request fails the run (exit code 5), with no retry.
