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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
An opt-in source of OSV records: `forewarn match --osv-api` queries `/v1/querybatch` with the packages of the SBOM
(ecosystem, name, version, never the package URL), reads each id with `/v1/vulns/<id>`, and reports the API, its URL
and the time of the query as the source. Out of scope: caching the answers, retries, an environment variable.

## Plan
1. [x] API query: module `forewarn_osv::api` (batches of 1000, pagination, one record request per id, errors,
   freshness), ADR 0006; verified by tests against a loopback HTTP server; makes true OSR-24 to OSR-31, OSR-H6, the
   OSV reading spec `accepted`. (~800 lines)
2. [x] CLI: `--osv-api` and `--osv-api-url` on `forewarn match`, the API source in both reports, the help and the docs
   saying what leaves the CI; verified by end-to-end tests of the binary against a loopback server; makes true MCH-24
   to MCH-28, MCH-H3, the match spec `accepted`. (~400 lines) (autonomous)
3. [x] Review fixes of the whole issue (`high` review): a `next_page_token` given twice refused instead of paging
   forever, a record holding another id refused, a Go version queried without its leading `v`, one path-segment check
   shared by ecosystem names and ids, the request body built without a fallible serialization, the doc of `utc`;
   verified by 3 new tests; OSR-28, OSR-31, MCH-24 amended. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: d32dd8bf689fca5496372ca502239be4f367eb2a
- `querybatch` receives the ecosystem, name and version of each component, never its package URL (OSR-26, OSR-27).
- The flag `--osv-api` alone turns the source on, no environment variable (MCH-25).
- `--osv-api-url <url>` changes the API, and requires `--osv-api` (MCH-27, MCH-10).
- No cache of the answers and no retry: a failed request exits with 5.

## Summary of deliverable 1
- done: module `forewarn_osv::api` (`Api::query`: batches of 1000, pagination, one record request per id, ids
  checked before any record request, errors of OSR-31, freshness of OSR-25); `parse_record` and the HTTP agent shared
  with `fetch`; ADR 0006 accepted; `specs/osv-reading.md` accepted; CLAUDE.md updated.
- checks: tests pass (16 new, loopback server), clippy pedantic clean, `check-specs` passes.
- red: OSR-H6, OSR-24, OSR-25, OSR-26, OSR-27, OSR-28, OSR-29, OSR-30, OSR-31: `unresolved import forewarn_osv::api`.
- Code review: no findings

## Summary of deliverable 2
- done: `forewarn match --osv-api` and `--osv-api-url` (conflicting with `--osv`, `--cache`, `--refresh`,
  `--osv-url`); the API source in the human and JSON reports (`kind: "api"`, `queriedAt`); the help says what the API
  receives; `push_source` split out of the human report (pedantic `too_many_lines`); README and CLAUDE.md updated;
  `specs/cli-match.md` accepted. An error on a record of the API names it `OSV API record <id>`.
- checks: tests pass (8 new end-to-end, 1 internal), clippy pedantic clean, `check-specs` passes.
- red: MCH-H3, MCH-24, MCH-26, MCH-27, MCH-16, MCH-12, MCH-14, MCH-28: exit code 2, `unexpected argument
  '--osv-api'` (MCH-10 and MCH-25 passed before the code: their exit codes do not depend on the flag existing).
- Code review: no findings

## Summary of deliverable 3
- done: the fixes of the `high` review listed in the plan; follow-up issue
  `issues/done/evaluate_ecosystem_ranges_beyond_semver.md` (roadmap: Match known vulnerabilities).
- checks: tests pass (3 new), clippy pedantic clean, `check-specs` passes.
- red: OSR-28, OSR-31, MCH-24: a fix of a review finding, the tests written with the fix.
- High review: 9 findings. Fixed: endless pagination, record id not checked, Go `v` prefix, duplicated name check,
  misleading serialization error, `utc` doc. Not fixed: `ECOSYSTEM` ranges of PyPI/Maven not evaluated (outside the
  issue: follow-up issue); record requests one after another (a perf choice: few ids per SBOM, kept simple); the
  loopback test server copied per test file (each serves a different protocol; sharing it across two crates needs a
  test-support crate).
- Code review (low): no findings
