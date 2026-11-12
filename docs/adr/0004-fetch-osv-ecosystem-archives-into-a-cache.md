# 0004. Fetch the OSV archive of each ecosystem into a cache

- Status: accepted
- Date: 2026-11-13

## Context

The matching needs the OSV records that may affect the components of an SBOM (`issues/fetch_osv_records.md`), and a
vendor cannot be asked to download them by hand. OSV offers two ways to get them:

- its API: `/v1/querybatch` takes package URLs and versions and returns ids only, paginated; each full record then
  takes a `/v1/vulns/<id>` request. Little data moves, but the package URLs of the inventory leave the CI, and the
  answer depends on the moment of the query, with nothing kept to replay it;
- the archive of each ecosystem, `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`: every
  record of the ecosystem, refreshed by OSV continuously. The request names only the ecosystem; the archive can be
  kept and read again offline. Some archives are large (npm holds the malicious-package records).

`forewarn` must stay deterministic, keep the inventory in the CI unless the user decides otherwise, and run in an
air-gapped CI. The HTTP client must be compatible with `MIT OR Apache-2.0`.

## Decision

The OSV adapter (`forewarn-osv`) downloads the archive of each ecosystem the caller names into a cache directory,
extracts its records into one directory per ecosystem, beside the time of the download, its URL and the
`Last-Modified` the server sent, and reads that directory with `read_directory`. A refresh policy chosen by the
caller (`offline`, `if-missing`, `older-than <age>`, `always`) says when to download again; a new snapshot replaces the
former one only once fully extracted and read. The base URL is a parameter, so tests serve archives from a loopback
server and need no network.

The HTTP client is `ureq` (`MIT OR Apache-2.0`, blocking, no async runtime) with its default `rustls` backend
(`ring`: `Apache-2.0 AND ISC`; `webpki-roots`: `CDLA-Permissive-2.0`); the archive is read with `zip` (`MIT`),
`deflate` only.

The OSV API is not used; querying it, which sends the package URLs out, would be an opt-in of its own.

## Consequences

- Only ecosystem names leave the CI; a snapshot in the cache makes a run reproducible and lets an air-gapped CI run
  `offline` on a cache filled elsewhere.
- A report can state how fresh its data is: the download time and the `Last-Modified` of each archive.
- A first run downloads whole archives; a large ecosystem costs time and disk space.
- One unreadable record of an archive fails the fetch of its ecosystem, as `read_directory` does: the former snapshot
  stays usable.
- The domain stays free of I/O: the CLI derives the ecosystems from the SBOM and passes the vulnerabilities to the
  matching.
