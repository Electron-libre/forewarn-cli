---
priority: high
why: 'the Debian packages are matched against advisories frozen in October 2024: a newer glibc or OpenSSL vulnerability raises nothing'
---
# Read the Debian releases from the current archive

# Goal
`forewarn match` fetches `Debian:13` from `<osv>/Debian%3A13/all.zip` and falls back to the `Debian` archive only when
that answers 404 (OSF-22). OSV still serves the per-release archive, but it is no longer updated: the Debian packages of
an SBOM are matched against advisories two years old, and the report gives no sign of it. Match them against the
current Debian advisories.

# Findings
* 2026-11-20, forewarn 0.6.0 on the Syft SBOM of a `gcr.io/distroless/cc-debian13` image (14 Debian packages):
  `Debian:13: 28999 records … from …/Debian%3A13/all.zip, Last-Modified Fri, 04 Oct 2024 15:53:24 GMT`, while the
  `crates.io` archive of the same run is from the same day.
* Same day, `HEAD` of the bucket: `Debian%3A13/all.zip` 43 MB, Last-Modified 2024-10-04; `Debian/all.zip` 83 MB,
  Last-Modified 2026-11-20.

# Approach
1. Measure first: list the `Debian:<n>` entries of the bucket and their Last-Modified, and check that `Debian/all.zip`
   holds the records of every release (`affected[].package.ecosystem` `Debian:13`, `Debian:12`…), so that nothing of
   the per-release archive is lost.
2. Then either always read a `<parent>:<release>` from the `<parent>` archive (one download per run for every release,
   OSF-22 generalised), or prefer the parent when the release archive is older than it.
3. Report the age of an archive far behind the others of the run, so a frozen source is visible.

# Specs
* `specs/osv-fetching.md`: OSF-22, OSF-23 amended, their scenarios.

# Resources
* `crates/forewarn-osv/src/fetch.rs`: `Archives::fetch`, `push`, `Failure::unpublished`.
* `specs/osv-fetching.md`, `specs/debian-matching.md`.
