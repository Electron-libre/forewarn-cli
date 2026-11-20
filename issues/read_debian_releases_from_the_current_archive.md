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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-20

## Understanding
Read every `<parent>:<release>` from the `<parent>` archive (OSF-22 generalised): the release archive is never
requested, so the Debian packages are matched against the advisories Debian publishes today. Out of scope: the other
distributions (the domain maps only Debian), removing the stale `Debian%3A<n>` snapshots of a user's cache.

## Measure (2026-11-20)
* Bucket: `Debian:3.0` to `Debian:13` published, every one Last-Modified 2024-10-04 or 2024-10-09; `Debian:14`
  404. Same for `Alpine:v3.x` (2024-10-09) and `Ubuntu:24.04:LTS` (2024-10-08), while `Debian`, `Alpine`, `Ubuntu`
  are of the day: OSV froze every per-release archive.
* `Debian/all.zip` (75,874 records) names every release, `Debian:3.0` to `Debian:14`; `Debian:13` in 63,387
  `affected` entries against 31,045 in `Debian%3A13/all.zip`.
* `Debian%3A13/all.zip` holds 28,999 NVD-shaped `CVE-` records (with Alpine entries); by (CVE, package) 882 pairs
  are absent from the parent, 92 of their packages absent from it for `Debian:13` (`uw-imap`, removed packages), the
  rest `introduced 0` unfixed in 2024 (`libvpx` CVE-2017-0641) that the current tracker no longer lists for trixie.
  The parent is Debian's current judgement: nothing is lost that Debian still claims.
* Approach 3 (age of an archive far behind): live archives stay unchanged for months (`CRAN`, `GHC` 2026-09-08,
  `Pub` 2026-10-15), so a threshold is arbitrary; with the release archives no longer read, no source left is frozen.

## Plan
1. [x] Read each release from its parent: `Archives::fetch` maps `<parent>:<release>` to `<parent>` before any
   request (the 404 fallback and `Failure::unpublished` removed), tests of `release_archive.rs`, `fetching.rs` (osv
   and CLI) rewritten to the amended scenarios, user guide and MCH-5 updated; verified by the OSF-H4, OSF-22 to
   OSF-24 tests and `just check`; makes true OSF-14, OSF-21, OSF-22, OSF-23, OSF-24, MCH-5. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 10bb2a2a74793fffc3814171ae4141e27f73509a
- No age warning on an archive behind the others (approach 3 dropped): live archives stay unchanged for months, and
  no frozen source is read any more; the report keeps its `Last-Modified`.
- The stale `Debian%3A<n>` snapshots of a cache are left in place, not read; the user guide says they can be removed.

## Deliverable 1
- done: a `<parent>:<release>` is fetched from the `<parent>` archive before any request; the 404 fallback,
  `Failure` and `push` removed; tests, user guide, `CLAUDE.md` and MCH-5 updated.
- red: OSF-H4, OSF-22, OSF-23, OSF-24: `left: ["GET /Debian%3A13/all.zip", "GET /crates.io/all.zip"]`,
  `right: ["GET /Debian/all.zip", "GET /crates.io/all.zip"]`; offline `left: ["Debian:13"]`, `right: ["Debian"]`.
- checks: `project-check` green (fmt, clippy, tests, specs), docs updated, specs `accepted` again.
- Code review: no findings
- not verified: a real run against the OSV bucket (the measure above stands for it).
