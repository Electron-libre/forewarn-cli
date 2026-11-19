---
priority: medium
depends_on: [match_debian_packages]
why: 'one package of a Debian testing image makes the whole match run fail'
---
# Keep a Debian release without an OSV archive from failing the run

# Goal
`forewarn match` downloads the OSV archive of each ecosystem of the SBOM, and a download that fails stops the run.
OSV publishes advisories for `Debian:14` (testing) but no archive `Debian%3A14/all.zip`, so an SBOM of a testing image
fails as a whole, every other ecosystem included. Have such a release reported, its packages not evaluated, and the
rest matched.

# Findings
* 2026-11-19, the OSV bucket: `Debian%3A13/all.zip` answers 200, `Debian%3A14/all.zip` and `Debian%3A15/all.zip` 404;
  `DEBIAN-CVE-2024-6387` names `Debian:12`, `Debian:13` and `Debian:14` packages.
* `ecosystems.txt` of the bucket lists `Debian` alone, not its releases.

# Approach
1. Treat a 404 on the archive of a `Debian:<release>` ecosystem as an ecosystem OSV does not publish: its components
   not evaluated with a reason of their own (or `unknown release`), the run going on.
2. Or read the parent archive `Debian/all.zip` and keep the records of the release (larger download).
3. With `--osv-api`, the API may answer for `Debian:14`: check before choosing.

# Specs
* `specs/osv-fetching.md` (OSF-18), `specs/cli-match.md` (MCH-5), `specs/vulnerability-matching.md` (VMT-10).

# Resources
* `crates/forewarn-osv/src/fetch.rs`, `crates/forewarn/src/main.rs` (`ecosystems`, `no_records`).
* `issues/done/match_debian_packages.md`.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
A `Debian:<release>` whose archive OSV does not publish (404, `Debian:14` testing) must not fail the run: fetch the
parent archive `Debian/all.zip` instead (checked 2026-11-19: 82 MB zipped, 75k records, `DEBIAN-CVE-2024-6387` names
`Debian:14` there), so the packages of a testing image are matched, not just set aside. The rule is generic to any
`<parent>:<release>`. `--osv-api` needs no change: the API answers for `Debian:14` (checked). Approach 2 of the issue.

## Plan
1. [x] Move the test helpers of `crates/forewarn-osv/tests/fetching.rs` (fake server, archives, fixtures; the file is
   over the size limit) into `crates/forewarn-osv/tests/common/mod.rs`, no change of behaviour; verified by the
   unchanged tests passing. (autonomous)
2. [x] Fall back to the parent archive: a 404 told apart from the other download failures (`forewarn-cache`), the
   fallback in `Archives::fetch` (`forewarn-osv/src/fetch.rs`), the parent returned once, offline read of a cached
   parent; verified by `forewarn-osv/tests/release_archive.rs` (new, fake server) and a `forewarn match` test in
   `crates/forewarn/tests/debian.rs` (a `Debian:14` package matched through `Debian/all.zip`, the crates of the same
   SBOM matched too); docs: user guide, `CLAUDE.md`; makes true OSF-22, OSF-23, OSF-24, OSF-25.  (autonomous)

## Decisions
- Mode: autonomous
- Base commit: aca81fcd49cd158f0ae07ccbc80842bfe9c3b9a5
- The report names the archive `Debian` (its URL, its record count) as a source in place of `Debian:14`: what was
  downloaded.
- 2026-11-19 (the user's answer `ok`): the parent archive is fetched (approach 2), for any `<parent>:<release>`.

## Deliverable 1: move the test helpers of fetching

done: the loopback server, the archives of the fixtures and the `Archives` pointed at it moved from
`crates/forewarn-osv/tests/fetching.rs` to `crates/forewarn-osv/tests/common/mod.rs`, made `pub`; no test changed.
The spec amendment (OSF-22 to OSF-25, `draft`) goes with this commit.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clippy pedantic clean |
| specs | OSF `draft`, `check-specs` clean |
| docs | none (tests only) |
| code review | see below |

red: none (a move, no new test).

Code review: no findings

not verified: nothing.

decisions needed: none.

## Deliverable 2: fall back to the parent archive

done: `Archives::fetch` reads an ecosystem `<parent>:<release>` whose archive answers 404 (or, offline, that the cache
does not hold) from the snapshot of `<parent>`, returned once at the place of the first ecosystem it stands for; a
failure of the parent names the release. `forewarn_cache::Error::Download` carries the status the server answered.
Fixture `DEBIAN-CVE-2024-6387.json` (api.osv.dev) added; the two `matching.rs` tests reading the fixture directory count 5 records.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clippy pedantic clean |
| specs | OSF accepted, `check-specs` clean |
| docs | user guide (sources), `CLAUDE.md`, fixtures README |
| code review | see below |

red: OSF-H4, OSF-22, OSF-23, OSF-24: `forewarn match` exited 5, `"Debian:14": cannot download …/Debian%3A14/all.zip:
the server answered 404 Not Found`; `Archives::fetch` failed the same way for each scenario. OSF-25 and the 503 case
passed before the code (the former behaviour, kept).

Measured on the real `Debian/all.zip` (74,965 records, `--osv` on the extracted archive): an openssh-server of
`debian-14` matched (CVE-2024-6387 among others), peak memory 650 MB.

Code review: no findings

not verified: the real OSV bucket answering 404 for `Debian%3A14` through `forewarn match` (no test reaches the
network; the 404 was checked with `curl`).

decisions needed: none.
