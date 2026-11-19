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
* `issues/match_debian_packages.md`.
