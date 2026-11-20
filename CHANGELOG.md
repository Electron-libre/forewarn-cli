# Changelog

The notable changes of each version, newest first ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
[Semantic Versioning](https://semver.org/)). Each section is written by `cardinal run release <version>` from the commits,
then reread before the release is committed.

## [0.7.0] - 2026-11-20

### Fixed

- the Debian packages are matched against the current advisories of `Debian/all.zip`, read for every release: OSV
  stopped updating its archive per release (`Debian%3A13/all.zip`) in October 2024; a `Debian%3A<n>` directory of the
  cache is no longer read, so with `--refresh offline` a cache filled by 0.6.0 needs the `Debian` archive first

## [0.6.0] - 2026-11-20

### Added

- `forewarn match` matches the Debian packages of a container image (`pkg:deb/debian/…`) against the OSV advisories
  of their release (the `distro` qualifier), under their source package and version as Syft (`upstream`), Trivy (its
  `Src…` properties) or cdxgen (a `source` component) names them, the epoch of the version kept; a Debian advisory is
  reported under the CVE it names
- the OSV archive of each Debian release is fetched into the cache, that of `Debian` for a release OSV publishes none
  of (`Debian:14`)
- the components whose package URL points to a local path (a `download_url` of `file:`) are listed not evaluated,
  never matched nor sent to the OSV API

## [0.5.0] - 2026-11-19

### Added

- remember the moment of awareness of each exploited CVE
- the CI templates keep the moments of awareness in their cache

### Fixed

- keep the origin and the hand edits of the moments of awareness

## [0.4.1] - 2026-11-19

### Milestones

- CI integration templates

### Added

- a GitHub Actions workflow template, `examples/ci/github-actions.yml`
- a GitLab CI template, `examples/ci/gitlab-ci.yml`, included without global keys
- the CI templates install the released version, checked against its `SHA256SUMS`

## [0.4.0] - 2026-11-19

### Milestones

- Upload from CI

### Added

- build the route of an SBOM upload to a Forewarn service
- read the answers of the service to an SBOM upload
- check the endpoint and the token of an SBOM upload
- upload an SBOM to a Forewarn service
- upload an SBOM from the command line
- preview an SBOM upload with --dry-run

### Fixed

- refuse an answer body that is not a JSON object
- keep the token of an upload off a proxy and out of errors
- refuse a blank product and an oversized SBOM first
- tell refused credentials answered before the SBOM is sent
- send an upload again without Expect after a 417

## [0.3.0] - 2026-11-17

### Milestones

- Beta

### Added

- release binaries for Linux (musl, x86_64 and aarch64) and macOS on GitHub, each with its license notices and an
  SBOM `forewarn check` finds complete
- set aside the matches a VEX verdict says do not affect
- apply the VEX verdicts of the SBOM and of --vex files
- print the version of the last release
- name the stale drafts a rerun no longer writes
- print the backslashes of a Windows path as written

### Fixed

- apply the fixes of the review of the VEX verdicts
- apply the fixes of the review of the release version
- list the stale drafts before writing any draft
- upgrade zip to 9 and time to 0.3.55 past their advisories

## [0.2.0] - 2026-11-16

### Milestones

- Draft the CRA early warning
- Proof-of-concept demo

### Added

- read the product an SBOM describes
- draft the CRA early warning of each exploited CVE
- write the CRA early warning draft in Markdown
- write the draft early warnings of match into files
- name the draft early warnings written in the match report
- name the EUVD id of the record in the draft early warning
- read the components nested in the product
- flag the components of the product first-party
- keep first-party components out of the OSV match
- escape every character that hides text and the backslash
- group the records of a match under their status
- tell a file component from a package
- list the file components apart in the completeness check

### Fixed

- take the manufacturer of the product, not of the SBOM
- never ask to complete the manufacturer of a draft
- escape what could hide or reorder a value of the draft
- write each draft through a new temporary file, flushed
- trim the EUVD record id, none when blank
- take the product manufacturer and supplier by name only
- skip the targets of the product and blank bom-refs
- escape the bidirectional and invisible characters in reports
- flag first-party only the modules of the product's namespace
- escape the values of the adapter errors once
- count each clean component at its place in the SBOM
- escape the blank characters, let the visible format ones read
- keep escaping the annotation and hieroglyph format controls
- escape the characters whose Unicode name ends in BLANK
- tell a typed backslash from an escape in the draft
- group the records of a match through an exhaustive status

## [0.1.0] - 2026-11-13

### Milestones

- Read and check an SBOM
- Match known vulnerabilities (OSV)
- Flag actively exploited vulnerabilities (KEV, EUVD)
- Compute CRA reporting deadlines

First numbered release.
