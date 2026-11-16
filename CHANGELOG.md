# Changelog

The notable changes of each version, newest first ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
[Semantic Versioning](https://semver.org/)). Each section is written by `cardinal run release <version>` from the commits,
then reread before the release is committed.

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
