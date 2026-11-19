---
priority: medium
depends_on: [match_debian_packages]
why: 'a Trivy SBOM of a Debian image may look clean while its packages are never compared'
---
# Match the Debian packages of a Trivy SBOM

# Goal
`forewarn match` names a Debian package by the `upstream` qualifier of its package URL, which Syft writes. Trivy
reportedly does not: the source package would sit in CycloneDX properties of the component. A package whose binary
name differs from its source (`libssl3`, source `openssl`) is then looked up under a name no OSV Debian advisory uses,
and is reported neither affected nor not evaluated. Have the Debian packages of a Trivy SBOM matched under their
source package and version.

# Findings
* 2026-11-19, `high` review of `match_debian_packages`: Trivy's `deb` package URLs are said to carry `arch`,
  `distro` (and an `epoch`) but no `upstream`, the source in the properties `aquasecurity:trivy:SrcName`,
  `SrcVersion`, `SrcRelease`, `SrcEpoch`. Not verified: Trivy was not available on the machine.
* A component without `upstream` is matched under its binary name and version (VMT-33, VMT-34): right when the
  source has the binary's name, as Syft omits `upstream` then.

# Approach
1. Measure first: generate the CycloneDX SBOM of a Debian image with Trivy and record its `deb` components (package
   URL, version, properties), the epoch included.
2. If the properties hold the source: read them in the CycloneDX adapter into the domain component (a source name
   and version beside the package URL), used by `ComponentPackage::of` where `upstream` is absent.
3. Read an `epoch` qualifier, if Trivy writes one, into the version.

# Specs
* `specs/sbom-reading.md` (the source of a component), `specs/vulnerability-matching.md` (VMT-33, VMT-34 amended).

# Resources
* `crates/forewarn-domain/src/debian.rs`, `crates/forewarn-cyclonedx/src/`.
* `issues/done/match_debian_packages.md`.

# Hints
* Properties are vendor-specific: keep their names in the adapter, out of the domain.
