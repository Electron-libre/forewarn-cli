---
priority: medium
depends_on: [keep_the_epoch_of_a_debian_package_url_version]
why: 'a cdxgen SBOM of a Debian image misses the advisories of every package named apart from its source'
---
# Match the Debian packages of a cdxgen SBOM under their source package

# Goal
The Debian advisories of OSV name the source package (`shadow`, `glibc`); a `deb` component is matched under the
source its `upstream` qualifier (Syft) or its `aquasecurity:trivy:Src…` properties (Trivy) name (DEB-2, DEB-3,
SBR-17). cdxgen writes neither: its binary packages named apart from their source (`passwd`, `libc6`) are matched
under their own name, no advisory names them, and the SBOM looks clean while they are never compared. Have such a
package matched under its source, or reported as not evaluated, rather than silently clean.

# Findings
* 2026-11-20, `debian:12` saved with `docker save`, cdxgen 13.2.0 (its Trivy plugin v0.74.0) `-t docker` on the
  archive: 130 `deb` components, none with an `upstream` qualifier nor an `aquasecurity:trivy:SrcName` /
  `SrcVersion` property; the properties written are `PkgID`, `PkgType`, `PackageSource` (`apt`, `cdebconf`,
  `usrmerge`: a source on 3 values only), `PackageStatus`, `PackageArchitecture`, `InstalledCommand…`,
  `Capability…`.
* Same image: `forewarn match` with a record of `Debian:12` `shadow` fixed at `1:4.13+dfsg1-1+deb12u3` reports
  `passwd` of the Syft SBOM, not that of the cdxgen SBOM (it reports cdxgen's `login` and `shadow` components only
  because a record of the test also named `login`).
* Same measure: Syft 1.57.1 writes `upstream=shadow` for `login` and `passwd`.

# Approach
1. Measure: whether an option of cdxgen (its Trivy plugin, a `--profile`, a newer release) writes the source
   package, and what `PackageSource` holds when written.
2. If one does: read it (amend SBR-17 or DEB-2) and document the option in the user guide.
3. Else, without detecting dependencies (never build a scanner): a `deb` component with no source named reported
   apart (a not-evaluated reason, or a warning of the completeness check), or a mapping read from the OSV records
   themselves if they name binary packages. Propose, decide at validation.

# Specs
* `specs/debian-matching.md` (DEB-2, DEB-3), maybe `specs/sbom-reading.md` (SBR-17).

# Resources
* `crates/forewarn-domain/src/debian.rs` (`DebianPackage::of`).
* `crates/forewarn-cyclonedx/src/trivy.rs`.
* `issues/done/match_the_debian_packages_of_a_trivy_sbom.md` (the same gap for Trivy).

# Hints
* cdxgen writes the `:` of a package URL version unencoded (`login@1:4.13%2B…`); `forewarn` reads it.
