---
priority: low
depends_on: [match_the_debian_packages_of_a_trivy_sbom]
why: 'a false positive on a package whose SBOM writes its epoch in one version only; no tool measured does so yet'
---
# Keep the epoch of a Debian package URL version

# Goal
A `deb` component is matched at its own version first. When that version lacks the epoch its package URL version
carries (`version` `4.13+dfsg1-1`, `pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1?distro=debian-12`), it is compared at
epoch 0, below every `1:` fixed version of the Debian advisories: reported affected when it is not. Have the epoch of
the package URL version kept in that case.

# Findings
* 2026-11-19, `high` review of `match_the_debian_packages_of_a_trivy_sbom`: pre-existing; DEB-5 now adds the epoch
  of the `epoch` qualifier to a version that lacks one, not the epoch written in the package URL version.
* Trivy 0.76.2 writes the epoch in the component `version` and in the `epoch` qualifier (both handled); the tool
  that writes it in the package URL version only was not measured.

# Approach
1. Measure: the Syft and cdxgen SBOMs of a Debian image, a package with an epoch (`login`, `passwd`): where each
   writes the epoch.
2. When the component version holds no `:` and the package URL version does, take the epoch of the latter (amend
   DEB-5).

# Specs
* `specs/debian-matching.md`, DEB-5 amended.

# Resources
* `crates/forewarn-domain/src/debian.rs` (`DebianPackage::of`).
* `crates/forewarn-domain/tests/component_package.rs` (DEB-5).
