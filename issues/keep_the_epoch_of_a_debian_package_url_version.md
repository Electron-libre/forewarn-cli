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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-20

## Understanding
A `deb` version taken from the component without a `:` gets the epoch of its package URL version when the `epoch`
qualifier gives none (DEB-5 amended), so `login` 4.13+dfsg1-1 of `…/login@1%3A4.13…` compares as 1:4.13+dfsg1-1.
Out of scope: the source package version (`upstream`, SBOM source), which keeps its own epoch.
Measure (approach step 1): not run, a Docker run of Syft/cdxgen was refused in this session; see the question.

## Plan
1. [x] Epoch of the package URL version: `DebianPackage::of` takes the epoch of the package URL version when the
   chosen version holds no `:` and the qualifier gives none; verified by a DEB-5 test in `component_package.rs`
   and one matching a record fixed at `1:` (not reported); makes true DEB-5. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: cc8892d9e7017b2413e25e2938a5a84acbdefef8
- Measure: skipped (1 a); the fix holds whatever Syft and cdxgen write.
- Both epochs given: the `epoch` qualifier first (2 a).

## Summary of deliverable 1
done: a `deb` version without `:` takes the epoch of the `epoch` qualifier, else that of the package URL version.
| check | result |
|---|---|
| tests | pass (`cardinal run project-check`) |
| lint | pass |
| specs | pass, `debian-matching` back to `accepted` |
| docs | `docs/user-guide.md`, doc comment of `DebianPackage::version` |
| code review | `low`, no findings |

red: DEB-5: `login` 4.13+dfsg1-1 of `pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1?…` reported by `DSA-6101-1` fixed at
`1:4.13+dfsg1-1` (left: two matches, right: `DSA-6102-1` only); version `4.13+dfsg1-1`, expected `1:4.13+dfsg1-1`.
Code review: no findings
not verified: where Syft and cdxgen write the epoch (measure skipped, decision 1 a).
