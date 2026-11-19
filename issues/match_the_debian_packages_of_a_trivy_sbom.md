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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
Match a `deb` component without `upstream` under the source package `trivy` writes in its properties
(`aquasecurity:trivy:SrcName`, `SrcEpoch`, `SrcVersion`, `SrcRelease`), read by the CycloneDX adapter into a source
package of the domain component; read the `epoch` qualifier into a version taken from the package URL. Measured on
2026-11-19, `trivy` 0.76.2 on `debian:bookworm-slim` (CycloneDX 1.7): 88 `deb` components, none with `upstream`, 62
named apart from their source, 11 with `epoch=` (their component `version` already carries `1:`). Other
distributions and other tools' properties stay out.

## Plan
1. [x] Split the Debian requirements out of `specs/vulnerability-matching.md` (over `spec_max_bytes`) into a spec of
   their own, ids moved as `write-spec` says, the tests re-cited, no change of behaviour; verified by
   `cardinal run check-specs` and the tests unchanged; ~200 lines. (autonomous)
2. [x] Read the source package of a Trivy component (adapter module `trivy`, `Component::source` in the domain), match
   a `deb` component under it when `upstream` gives no name, read `epoch`; a trimmed Trivy SBOM of
   `debian:bookworm-slim` as fixture (`fixtures/trivy.cdx.json`, its command in the fixtures README); verified by
   `forewarn-cyclonedx/tests/real_tools.rs`, `reading.rs`, `forewarn-domain/tests/component_package.rs` and a
   `forewarn match --osv` test through the binary on a Trivy SBOM; makes true SBR-4, SBR-17, SBR-H6, VMT-33, VMT-34,
   now DEB-2, DEB-3, DEB-5, DEB-H2; ~500 lines. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 2b990ee2c31bb420b738ba07761c755920193503
- 2026-11-19, the user's answer `ok`: the Debian requirements split into a spec of their own first (1 a), the
  Trivy fixture trimmed (2 a).
- `upstream` comes before the Trivy properties: the package URL is the standard field.
- The fixture is trimmed (a few `deb` components, the `dependencies` dropped): the whole SBOM is 206 KB.

## Deliverable 1: split the Debian requirements out

done: VMT-32 to VMT-35 moved to `specs/debian-matching.md` (DEB-1 to DEB-4, VMT-H4 as DEB-H1), withdrawn in
`specs/vulnerability-matching.md` (back to `accepted`); the amendments of this issue written there as DEB-2, DEB-3,
DEB-5, DEB-H2 (`draft`), with SBR-4, SBR-17, SBR-H6 in `specs/sbom-reading.md` (`draft`); tests re-cited; no code
change of behaviour.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clippy pedantic clean |
| specs | `check-specs` clean |
| docs | `CLAUDE.md`, `docs/architecture.md` |
| code review | see below |

red: none (no new test: a move).

Code review: no findings

not verified: nothing.

decisions needed: none.

## Deliverable 2: match the Debian packages of a Trivy SBOM

done: the CycloneDX adapter reads the source package of the `aquasecurity:trivy:Src…` properties (module `trivy`)
into `Component::source` (`SourcePackage`); a `deb` component without a name in `upstream` is matched under it, its
version that of the source; the `epoch` qualifier precedes a version of the component or its package URL that
lacks one; a trimmed Trivy
SBOM of `debian:bookworm-slim` as fixture. `specs/debian-matching.md` and `specs/sbom-reading.md` `accepted`.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clippy pedantic clean |
| specs | `check-specs` clean |
| docs | user guide, `CLAUDE.md`, `docs/architecture.md`, fixtures README |
| code review | see below |

red: DEB-H2, DEB-2, DEB-3, DEB-5, SBR-4, SBR-H6, SBR-17: `unresolved import forewarn_domain::sbom::SourcePackage`
(domain and adapter tests); through the binary, `libpam0g` matched under its binary name and `libc6`, `bash` missed
(`left: [libpam0g DSA-6103-1]`, `right: [libc6 DSA-6101-1, bash DSA-6102-1]`).

Code review: 1 finding
- `matching.rs`: the `epoch` qualifier was lost when the component has a version of its own without epoch (a
  `1.2.13` compared below a `1:` fix). Fixed: DEB-5 amended to the version of the component too, tested in
  `component_package.rs`.

not verified: a whole Trivy SBOM against the OSV `Debian:12` archive (the fixture is trimmed, the archive not
fetched).

decisions needed: none.
