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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-20

## Understanding
Measured on 2026-11-20 (cdxgen 13.2.0, `debian:12`, `/opt/cdxgen/lib/managers/binary.js`): cdxgen reads the
`aquasecurity:trivy:Src…` properties of its Trivy plugin, drops them from the binary package and adds a component of
its own for each source package named apart (`shadow`, `glibc`: tag `source`, identity evidence of confidence 0
naming the binaries), dropped when a binary of the same package URL exists (`util-linux`, `apt`). `forewarn match`
already reports the advisory of `shadow` under that component: nothing is silently clean, so no new reading. Left to
do: guard it with a cdxgen fixture and a test through the binary, and say it in the user guide. Naming the binaries
(`passwd`) beside the source component is out of scope (non-goal of `specs/debian-matching.md`).

## Plan
1. [x] A trimmed cdxgen SBOM of `debian:12` as fixture (`cdxgen-debian.cdx.json`: `passwd`, `login`, `libc6`, the
   source components `shadow` and `glibc`, `util-linux` and `libblkid1`, its command in the fixtures README), read by
   `real_tools.rs`, and a `forewarn match --osv` test through the binary reporting `shadow` and `glibc` under their
   records, `passwd` and `libc6` not; the user guide names cdxgen and its source components; verified by
   `crates/forewarn/tests/debian.rs`; makes true DEB-H3; ~250 lines. (autonomous)
2. [x] Fixes of the `high` review: the user guide says the binaries are counted clean and a VEX verdict names the
   source component; the DEB-H3 test proves the epoch (a record fixed at `4.14`); `real_tools.rs` checks the package
   URLs of the source components; verified by the same tests; makes true DEB-H3, DEB-5. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: db528763cbcd5acc4287c308a37cce54aabcd1cc
- 2026-11-20, the user's answer `ok`: the binaries a cdxgen source component names in its evidence are not reported (1 a).

## Deliverable 1: guard the source components of a cdxgen SBOM

done: a trimmed cdxgen 13.2.0 SBOM of `debian:12` as fixture (`cdxgen-debian.cdx.json`), read by `real_tools.rs`;
`forewarn match --osv` on it reports `shadow`, `glibc` and `util-linux` under their records, the binaries named apart
clean; DEB-H3 and a non-goal in `specs/debian-matching.md` (back to `accepted`); the user guide names cdxgen and its
source components.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clippy pedantic clean |
| specs | `check-specs` clean |
| docs | user guide, fixtures README; `CLAUDE.md` and `docs/architecture.md` still true |
| code review | see below |

red: none (DEB-H3 guards a behaviour already true: the test passed on first run).

Code review: no findings

not verified: the whole cdxgen SBOM against the OSV `Debian:12` archive (the archive not fetched).

decisions needed: none.

## Deliverable 2: fixes of the `high` review

done: the user guide names what cdxgen does not write, says the binaries built from a source component are counted
clean and that a VEX verdict sets the match aside when it names the source component; the DEB-H3 test adds a
`shadow` record fixed at `4.14`, which only a lost epoch would report; `real_tools.rs` checks the package URLs of
`shadow` and `glibc`.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clippy pedantic clean |
| specs | `check-specs` clean |
| docs | user guide |
| code review | see below |

red: none (the fixes strengthen tests of a behaviour already true).

`high` review, 4 findings, all fixed:
- the binaries of a source component counted clean, unsaid: said in the user guide (with the VEX consequence).
- the DEB-H3 test did not prove DEB-5: a record fixed at `4.14` added.
- `real_tools.rs` did not check the source components: their package URLs asserted.
- "`cdxgen` writes neither" ambiguous after the epoch sentence: names the `upstream` qualifier and the properties.

Code review: no findings

not verified: nothing.

decisions needed: none.
