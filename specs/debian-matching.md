---
id: DEB
status: accepted
adrs: [0001]
---

# Debian package matching

## Intent

Match the Debian packages of an image SBOM against the OSV advisories of their Debian release, under the source
package and version the advisories name, whichever image scanner wrote the SBOM.

## Requirements

### Behaviour

- **DEB-1** (deterministic) The ecosystem of a `deb` package URL of namespace `debian` must be `Debian:<release>`,
  `<release>` the run of ASCII digits that follows `debian-` at the start of its `distro` qualifier, its leading zeros
  dropped (`debian-13.7` and `debian-13` give `Debian:13`), followed for a release before 7 by `.` and the run of
  digits after the next `.`, as OSV names them (`debian-6.0.10` gives `Debian:6.0`); a value that does not start with
  `debian-` and a digit, or names a release before 7 without its minor, gives the reason `unknown release`
  (`specs/vulnerability-matching.md`, VMT-10).
- **DEB-2** (deterministic) The name of a `deb` package must be the part of its `upstream` qualifier before its first
  `@`, the source package OSV names, when that part is not empty, else the name of the source package the component
  carries (`specs/sbom-reading.md`, SBR-17), a source with a name empty or only whitespace counting as none (DEB-3
  too), else the name of the package URL.
- **DEB-3** (deterministic) The version of a `deb` package must be the part of its `upstream` qualifier after its
  first `@`, the version of its source package, when that part is not empty; else, when `upstream` gives no name
  (DEB-2), the version of the source package the component carries, when it has one; else the version of VMT-7
  (`specs/vulnerability-matching.md`).
- **DEB-4** (deterministic) A `deb` package URL of namespace `debian` whose `distro` or `upstream` qualifier does not
  percent-decode must carry the reason `invalid package URL` (`specs/vulnerability-matching.md`, VMT-10).
- **DEB-5** (deterministic) A version of a `deb` package taken from the component or its package URL
  (`specs/vulnerability-matching.md`, VMT-7) must be preceded by `<epoch>:` when it holds no `:`, `<epoch>` the part
  before the first `:` of the package URL version, else its `epoch` qualifier, the first of the two that is not empty
  nor only whitespace; an `epoch` qualifier that does not percent-decode gives the reason
  `invalid package URL` (`specs/vulnerability-matching.md`, VMT-10).

## Scenarios

- **DEB-H1** (happy; DEB-1, DEB-2) Given an SBOM an image scanner wrote, with
  `pkg:deb/debian/libssl3t64@3.5.7-1~deb13u3?arch=amd64&distro=debian-13.7&upstream=openssl`, and a record affecting
  `Debian:13` `openssl` in the `ECOSYSTEM` range introduced `0`, fixed `3.5.7-1~deb13u4`, when the components are
  matched, then `libssl3t64` 3.5.7-1~deb13u3 is reported with that record.
- **DEB-H2** (happy; DEB-2, DEB-3) Given an SBOM `trivy` wrote, with
  `pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12.15` of source package `glibc` 2.36-9+deb12u14,
  and a record affecting `Debian:12` `glibc` in the `ECOSYSTEM` range introduced `0`, fixed `2.36-9+deb12u15`, when
  the components are matched, then `libc6` 2.36-9+deb12u14 is reported with that record.
- **DEB-H3** (happy; DEB-1, DEB-2, DEB-5) Given an SBOM `cdxgen` wrote for the image `debian:12`, with the binary
  package `pkg:deb/debian/passwd@1:4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12&epoch=1` and, beside it, the
  component cdxgen adds for its source package, tagged `source`,
  `pkg:deb/debian/shadow@1:4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12&epoch=1`, and a record affecting
  `Debian:12` `shadow` in the `ECOSYSTEM` range introduced `0`, fixed `1:4.13+dfsg1-1+deb12u3`, when the components
  are matched, then `shadow` 1:4.13+dfsg1-1+deb12u2 is reported with that record and `passwd` is not.
- (DEB-1) Given the `openssl` record of DEB-H1 under `Debian:12`, when the `libssl3t64` of DEB-H1 is matched, then no
  match is reported.
- (DEB-1) Given `pkg:deb/debian/libc6@2.41-12?arch=amd64`, with no `distro`, or with `distro=trixie`, when it is
  matched, then it is reported as not evaluated, unknown release.
- (DEB-1) Given `pkg:deb/debian/libc6@2.11.3-4?distro=debian-6.0.10`, when it is matched, then its ecosystem is
  `Debian:6.0`; with `distro=debian-6`, it is reported as not evaluated, unknown release.
- (DEB-4) Given `pkg:deb/debian/libssl3@3.0.11-1?distro=debian-12&upstream=openssl%4`, when it is matched, then it is
  reported as not evaluated, invalid package URL.
- (DEB-2, DEB-3) Given `pkg:deb/debian/libssl3@3.0.11-1?distro=debian-12&upstream=openssl` of source package
  `openssl-other` 3.0.12-1, when it is matched, then it is matched as `openssl` 3.0.11-1: the package URL comes first.
- (DEB-3) Given `pkg:deb/debian/bash@5.2.15-2%2Bb13?distro=debian-12` of source package `bash` 5.2.15-2, when it is
  matched, then its version is 5.2.15-2, that of the source; of source package `pam` with no version, the version of
  VMT-7.
- (DEB-5) Given `pkg:deb/debian/login@4.13%2Bdfsg1-1?distro=debian-12&epoch=1` with no version of its own nor source
  package, when it is matched, then its version is 1:4.13+dfsg1-1; with the component version 1:4.13+dfsg1-1 or
  4.13+dfsg1-1, the same; of source package `shadow` 4.13+dfsg1-1, 4.13+dfsg1-1, the epoch the source gives; with
  `epoch=%G1`, it is reported as not evaluated, invalid package URL.
- (DEB-5) Given `pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1?distro=debian-12` with the component version 4.13+dfsg1-1,
  when it is matched, then its version is 1:4.13+dfsg1-1 and a record fixed at 1:4.13+dfsg1-1 does not report it;
  with `epoch=2` too, 1:4.13+dfsg1-1 with or without the component version, the package URL version first.
- (DEB-2) Given `pkg:deb/debian/zlib1g@1%3A1.3.dfsg-3?distro=debian-13`, with no `upstream`, when it is matched, then
  its name is `zlib1g` and its version `1:1.3.dfsg-3`.
- (DEB-2, DEB-3) Given `pkg:deb/debian/libc6@2.41-12%2Bb1?distro=debian-13&upstream=glibc%402.41-12`, a binNMU, when
  it is matched, then its name is `glibc` and its version `2.41-12`; with `upstream=glibc@`, its version is
  `2.41-12+b1`.

## Non-goals

- The packages of Debian derivatives (Ubuntu) and of other distributions (Alpine, RPM), and a Debian release named by
  its code name (`trixie`): each needs its own mapping to an OSV ecosystem.
- The ordering of Debian versions: `specs/version-ordering.md` states it.
- Naming, beside a source package component `cdxgen` adds (DEB-H3), the binary packages its evidence says it was
  built into: the advisory is reported under the component the SBOM lists.
