---
priority: medium
why: 'the system packages of a container image (glibc, OpenSSL, zlib) get no verdict, though image scanners list them'
---
# Match the Debian packages of an SBOM

# Goal
An SBOM written by an image scanner (Syft, Trivy) lists the Debian packages of the image as
`pkg:deb/debian/<name>@<version>?arch=<arch>&distro=debian-<release>[&upstream=<source>]`. `forewarn match` reports
them "Not evaluated", reason `unknown ecosystem` (VMT-4), so an actively exploited vulnerability of glibc or OpenSSL in
a vendor's image raises nothing. Have them matched against the Debian advisories of OSV.

# Findings
* 2026-11-19, forewarn 0.5.0 on the Syft SBOM of a `gcr.io/distroless/cc-debian13` image: 14 components
  `pkg:deb/debian/…?distro=debian-13.7` reported `unknown ecosystem`, among them
  `pkg:deb/debian/libc6@2.41-12%2Bdeb13u4?arch=amd64&distro=debian-13.7&upstream=glibc`,
  `pkg:deb/debian/libssl3t64@3.5.7-1~deb13u3?arch=amd64&distro=debian-13.7&upstream=openssl` and
  `pkg:deb/debian/zlib1g@1%3A1.3.dfsg%2Breally1.3.1-1%2Bdeb13u1?…&upstream=zlib` (an epoch); 5 of 14 carry no
  `upstream=` (their source package has their name).
* OSV publishes the Debian advisories (DSA, DLA, DEBIAN-CVE) under the ecosystems `Debian:<release>` (e.g.
  `Debian:13`), keyed by **source** package, with `ECOSYSTEM` ranges in Debian version order.

# Approach
1. VMT-4: map the type `deb` with namespace `debian` to `Debian:<major>`, `<major>` taken from the `distro` qualifier
   (`debian-13.7` → `13`); without a `distro` qualifier, a new reason (the release is unknown) rather than a guess.
2. Name the package by its source: the `upstream=` qualifier when present (its version part, `upstream=glibc@2.41-12`,
   dropped), the binary name otherwise.
3. A `Scheme` of `crates/forewarn-domain/src/version.rs` for the Debian ordering (epoch, upstream version, revision;
   `~` sorts before everything, letters before non-letters), and its row in the `ECOSYSTEMS` table.
4. The archive and API fetching follow from the ecosystem name; check the `:` of `Debian:13` in the cache path and the
   archive URL.

# Specs
* `specs/vulnerability-matching.md`: VMT-4 amended (the `deb` row, the `distro` and `upstream` qualifiers), the new
  reason; `specs/version-ordering.md`: the Debian ordering.

# Resources
* `crates/forewarn-domain/src/matching.rs`: `ComponentPackage::of`, the `ECOSYSTEMS` table.
* `crates/forewarn-domain/tests/component_package.rs`, `crates/forewarn-domain/tests/version_ordering.rs`.
* Debian Policy 5.6.12 (the version ordering), the package URL specification of the `deb` type.

# Hints
* A binary package built from a source of another version (binNMU, `+b1`) keeps the source version in `upstream=`
  only when the scanner writes it; match on the binary version otherwise.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
Match the `pkg:deb/debian/…` components of an image SBOM against the OSV `Debian:<release>` advisories: release from
`distro`, source package and version from `upstream`, the dpkg version ordering, the `:` of the ecosystem name in
the archive URL and the cache directory. Ubuntu and other distributions, and code names (`trixie`), stay out.

## Plan
1. [x] Match `deb` components: the Debian ordering (`Scheme::Debian` in `version/debian.rs`, `version.rs` already
   over the file size limit), the `distro` and `upstream` qualifiers read (`purl.rs`), the `deb` mapping in a module
   of its own (`debian.rs`, `matching.rs` near the limit), `ComponentPackage::ecosystem` a `String`, the index and the
   reason `unknown release` (domain, report text, user guide); verified by `tests/version_ordering.rs`,
   `tests/component_package.rs` and a `forewarn match --osv` test through the binary; makes true VMT-4, VMT-5, VMT-7,
   VMT-10, VMT-32, VMT-33, VMT-34, VOR-1, VOR-7, the reason of MCH (cli-match table). (autonomous)
2. [x] Fetch `Debian:13`: `:` accepted (OSF-17), written `%3A` in the URL (OSF-14) and in the cache directory
   (OSF-21); verified by `forewarn-osv/tests/fetching.rs` (a fake server) and a `forewarn match` test reading the
   cached archive; makes true OSF-14, OSF-17, OSF-21. (autonomous)
3. [x] Fixes of the `high` review: the `upstream` of an OSV record read as aliases (Debian advisories name their CVE
   only there), the releases before 7 named `Debian:<major>.<minor>` as OSV names them, a `distro` or `upstream` that
   does not decode reported invalid, the doc of `Cache::fetch`; verified by `forewarn-osv/tests/reading.rs`,
   `tests/component_package.rs`, `tests/debian.rs`; makes true OSR-42, VMT-32, VMT-35. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 0408e7d04dcb670476b6b40f0feb46e3f5b0db60
- The version of `upstream=<source>@<version>` is matched when present (the issue's hint): OSV's Debian ranges are
  source versions, and a binary of another version (binNMU, `gcc-defaults`) would be compared out of place.
- `:` written `%3A` in the cache directory name, not dropped or replaced: injective, and a valid name on Windows.
- 2026-11-19: the ordering and the mapping make one deliverable (planned as 1 and 2): the ordering is only
  observable through the matching of a `deb` component, which needs the mapping.
- 2026-11-19, `high` review findings left out (the user's answer `1 a, 2 a`): Trivy SBOMs go to
  `issues/done/match_the_debian_packages_of_a_trivy_sbom.md`, a release with no OSV archive to
  `issues/done/keep_a_debian_release_without_an_osv_archive_out.md`.
- No ADR: the mapping extends the VMT-4 table, no new boundary.

## Deliverable 1: match `deb` components

done: `pkg:deb/debian/…` matched under `Debian:<release>` (from `distro`), named by the source package and its
version (from `upstream`), versions in the dpkg ordering (`version/debian.rs`); a `deb` package URL with no release
is not evaluated, `unknown release`; `ComponentPackage::ecosystem` is a `String`, `Archives::fetch` takes any string
slice list.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clippy pedantic clean |
| specs | VMT, VOR, MCH accepted, `check-specs` clean |
| docs | user guide, `CLAUDE.md`, `docs/architecture.md` |
| code review | see below |

red: VMT-4, VMT-5, VMT-6, VMT-7, VMT-9, VMT-10, VMT-32, VMT-33, VMT-34, VMT-H4, VOR-1, VOR-7: `no variant named
UnknownRelease found for enum ComponentReason` (the tests did not compile before the code).

Code review: no findings

not verified: a real Syft SBOM against the OSV `Debian:13` archive (deliverable 2 fetches it).

decisions needed: none.

## Deliverable 2: fetch `Debian:13`

done: an ecosystem name may hold `:` (not first); it is written `%3A` in the archive URL and in the name of its cache
entry (`forewarn-cache` accepts `%` in an entry name); `forewarn match` on a Debian image fetches
`Debian%3A13/all.zip`.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clippy pedantic clean |
| specs | OSF accepted, `check-specs` clean |
| docs | user guide (download URL, cache contents) |
| code review | see below |

red: OSF-14, OSF-17, OSF-21: `the ecosystem is fetched: FetchError { ecosystem: "Debian:13", cause: InvalidName }`.

`crates/forewarn/tests/fetching.rs` (over the file size limit) takes one more test of 15 lines: its `Mirror` lives
there; moving it to `tests/common` is a refactor of its own.

Code review: no findings

not verified: the real OSV bucket serving `Debian%3A13/all.zip` (no test reaches the network).

decisions needed: none.

## Deliverable 3: fixes of the `high` review

done: the `upstream` ids of an OSV record read as aliases after its `aliases` (OSV's Debian advisories name their CVE
only there: `DSA-5724-1`, `DEBIAN-CVE-2024-6387`, checked on api.osv.dev); the releases before 7 named
`Debian:<major>.<minor>` (OSV publishes `Debian:3.0` to `Debian:6.0`, checked on the bucket); a `distro` or
`upstream` that does not decode reported invalid package URL; the doc of `Cache::fetch` names `%`.

| check | result |
|---|---|
| tests | `cardinal run project-check` passes |
| lint | clippy pedantic clean |
| specs | VMT, OSR accepted, `check-specs` clean |
| docs | user guide (advisories under their CVE) |
| code review | see below |

red: OSR-42: `forewarn match` exited 1 instead of 6 on a DSA naming a KEV CVE in `upstream`; VMT-32, VMT-35:
`pkg:deb/debian/libc6@2.11.3-4?distro=debian-6` gave `Ok(… "Debian:6" …)`, `upstream=openssl%4` gave `Ok(…)`.

`high` review findings left to the user: Trivy SBOMs (no `upstream` qualifier, the source in properties) and the
release OSV publishes no archive of (`Debian:14`, 404, fails the run).

Code review: no findings

not verified: a real Syft SBOM against the real `Debian:13` archive.

decisions needed: Trivy SBOMs; a release with no OSV archive (see above).

Done: the three deliverables are committed; what remains is in the two issues named in `## Decisions`.
