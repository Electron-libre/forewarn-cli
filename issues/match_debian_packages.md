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
2. [ ] Fetch `Debian:13`: `:` accepted (OSF-17), written `%3A` in the URL (OSF-14) and in the cache directory
   (OSF-21); verified by `forewarn-osv/tests/fetching.rs` (a fake server) and a `forewarn match` test reading the
   cached archive; makes true OSF-14, OSF-17, OSF-21.

## Decisions
- Mode: autonomous
- Base commit: 0408e7d04dcb670476b6b40f0feb46e3f5b0db60
- The version of `upstream=<source>@<version>` is matched when present (the issue's hint): OSV's Debian ranges are
  source versions, and a binary of another version (binNMU, `gcc-defaults`) would be compared out of place.
- `:` written `%3A` in the cache directory name, not dropped or replaced: injective, and a valid name on Windows.
- 2026-11-19: the ordering and the mapping make one deliverable (planned as 1 and 2): the ordering is only
  observable through the matching of a `deb` component, which needs the mapping.
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
