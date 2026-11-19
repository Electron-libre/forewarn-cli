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
