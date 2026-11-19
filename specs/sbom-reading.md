---
id: SBR
status: accepted
adrs: [0001, 0002, 0014]
---

# SBOM reading

## Intent

Read a CycloneDX JSON SBOM, produced by an existing tool, into the components of the domain, and tell whether its
spec version meets the BSI TR-03183-2 minimum (1.6), and the product the SBOM describes, so that the completeness
check and the matching work on the components and a report names the product.

## Requirements

### Behaviour

- **SBR-1** (deterministic) Reading a CycloneDX JSON SBOM of spec version 1.6 or 1.7 must return its components and
  its spec version, with no outdated flag.
- **SBR-2** (deterministic) Reading a CycloneDX JSON SBOM of spec version 1.3, 1.4 or 1.5 must return its components
  with its spec version flagged as below the BSI TR-03183-2 minimum.
- **SBR-3** (deterministic) Reading an input that is not a readable CycloneDX JSON SBOM must fail with an error that
  names the cause, from the table of SBR-7.
- **SBR-4** (deterministic) The SBOMs produced by `cargo-cyclonedx`, `syft`, `cdxgen` and `trivy` must be read without
  error.
- **SBR-9** (deterministic) Reading a CycloneDX JSON SBOM must return the product it describes, its name, version,
  package URL, manufacturer and supplier, when the SBOM has a `metadata.component`, and no product, with no error,
  when it has none.

### Contract

- **SBR-5** (deterministic) Each component read must carry the fields of this table, taken from the CycloneDX
  component as stated, an absent CycloneDX field giving an absent or empty domain field.

  | Domain field | CycloneDX source |
  |---|---|
  | name | `name` |
  | version | `version` |
  | package URL | `purl`, as written |
  | supplier | the identity of `supplier`, as below |
  | manufacturer | the identity of `manufacturer` (1.6), as below |
  | authors | `author` when present, then the identity of each entry of `authors` (1.6) that has one, as below |
  | publisher | `publisher` |
  | licenses | each entry of `licenses`: the SPDX id or the name of a `license`, or the text of an `expression` |
  | hashes | each entry of `hashes`: the algorithm as written and the value |

  The identity of an organization (`supplier`, `manufacturer`) is the first that is not empty nor only whitespace of
  its `name`, the `email` of each of its `contact` in order, then each of its `url` in order; that of an author (an
  entry of `authors`) is the first such of its `name` and its `email`. An entry with none of them has no identity.

- **SBR-6** (deterministic) The components nested in a component (`components[].components`, at any depth) must be
  returned in the same flat list as the top-level ones, in document order, each parent before its children.
- **SBR-7** (deterministic) A refused input must fail with the error of this table, the first cause that applies in
  table order, its message quoting the offending value when there is one.

  | Cause | Error |
  |---|---|
  | the input cannot be read (an I/O error) | cannot read the input, with the system's reason |
  | the input is not JSON | not JSON |
  | `bomFormat` is absent or is not `CycloneDX` | not a CycloneDX SBOM |
  | `specVersion` is absent or is not a string | missing spec version |
  | `specVersion` is not 1.3, 1.4, 1.5, 1.6 or 1.7 | unsupported spec version, quoting it |
  | the document does not match its spec version | invalid SBOM, with the parser's reason |

- **SBR-8** (deterministic) Reading must not refuse nor drop a component whose type or hash algorithm is a value the
  CycloneDX enumerations do not list.

- **SBR-10** (deterministic) withdrawn: replaced by SBR-12, which takes the manufacturer and the supplier of the
  product by their name only, a contact email or a URL not being a name.

- **SBR-11** (deterministic) Reading must not add `metadata.component` to the components of SBR-1, SBR-2 and SBR-6;
  a component of `components` that describes the same product stays among them.
- **SBR-12** (deterministic) The product must carry the fields of this table, a name being the `name` of an
  organization not made only of white space, an organization without one giving no name, and an absent CycloneDX field
  giving an absent domain field.

  | Domain field | CycloneDX source |
  |---|---|
  | name | `metadata.component.name` |
  | version | `metadata.component.version` |
  | package URL | `metadata.component.purl`, as written |
  | manufacturer | the first name of `metadata.component.manufacturer` (1.6), then `metadata.manufacture` (deprecated in 1.6) |
  | supplier | the first name of `metadata.supplier`, then `metadata.component.supplier` |

- **SBR-13** (deterministic) The components nested in the product (`metadata.component.components`, at any depth)
  must be returned in the same flat list, after those of SBR-6, in document order, each parent before its children;
  skipped, its own nested components still read: one whose `bom-ref`, not empty nor only whitespace, is that of a
  component already returned, and a target of the product, whose package URL is that of the product once the
  qualifiers (`?`) and the subpath (`#`) of both are removed.
- **SBR-14** (deterministic) Each component read must say whether it is first-party, the vendor's own code: one
  whose package URL names the package of the product's (the same type, namespace, name and version, read by the
  package URL specification, its qualifiers and subpath ignored), and one returned from the components nested in the
  product (SBR-13) whose package URL has the type and the namespace of the product's, two without a namespace having
  the same; every other component, and each one when the product has no valid package URL, is not first-party.
- **SBR-15** (deterministic) Each component read must say whether it is a file, a component of CycloneDX type `file`
  (a manifest or lock file a tool read, such as `/Cargo.lock`), the type compared as written; a component of any other
  type, or of a type the enumeration does not list, is not a file.
- **SBR-16** (deterministic) Each component read must carry its `bom-ref` as written, none when it has none, so that a
  verdict can name it (`specs/vex-verdicts.md`, VEX-7).
- **SBR-17** (deterministic) Each component read must carry the source package it was built from, when its
  properties name one as `trivy` writes them: the name the value of the property `aquasecurity:trivy:SrcName`, the
  version `<epoch>:<version>-<release>` of the values of `aquasecurity:trivy:SrcEpoch`, `SrcVersion` and `SrcRelease`
  (same prefix), `<epoch>:` left out when the epoch is absent or `0`, `-<release>` when the release is absent, and no
  version when `SrcVersion` is absent; a value only whitespace counts as absent, each value is taken trimmed, the first
  property of a name when it is repeated. A component without `SrcName` has no source package.

## Scenarios

- **SBR-H1** (happy; SBR-1, SBR-4, SBR-5) Given an SBOM a vendor generated with `syft` in CycloneDX 1.6, when
  `forewarn` reads it, then it gets every component with the name, version, package URL and hashes `syft` wrote, and
  spec version 1.6 with no flag.
- **SBR-H2** (happy; SBR-2) Given an SBOM in CycloneDX 1.5, when `forewarn` reads it, then it gets its components and
  the warning that 1.5 is below the BSI TR-03183-2 minimum.
- **SBR-H3** (happy; SBR-9, SBR-4) Given an SBOM a vendor generated with `syft` for their product
  `rollcall-fixture-sample` 0.1.0, when `forewarn` reads it, then it gets the product `rollcall-fixture-sample` at
  version 0.1.0, with no manufacturer nor supplier since `syft` writes none.
- **SBR-H4** (happy; SBR-13, SBR-4) Given an SBOM a vendor generated with `cdxgen` for their Maven project of two
  modules, which `cdxgen` nests under the product, when `forewarn` reads it, then it gets the two modules after the
  libraries they depend on, so that they are checked and matched like them.
- **SBR-H5** (happy; SBR-14, SBR-4) Given the SBOM `cdxgen` generated for a Maven project of two modules, when
  `forewarn` reads it, then the two modules are first-party and the libraries they depend on are not.
- **SBR-H6** (happy; SBR-17, SBR-4) Given the SBOM `trivy` generated for the image `debian:bookworm-slim`, when
  `forewarn` reads it, then `libc6` 2.36-9+deb12u14 carries the source package `glibc` 2.36-9+deb12u14 and `login`
  1:4.13+dfsg1-1+deb12u2 the source package `shadow` 1:4.13+dfsg1-1+deb12u2.
- (SBR-7) Given a CycloneDX 1.2 JSON file, when it is read, then it fails with "unsupported spec version" quoting `1.2`.
- (SBR-7) Given a JSON file with `bomFormat` `CycloneDX` and no `specVersion`, when it is read, then it fails with
  "missing spec version".
- (SBR-7) Given an SPDX JSON document, when it is read, then it fails with "not a CycloneDX SBOM".
- (SBR-7) Given a 1.6 document whose `components` is a string, when it is read, then it fails with "invalid SBOM".
- (SBR-5) Given a component whose `supplier` has no name, the URL `https://example.com` and a contact with the email
  `sec@example.com`, when it is read, then its supplier is `sec@example.com`; with no email, it is the URL.
- (SBR-5) Given a component whose only entry of `authors` has an email and no name, when it is read, then its authors
  are that email; an entry with only a phone gives no author.
- (SBR-5) Given a component whose `supplier` name is `"  "` and that has a URL, when it is read, then its supplier is
  the URL.
- (SBR-5) Given a component with no supplier, no licenses and no hashes, when it is read, then it is returned with
  those fields absent or empty, not refused.
- (SBR-1) Given a valid 1.6 SBOM preceded by a UTF-8 byte-order mark, when it is read, then it is read as without it.
- (SBR-1) Given a valid 1.6 SBOM with no `components`, when it is read, then it returns an empty list.
- (SBR-9) Given a valid 1.6 SBOM with no `metadata`, or a `metadata` with no `component`, when it is read, then it
  returns its components and no product.
- (SBR-12) Given a 1.6 SBOM whose `metadata.manufacturer`, the organization that made the SBOM, is named
  `SBOM Service` and whose `metadata.component.manufacturer` is named `Acme`, when it is read, then the manufacturer
  of the product is `Acme`; with no `metadata.component.manufacturer`, it has none.
- (SBR-12) Given a 1.6 SBOM whose `metadata.component.manufacturer` is named `Acme` and whose `metadata.manufacture`
  is named `Other`, when it is read, then the manufacturer of the product is `Acme`.
- (SBR-12) Given a 1.5 SBOM whose `metadata.manufacture` is named `Acme`, when it is read, then the manufacturer of the
  product is `Acme`.
- (SBR-12) Given a 1.6 SBOM whose `metadata.component.manufacturer` has the name `"  "`, the URL
  `https://acme.example` and a contact with the email `security@acme.example`, when it is read, then the product has
  no manufacturer; with a `metadata.manufacture` named `Acme`, its manufacturer is `Acme`.
- (SBR-12) Given an SBOM whose `metadata.supplier` has only a contact email and whose `metadata.component.supplier` is
  named `Acme`, when it is read, then the supplier of the product is `Acme`.
- (SBR-12) Given an SBOM whose `metadata.supplier` is named `Acme` and whose `metadata.component.supplier` is named
  `Other`, when it is read, then the supplier of the product is `Acme`.
- (SBR-12) Given an SBOM with no `metadata.supplier` and a `metadata.component.supplier` named `Acme`, when it is read,
  then the supplier of the product is `Acme`.
- (SBR-13) Given an SBOM whose product nests a component whose `bom-ref` a top-level component carries, when it is
  read, then that component is returned once, at the top level; a component nested in the skipped one is still
  returned.
- (SBR-13) Given an SBOM whose product nests a component that nests another, when it is read, then both are returned
  after the top-level components, the parent first.
- (SBR-13) Given an SBOM `cargo-cyclonedx` generated, which nests the binary target of the product under it
  (`pkg:cargo/app@0.1.0?download_url=file://.#src/main.rs` under `pkg:cargo/app@0.1.0?download_url=file://.`), when it
  is read, then that target is not among the components, and the SBOM is complete when its dependencies are.
- (SBR-13) Given an SBOM whose product nests a component with no `bom-ref`, or two whose `bom-ref` is `""` or
  `"  "`, when it is read, then each is returned.
- (SBR-14) Given the SBOM `cdxgen` generated for a Cargo package, which also lists the product among its components
  (`pkg:cargo/rollcall-fixture-sample@0.1.0`), when it is read, then that component is first-party and its
  dependencies are not.
- (SBR-14) Given an SBOM whose product has the package URL `pkg:maven/acme/app@1.0?type=pom` and a top-level component
  `pkg:maven/acme/app@1.0?type=jar`, when it is read, then that component is first-party; `pkg:maven/acme/app@2.0` and
  `pkg:maven/acme/lib@1.0` are not.
- (SBR-14) Given an SBOM whose product `pkg:maven/org.acme/app@1.0` nests `pkg:maven/org.acme/mod-a@1.0` and a
  bundled `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`, when it is read, then `mod-a` is first-party and
  `log4j-core` is not, so that it is still matched.
- (SBR-14) Given an SBOM whose product has no package URL, or a blank or invalid one, when it is read, then no
  component is first-party, nested ones included, and a component with a blank package URL is not.
- (SBR-14) Given an SBOM whose product has the package URL `pkg:npm/%40acme/app@1.0` and a top-level component
  `pkg:npm/@acme/app@1.0`, when it is read, then that component is first-party.
- (SBR-14) Given an SBOM whose product nests a component whose `bom-ref` a top-level component carries, when it is
  read, then that component, returned at the top level, is not first-party.
- (SBR-15, SBR-4) Given the SBOM `syft` generated for a Cargo package, when it is read, then `/Cargo.lock` is a file
  and the libraries are not; the product, of type `file` in `metadata.component`, is still not among the components.
- (SBR-11) Given an SBOM that lists its product only in `metadata.component`, when it is read, then the product is
  not among its components; given one whose `components` also lists it (as `syft` and `cdxgen` do), it stays there
  once.

- (SBR-17) Given a component whose properties are `aquasecurity:trivy:SrcName` `bash`, `SrcVersion` `5.2.15` and
  `SrcEpoch` `0`, with no `SrcRelease`, when it is read, then it carries the source package `bash` 5.2.15.
- (SBR-17) Given a component whose properties name `SrcName` `pam` and no `SrcVersion`, when it is read, then it
  carries the source package `pam` with no version; given one with `SrcVersion` and no `SrcName`, or `SrcName` only
  whitespace, it carries none.

## Non-goals

- XML or Protobuf input.
- SPDX input, or converting another format to CycloneDX.
- Detecting dependencies: the input is always an SBOM produced by another tool.
- Validating the SBOM against the CycloneDX JSON schema beyond what parsing needs.
- The licenses, hashes and authors of the product, and the other fields of `metadata` (authors, tools, lifecycles):
  nothing uses them yet.
- The organization that made the SBOM (`metadata.manufacturer` in 1.6): it is not the manufacturer of the product.
- Skipping a duplicate by anything but its `bom-ref` (its package URL, its name and version): two entries with
  different `bom-ref`s are two components.
- Services and dependencies: later milestones read them. VEX statements are read by `specs/vex-verdicts.md`.
- Deciding whether an SBOM without a product, or a product without a manufacturer, is incomplete for the CRA.
- The contacts and URLs of the manufacturer and the supplier of the product: nothing uses them yet, and a draft early
  warning has no field for them (ADR 0012). A component keeps its organization's email or URL (SBR-5).
- Deciding whether a field counts as present for the CRA: the completeness check (`specs/sbom-completeness.md`) does.
- Telling first-party code by a `file://` download URL (`cargo-cyclonedx` writes one for a path dependency, which may
  be a vendored copy of a published package), the group of the product, the `scope` or a property of a tool
  (`cdx:cargo:sourceKind`): only the place in the SBOM and the package URL of the product are read. The matching keeps
  a component pointing to a local path out under a reason of its own (`specs/vulnerability-matching.md`, VMT-31).
- Telling a component bundled in the product from a module of it when their package URLs share the type and have no
  namespace (a Cargo product nesting a vendored crate): the SBOM gives nothing else to tell them apart.
- Reading the file from disk or standard input: the command line does.
- The source package other tools may write in their own properties, and the other properties of `trivy` (its layers,
  its package id): only the source package the matching needs is read (SBR-17).
