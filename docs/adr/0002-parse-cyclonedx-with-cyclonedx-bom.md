# 0002. Parse CycloneDX with the `cyclonedx-bom` crate

- Status: accepted
- Date: 2026-11-12

## Context

`rollcall` reads CycloneDX JSON SBOMs of spec versions 1.6 and 1.7, and accepts older ones with a flag. Writing a
`serde` model of the subset of fields the domain needs is possible, but each spec version and each later field (VEX,
services, `metadata.component`) would grow it. The CycloneDX project maintains a Rust model, `cyclonedx-bom`, in the
`cyclonedx-rust-cargo` repository.

Measured on version 0.9.0:

- it parses spec versions 1.3, 1.4, 1.5, 1.6 and 1.7 (JSON and XML), reading `specVersion` first, and refuses older
  versions as unsupported;
- it tolerates fields it does not know and keeps unknown enumeration values (a hash algorithm, for instance);
- it parses the output of `cargo-cyclonedx` 0.5.10 and `syft` 1.57 in CycloneDX 1.6, and of `cdxgen` 13.2 in
  CycloneDX 1.7;
- it is licensed `Apache-2.0`, and every crate it pulls in is permissive (`MIT`, `Apache-2.0`, `MIT-0`, `Unlicense`,
  `Unicode-3.0`, or a choice including one of them);
- it requires Rust 1.86.

## Decision

The CycloneDX adapter crate parses with `cyclonedx-bom` and maps its model to the types of the domain; no type of
`cyclonedx-bom` crosses into the domain or the CLI. The adapter checks `bomFormat` and `specVersion` itself before
the full parse, so that a wrong file or an unsupported version is reported as such rather than as a parse error.

## Consequences

- New spec versions come with an upgrade of the crate rather than a model of our own.
- The minimum Rust version of the workspace rises from 1.85 to 1.86.
- XML input is a later, small step: the crate already parses it.
- The crate is pre-1.0: an upgrade may change its model; the mapping in the adapter absorbs it.
- A malformed field anywhere in the document fails the whole parse, even in a part the domain does not read.
