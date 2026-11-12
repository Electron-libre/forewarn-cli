# 0003. An OSV adapter crate with its own `serde` model

- Status: proposed
- Date: 2026-11-12

## Context

The matching of the domain (`specs/vulnerability-matching.md`) works on vulnerabilities shaped after the OSV schema;
something must read OSV records into them. ADR 0001 lets a later adapter start as a module and become a crate when
another consumer needs it alone: the hosted service will read OSV records without the CLI, and the fetching of the
records (`issues/fetch_osv_records.md`) will grow this adapter with its own dependencies (HTTP, cache).

The domain reads a small subset of a record: `id`, `aliases`, `withdrawn`, and in `affected` the package, `versions`
and `ranges`. The `osv` crate, measured on version 0.3.0:

- follows OSV schema 1.7.4 (the records OSV serves on 2026-11-12 declare 1.9.0) and is licensed `Apache-2.0`;
- deserializes `affected[].package.ecosystem` into a closed enumeration: a record of an ecosystem it does not list
  (OSV adds ecosystems often) fails to parse, as a whole;
- parses `modified`, `published` and `withdrawn` as dates and refuses a record whose date it cannot read, although the
  domain needs none of them;
- pulls in `chrono` and `lazy-regex` for fields the domain does not read.

## Decision

A crate `forewarn-osv` (commit scope `feeds`) reads OSV records with a `serde` model of its own, limited to the fields
the domain needs, and maps it to the types of the domain; no type of the model leaves the crate. It depends on the
domain crate, `serde` and `serde_json`, never the reverse.

## Consequences

- A record of an ecosystem nobody here knows yet is still read; the matching decides what to do with it.
- A new field the domain needs is a field added to the model, not a crate upgrade.
- The model follows the schema by hand: a breaking schema change (a major version) is refused rather than misread.
- The fetching of the records joins this crate, keeping the domain free of I/O.
