# 0001. Workspace crate layout

- Status: accepted
- Date: 2026-11-12

## Context

`rollcall` must keep its domain (matching, completeness, reporting deadlines) apart from its adapters (CycloneDX
parsing, vulnerability feeds, report formats, HTTP upload), so that a change of regulatory format only touches an
adapter. A hosted service, kept elsewhere, may reuse the domain and the CycloneDX handling, never the reverse.

## Decision

One Cargo workspace with crates under `crates/`:

- a domain crate: domain types and rules, no I/O dependency;
- a CycloneDX adapter crate: parses an SBOM into domain types, depends on the domain crate;
- the CLI binary crate `rollcall`: argument parsing and wiring, depends on the others.

Later adapters (feeds, report formats, upload) start as modules of a crate and become crates when another consumer
needs them alone. The domain crate never depends on an adapter crate.

## Consequences

- The hosted service can depend on the domain and adapter crates without the CLI.
- The dependency direction is checked: `crates/rollcall/tests/workspace_policy.rs` fails when the domain crate
  depends on another crate of the workspace, so an adapter type cannot leak into the domain. Third-party I/O
  dependencies of the domain are left to review.
- More manifests to keep in step; the workspace inheritance (`license.workspace`, `[lints] workspace`) keeps them short.
