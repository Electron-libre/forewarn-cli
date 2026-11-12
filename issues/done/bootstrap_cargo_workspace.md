---
priority: high
why: 'every other issue of the milestone needs a workspace, and the project check fails until it exists'
---
# Bootstrap the Cargo workspace

# Goal
The repository has no code yet, so `just check` (`cargo fmt`, `cargo clippy -D warnings`, `cargo test`) fails. Create
a Cargo workspace laid out for the hexagonal architecture of `CLAUDE.md`, with the license and lint policy inherited by
every crate, so that `just check` passes on an empty but buildable skeleton.

# Findings
* No `Cargo.toml` exists; `CLAUDE.md` ("Project status") states the project check fails until the workspace exists.
* `.claude/cardinal.toml` lists the commit scopes `cli`, `sbom`, `matching`, `feeds`, `report`: a hint of the expected
  crates or areas.

# Approach
1. Root `Cargo.toml` with `[workspace.package]` (`license = "MIT OR Apache-2.0"`, edition, repository) and
   `[workspace.lints.clippy] pedantic = { level = "deny", priority = -1 }`.
2. Candidate crates, to settle at step 1 of `issue-workflow`:
   - a domain crate (components, completeness rules, later matching and deadlines), with no I/O dependency;
   - a CycloneDX adapter crate (parsing into domain types);
   - the `rollcall` binary crate (CLI, wiring the adapters).
   Fewer crates with modules is an option while the domain is small; the constraint is that the domain never depends
   on an adapter.
3. Each crate: `license.workspace = true`, `[lints] workspace = true`, a placeholder test so `cargo test` runs.
4. A CI workflow running `just check` is optional here; it can be its own issue.

# Milestone
Read and check an SBOM

# Resources
* `CLAUDE.md`: hexagonal architecture, license, lint policy.
* `.claude/cardinal.toml`: `check_command`, `commit_scopes`.

# Hints
* Public repository: the crates shared with the hosted service (matching, CycloneDX handling, API types) must be
  usable without the CLI, so keep them free of CLI dependencies.
* Silence a pedantic lint only locally with `#[expect(clippy::<lint>, reason = "...")]`.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-12

## Understanding
A buildable workspace skeleton, laid out hexagonally, with the license and the pedantic lints inherited by every crate,
so that `just check` passes. No SBOM parsing nor CLI argument yet (later issues).

## Plan
1. [x] Workspace skeleton: root `Cargo.toml` (`[workspace.package]`, `[workspace.lints.clippy]`), three crates under
   `crates/` (domain, CycloneDX adapter, CLI binary printing its version), a placeholder test per crate, the crate
   layout ADR; verified by `cardinal run project-check` and a test asserting each manifest inherits the license and
   the lints. (autonomous)

2. [x] Review fixes of the whole issue: the policy test lists the members through `cargo metadata` (globs), reads
   the manifests without panicking before its message, and checks that the domain depends on no workspace crate; ADR
   0001 and `CLAUDE.md` (check command) corrected; verified by `cardinal run project-check` and the new test failing
   on a domain → adapter dependency. (autonomous)

## Deliverable 1 summary
- done: workspace with `rollcall-domain`, `rollcall-cyclonedx`, `rollcall` (empty), license and pedantic lints
  inherited, `clippy.toml` accepting `CycloneDX` in doc comments, `.gitignore`, ADR 0001, `CLAUDE.md` layout, scope
  `domain`.
- red: none (no spec); the policy test failed first with `crates/rollcall/Cargo.toml: [lints] workspace = true is
  missing`.
- Code review: no findings
- not verified: no CI job runs `cargo` yet (`.github/workflows/cardinal.yml` runs the Cardinal checks only).

## Deliverable 2 summary
- done: fixes of the `high` review (5 of 6 findings).
- red: none (no spec); the new test failed first with `rollcall-domain depends on rollcall-cyclonedx in
  [dependencies]: the domain must not depend on an adapter` on a temporary manifest.
- Code review: no findings
- High review of the issue: 6 findings. Fixed: indexing panics, glob members, unchecked dependency direction, wrong
  check command in `CLAUDE.md`. Not fixed: the plan named a version print and a placeholder test per crate; dropped,
  since a CLI behaviour needs a spec and an empty test proves nothing (the policy test runs instead). Not fixed:
  `rust-version = "1.85"` is not verified by any check; follow-up below.
- not verified: the MSRV 1.85 (no 1.85 toolchain run).

## Follow-ups
- Verify the declared `rust-version` in CI (`cargo +1.85 check` or `cargo msrv verify`), with a CI job running
  `just check`.

## Decisions
- Mode: autonomous
- Base commit: 6ddff02c0f49bfe376b6ff298063d8e0d2f364d6
- Package names: `publish = false` and provisional names (`rollcall`, `rollcall-domain`, `rollcall-cyclonedx`); the
  names `rollcall`, `rollcall-cli` and `rollcall-core` are taken on crates.io by another CRA SBOM project, to settle
  before the first publication.
- Product name conflict: a separate issue (choose a distinct product name).
