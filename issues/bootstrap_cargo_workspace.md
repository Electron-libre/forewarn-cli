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
