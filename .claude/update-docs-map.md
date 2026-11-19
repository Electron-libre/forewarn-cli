# Which documents to update after a change

Read by `skill:update-docs`. Owned by the project: one row per kind of change, with the documents that describe it.

| Change | Update |
|---|---|
| New or changed command, flag, option, report field or exit code | `docs/user-guide.md`, `CLAUDE.md`; `README.md` only when its example or quick start changes |
| New crate or module, or a changed boundary or flow | `docs/architecture.md`, the layout table of `CLAUDE.md`, `commit_scopes` in `.claude/cardinal.toml` |
| New ADR | its row in the Decisions table of `docs/architecture.md` |
| Third-party data vendored or its version changed | its license file next to it, the License section of `CLAUDE.md` |
| Release process or version handling (`set-version`, `release_version_command`) | `CLAUDE.md` (the project check paragraph); `docs/user-guide.md` (Install) when what `--version` prints changes |
| Dependency policy (`deny.toml`, an allowed license, an ignored advisory) | the License section of `CLAUDE.md`; `about.toml` for a license (a test keeps the two lists equal) |
| A CI template of `examples/ci/` added or changed | `docs/user-guide.md` (In CI), the pointer of `README.md`, `CLAUDE.md` (the paragraph of the templates) |
