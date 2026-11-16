# Which documents to update after a change

Read by `skill:update-docs`. Owned by the project: one row per kind of change, with the documents that describe it.

| Change | Update |
|---|---|
| New or changed command, flag or option | `README.md`, `CLAUDE.md` |
| New crate or module | `CLAUDE.md` (its layout table is the architecture), `commit_scopes` in `.claude/cardinal.toml` |
| Third-party data vendored or its version changed | its license file next to it, the License section of `CLAUDE.md` |
