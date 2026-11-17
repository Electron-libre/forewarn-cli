---
priority: medium
depends_on: [run_the_project_check_in_ci]
why: 'a Windows vendor reads doubled backslashes in every path the reports print; the CI tests Linux and macOS only until then'
---
# Print Windows paths as written and test on Windows in CI

# Goal
The CLI escapes each backslash of a printed value as `\\` (`crates/forewarn/src/escape.rs`), the paths included, so
that a value cannot forge an escape (`specs/cli-check.md`, `specs/cli-match.md`, MCH-23). On Windows the backslash is
the path separator: every path a report or an error prints (`--vex` files, `--osv` files, draft files) reads
`C:\\Users\\...`. Windows paths should read as written, without reopening the forgery the escape closes, and the
tests should run on Windows in CI.

# Findings
* 2026-11-16, at `33c1073`, found by the `high` review of `run_the_project_check_in_ci` (no Windows run yet: the
  cross build for Windows needs a MinGW compiler for `ring`).
* `escape.rs:8` doubles every backslash; paths go through it in `src/vex.rs:131`, `src/main.rs:512-513` and the
  draft lines of the human report.
* Tests that build the expected text from `path.display()` and would fail on Windows: `tests/vex.rs:282-283` and
  `:331`, `tests/matching.rs:95-96` and `:815`, `tests/exploited.rs:163`.
* Tests that create names Windows refuses, with no `#[cfg(unix)]`: `tests/drafts.rs:378` (a directory named with a
  newline, expected `/` separators), `tests/formatting_characters.rs:203` (a file named `a\nb.json` with a literal
  backslash).

# Approach
1. Decide how a path prints on Windows: leave the separator unescaped there (the escape of the other characters kept),
   or print paths with `/`; amend the requirements of the specs that state the backslash escape for paths.
2. Gate the two tests on names Windows refuses with `#[cfg(unix)]`; make the path tests build their expected text
   the way the CLI prints a path.
3. Add `windows-latest` back to the matrix of `.github/workflows/check.yml`, with
   `git config --global core.autocrlf false` before the checkout (the fixtures and expected reports are compared byte
   for byte).

# Specs
* `specs/cli-check.md`, `specs/cli-match.md` (MCH-18, MCH-23), `specs/cli-match-exploited.md` (MXL-35): the
  escape of the paths they print.

# Milestone
Beta

# Resources
* `crates/forewarn/src/escape.rs`, `.github/workflows/check.yml`.
* ADRs 0005 and 0007 (the file lock of the cache, which differs on Windows).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-17

## Understanding
A path the human report or an error line prints keeps the escape of the other characters, but on Windows its
backslashes, the separators, print as they are (CHK-16, MCH-43); the tests run on `windows-latest` in CI. Out of
scope: the JSON report (JSON escaping), the file lock of the cache unless the Windows run shows a failure there.

## Plan
1. [x] Paths printed as written on Windows: `escape::push_escaped_path` (backslash kept on Windows only), used for the
   paths of `report`, `vex`, `drafts::WriteError`, `unreadable` and the `ReadError`s of the OSV, KEV and EUVD adapters
   (the CLI prints their path and their cause apart); verified by an internal test of both platforms' rule, `#[cfg(windows)]`
   tests through the binary and a Unix one; makes true CHK-16, MCH-43, MXL-35, MXL-39. (autonomous)
2. [ ] Portable tests: `#[cfg(unix)]` on `tests/drafts.rs:378` and `tests/formatting_characters.rs:203`, the path tests
   (`tests/vex.rs`, `tests/matching.rs`, `tests/exploited.rs`) build their expected text with a helper printing a path
   as the CLI does; verified by `cargo test` on Linux and the Windows CI run.
3. [ ] `windows-latest` back in the matrix of `.github/workflows/check.yml`, `git config --global core.autocrlf false`
   before the checkout; verified by the Windows CI run.

## Decisions
- Mode: autonomous
- Base commit: 7411a7edb9f2ffef599dc8b40674237375dace9f
- Windows paths: their backslashes, the separators, print as they are, the other characters escaped (1 a).
- Verification on Windows: the agent pushes a branch to run the CI on Windows before the `high` review (2 a).

## Deliverable 1 summary
- done: paths printed by `escape::push_escaped_path` (backslashes as they are on Windows only) in the report, the VEX
  sources and the drafts; error lines naming a file built by the module `error_line` (path and cause apart, the
  adapters' `Cause` now `Display`); CHK-16, MCH-43 written, MXL-35 and MXL-39 point to MCH-43.
- red: CHK-16, MCH-43: `assertion left == right failed, left: "C:\\\\feeds\\\\a\\u{202e}\\n.json", right: "C:\\feeds\\a\\u{202e}\\n.json"`
- Code review: no findings
- not verified: the `#[cfg(windows)]` tests of `tests/paths.rs` (run once with `cfg(unix)` and `/` separators on
  Linux: pass), until the Windows CI run.

