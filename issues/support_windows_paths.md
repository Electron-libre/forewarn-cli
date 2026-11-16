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
