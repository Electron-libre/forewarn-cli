//! What the runs of the CI templates of `examples/ci/` share: the fixtures, the rewrites of `forewarn match` (local
//! feeds) and `forewarn upload` (a dry run), and the directory of a product where the shell of a job runs, against the
//! binary of this commit, with the variables of the job only.

// `expect` would fail in the run that uses every helper.
#![allow(
    dead_code,
    reason = "each run of a template uses a part of the helpers"
)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

use crate::common::{Run, run_command};

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

/// A file of the workspace, `relative` to its root.
pub fn fixture(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

/// A file of the fixtures of the template runs, `tests/fixtures/ci-template/<name>`.
pub fn ci_fixture(name: &str) -> PathBuf {
    fixture(&format!(
        "crates/forewarn/tests/fixtures/ci-template/{name}"
    ))
}

/// The indentation of a line, in spaces.
pub fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// The body of a literal block (`|`) that starts at line `i`, under a key indented to `parent`: its lines indented
/// further, or empty, dedented; `i` moves past it.
pub fn literal_block(lines: &[&str], i: &mut usize, parent: usize) -> String {
    let mut block = String::new();
    let mut body_indent = None;
    while *i < lines.len() && (lines[*i].trim().is_empty() || indent(lines[*i]) > parent) {
        let body = lines[*i];
        if !body.trim().is_empty() {
            let start = *body_indent.get_or_insert(indent(body));
            block.push_str(body.get(start..).unwrap_or(""));
        }
        block.push('\n');
        *i += 1;
    }
    block
}

/// `block` with each line continued by a final `\\` joined to the next, as the shell reads it, so that a command
/// written over several lines is rewritten as one. The blocks of the templates end no line with a `\\` that is not
/// a continuation (in quotes or a here-document).
fn unfolded(block: &str) -> String {
    let mut joined = String::new();
    for line in block.lines() {
        if let Some(head) = line.strip_suffix('\\') {
            joined.push_str(head);
        } else {
            joined.push_str(line);
            joined.push('\n');
        }
    }
    joined
}

/// Shell-quotes a path.
pub fn quoted(path: &Path) -> String {
    let text = path.to_str().expect("a UTF-8 path");
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The `forewarn <command>` line of `block`, a shell block of `template` its continued lines joined, rewritten by
/// `rewrite` (its tokens after the command); the block must run that command once, without quotes, so that no
/// rewrite misses an argument.
fn rewritten(
    template: &str,
    block: &str,
    command: &str,
    rewrite: impl Fn(Vec<&str>) -> Vec<String>,
) -> String {
    let block = &unfolded(block);
    let prefix = format!("forewarn {command} ");
    let lines: Vec<&str> = block
        .lines()
        .filter(|line| line.contains(&prefix))
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "{template}: one `forewarn {command}` in:\n{block}"
    );
    let line = lines[0];
    assert!(
        !line.contains(['\'', '"', '\\']),
        "{template}: the line of `forewarn {command}` is rewritten word by word: {line}"
    );
    let (head, tail) = line.split_once(&prefix).expect("the line runs the command");
    let tokens = rewrite(tail.split_whitespace().collect());
    block.replace(line, &format!("{head}{prefix}{}", tokens.join(" ")))
}

/// The positions of `option` and its value in `tokens`, given as `option value` or `option=value`, if it is there.
fn option_at(tokens: &[&str], option: &str) -> Option<std::ops::RangeInclusive<usize>> {
    let at = tokens.iter().position(|token| {
        *token == option
            || token
                .strip_prefix(option)
                .is_some_and(|rest| rest.starts_with('='))
    })?;
    Some(if tokens[at] == option {
        at..=at + 1
    } else {
        at..=at
    })
}

/// The match of `block`, a shell block of `template`, with the feeds given as files, so that nothing is fetched; its
/// refresh policy and its cache directory, if it gives one, are dropped, as `forewarn` refuses them when nothing is
/// fetched; `cache_kept` is the directory the job keeps between runs, the one the match must give, if any.
pub fn with_local_feeds(template: &str, block: &str, cache_kept: Option<&str>) -> String {
    rewritten(template, block, "match", |tokens| {
        let refresh = option_at(&tokens, "--refresh").unwrap_or_else(|| {
            panic!("{template}: the match gives a refresh policy, dropped here: {tokens:?}")
        });
        let cache = option_at(&tokens, "--cache");
        let cache_given = cache.as_ref().map(|at| {
            let value = tokens[*at.end()];
            value.strip_prefix("--cache=").unwrap_or(value)
        });
        assert_eq!(
            cache_given.map(|dir| dir.trim_end_matches('/')),
            cache_kept.map(|dir| dir.trim_end_matches('/')),
            "{template}: the match caches the feeds where the job keeps them"
        );
        let mut args: Vec<String> = [
            ("--osv", "crates/forewarn-osv/tests/fixtures"),
            ("--osv", "crates/forewarn/tests/fixtures/ci-template/osv"),
            ("--kev", "crates/forewarn-exploited/tests/fixtures/kev.json"),
            (
                "--euvd",
                "crates/forewarn-exploited/tests/fixtures/euvd.json",
            ),
        ]
        .iter()
        .flat_map(|(option, path)| [(*option).to_owned(), quoted(&fixture(path))])
        .collect();
        args.extend(
            tokens
                .iter()
                .enumerate()
                .filter(|(i, _)| {
                    !refresh.contains(i) && !cache.as_ref().is_some_and(|cache| cache.contains(i))
                })
                .map(|(_, token)| (*token).to_owned()),
        );
        args
    })
}

/// The value of `--awareness` of the match of `block`, a shell block of `template`: the file of the moments of
/// awareness the job must keep between runs.
pub fn awareness_file(template: &str, block: &str) -> String {
    let block = unfolded(block);
    let line = block
        .lines()
        .find(|line| line.contains("forewarn match "))
        .unwrap_or_else(|| panic!("{template}: a `forewarn match` in:\n{block}"));
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let at = option_at(&tokens, "--awareness").unwrap_or_else(|| {
        panic!("{template}: the match remembers the moments of awareness: {line}")
    });
    let value = tokens[*at.end()];
    value
        .strip_prefix("--awareness=")
        .unwrap_or(value)
        .to_owned()
}

/// The moment of awareness `file` records for the product `acme-app` and `cve`, and the one the report of the match
/// gives its match of `cve`, which must be the same.
pub fn recorded_and_reported(file: &Path, report: &Value, cve: &str) -> String {
    let moments: Value = serde_json::from_str(
        &fs::read_to_string(file).unwrap_or_else(|e| panic!("{}: {e}", file.display())),
    )
    .expect("the file of moments is JSON");
    let recorded = moments["awareness"]
        .as_array()
        .expect("an array")
        .iter()
        .find(|entry| entry["product"] == "acme-app" && entry["cve"] == cve)
        .unwrap_or_else(|| panic!("{cve} of acme-app is recorded: {moments}"))["awareSince"]
        .as_str()
        .expect("a moment")
        .to_owned();
    let reported = report["affected"]
        .as_array()
        .expect("an array")
        .iter()
        .find(|found| found["exploited"][0]["cve"] == cve)
        .unwrap_or_else(|| panic!("{cve} is exploited: {report}"))["awareSince"]
        .clone();
    assert_eq!(reported, recorded.as_str(), "{report}");
    recorded
}

/// The upload of `block`, a shell block of `template`, as a dry run: nothing sent, no token read.
pub fn as_dry_run(template: &str, block: &str) -> String {
    rewritten(template, block, "upload", |tokens| {
        std::iter::once("--dry-run".to_owned())
            .chain(tokens.into_iter().map(str::to_owned))
            .collect()
    })
}

/// The directory of a product where a job runs, the binary of this commit first on its `PATH` in place of a release,
/// and the variables the CI gives the job.
pub struct Sandbox {
    scratch: TempDir,
    pub product: PathBuf,
    pub bin: PathBuf,
    home: PathBuf,
    env: Vec<(&'static str, String)>,
}

impl Sandbox {
    /// The product `acme-app`, empty, and `env`, the variables of the CI.
    pub fn new(env: &[(&'static str, &str)]) -> Self {
        let scratch = TempDir::new().expect("a temporary directory");
        let product = scratch.path().join("acme-app");
        let bin = scratch.path().join("bin");
        let home = scratch.path().join("home");
        for directory in [&product, &bin, &home] {
            fs::create_dir(directory).expect("a directory is created");
        }
        symlink(env!("CARGO_BIN_EXE_forewarn"), bin.join("forewarn"))
            .expect("the binary is linked");
        Self {
            scratch,
            product,
            bin,
            home,
            env: env
                .iter()
                .map(|(name, value)| (*name, (*value).to_owned()))
                .collect(),
        }
    }

    /// The `HOME` of the job, where `~` leads.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The directory that holds the product, for the files of the test around it.
    pub fn scratch(&self) -> &Path {
        self.scratch.path()
    }

    /// `program`, run in the product with the variables of the CI only: none of the caller's (`GIT_DIR`, its Git
    /// configuration, `BASH_ENV`, `ENV`) reaches it.
    pub fn command(&self, program: &str) -> Command {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new(program);
        command
            .env_clear()
            .current_dir(&self.product)
            .env("PATH", path)
            .env("HOME", &self.home)
            .env("XDG_CACHE_HOME", self.home.join(".cache"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .envs(self.env.iter().map(|(name, value)| (*name, value.as_str())));
        command
    }

    /// Runs `git` in the product, expects it to succeed and gives its output, trimmed.
    pub fn git(&self, args: &[&str]) -> String {
        let mut all = vec!["-c", "user.name=ci", "-c", "user.email=ci@example.invalid"];
        all.extend_from_slice(args);
        let ran: Run = run_command(self.command("git"), &all, None, &[]);
        assert_eq!(ran.code, 0, "git {args:?}: {}", ran.stderr);
        ran.stdout.trim().to_owned()
    }

    /// The product as a Git repository whose tag `v1.2.0` is followed by a commit, the commit of that tag given.
    pub fn tagged_release_and_a_commit_after(&self) -> String {
        self.git(&["init", "--quiet"]);
        fs::write(self.product.join("README"), "1.2.0\n").expect("written");
        self.git(&["add", "README"]);
        self.git(&["commit", "--quiet", "-m", "release"]);
        self.git(&["tag", "v1.2.0"]);
        let release = self.git(&["rev-parse", "HEAD"]);
        fs::write(self.product.join("README"), "next\n").expect("written");
        self.git(&["commit", "--quiet", "-am", "next"]);
        release
    }

    /// The JSON report the match wrote to `forewarn.json`.
    pub fn report(&self) -> Value {
        let text =
            fs::read_to_string(self.product.join("forewarn.json")).expect("the report is written");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"))
    }
}
