//! The GitHub Actions template of `examples/ci/` run as a vendor's job would run it: the `run:` block of each of its
//! steps, with `bash -e` as GitHub runs it, in the directory of a product, against the binary of this commit, a fixture
//! SBOM and local feeds, so a change of the CLI or of the template that breaks the job turns this test red. The steps
//! that use an action (checkout, cache, artifact, the download of `syft`) are GitHub's, not run here; nothing is
//! fetched.
#![cfg(unix)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Run, run_command};
use serde_json::Value;
use tempfile::TempDir;

const TEMPLATE: &str = "examples/ci/github-actions.yml";

/// The steps run as the template writes them, but for the feeds of `forewarn match` and the dry run of the upload.
const CHECK_OUT: &str = "Check out the release";
const CHECK: &str = "Check the SBOM";
const MATCH: &str = "Match the SBOM against the vulnerabilities";
const UPLOAD: &str = "Upload the SBOM of the release";

/// The steps replaced: the binary of this commit is put on `PATH` instead of a release, and a fixture SBOM is copied
/// instead of the one `syft` would write.
const INSTALL: &str = "Install forewarn, checked against the SHA256SUMS of its release";
const PRODUCE_SBOM: &str = "Produce the SBOM";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn fixture(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

/// The indentation of a line, in spaces.
fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// A step of the template that runs a shell block.
#[derive(Default)]
struct TemplateStep {
    /// Its `run:` block, dedented.
    run: String,
    /// Its keys (`name`, `if`, `env`, `run`…).
    keys: BTreeSet<String>,
    /// The variables of its `env:`.
    env: BTreeSet<String>,
}

/// The `run:` block of a step that starts after line `i`: a literal block (`|`, `|-`, `|+`) dedented, or the
/// `value` of `run: <command>`; `i` moves past the block. A step's keys are indented to `keys`.
fn run_block(lines: &[&str], i: &mut usize, keys: usize, value: &str) -> String {
    let value = value.trim();
    if !matches!(value, "|" | "|-" | "|+") {
        assert!(
            !value.starts_with(['|', '>']),
            "{TEMPLATE}: a `run: {value}` block, read here as `|` only"
        );
        return format!("{value}\n");
    }
    let mut block = String::new();
    let mut body_indent = None;
    while *i < lines.len() && (lines[*i].trim().is_empty() || indent(lines[*i]) > keys) {
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

/// Each named step of the template that has a `run:`, by name. A step is an item of a `steps:` list; its keys are
/// indented two spaces past its dash, the variables of its `env:` two more.
fn run_steps(template: &str) -> BTreeMap<String, TemplateStep> {
    let lines: Vec<&str> = template.lines().collect();
    let mut found = BTreeMap::new();
    let mut step_indent = None;
    let mut current: Option<(Option<String>, TemplateStep)> = None;
    let mut in_env = false;
    let mut finish = |current: &mut Option<(Option<String>, TemplateStep)>| {
        if let Some((name, step)) = current.take()
            && step.keys.contains("run")
        {
            let name = name.unwrap_or_else(|| panic!("{TEMPLATE}: a `run:` step without a name"));
            found.insert(name, step);
        }
    };
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        i += 1;
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "steps:" {
            finish(&mut current);
            step_indent = Some(indent(line) + 2);
            continue;
        }
        let Some(dash) = step_indent else { continue };
        if indent(line) < dash {
            finish(&mut current);
            step_indent = None;
            continue;
        }
        let key = if indent(line) == dash && trimmed.starts_with("- ") {
            finish(&mut current);
            current = Some((None, TemplateStep::default()));
            &trimmed[2..]
        } else if indent(line) == dash + 2 {
            trimmed
        } else {
            if in_env
                && indent(line) == dash + 4
                && let (Some((_, step)), Some((variable, _))) =
                    (&mut current, trimmed.split_once(':'))
            {
                step.env.insert(variable.to_owned());
            }
            continue;
        };
        let (name, step) = current.as_mut().expect("a key belongs to a step");
        let (key, value) = key.split_once(':').unwrap_or((key, ""));
        step.keys.insert(key.to_owned());
        in_env = key == "env";
        match key {
            "name" => *name = Some(value.trim().to_owned()),
            "run" => step.run = run_block(&lines, &mut i, dash + 2, value),
            _ => {}
        }
    }
    finish(&mut current);
    found
}

/// Shell-quotes a path.
fn quoted(path: &Path) -> String {
    let text = path.to_str().expect("a UTF-8 path");
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The `forewarn <command>` line of `block` rewritten by `rewrite` (its tokens after the command); the block must run
/// that command once, on one line without quotes, so that no rewrite misses an argument.
fn rewritten(block: &str, command: &str, rewrite: impl Fn(Vec<&str>) -> Vec<String>) -> String {
    let prefix = format!("forewarn {command} ");
    let lines: Vec<&str> = block
        .lines()
        .filter(|line| line.contains(&prefix))
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "{TEMPLATE}: one `forewarn {command}` in:\n{block}"
    );
    let line = lines[0];
    assert!(
        !line.contains(['\'', '"', '\\']),
        "{TEMPLATE}: the line of `forewarn {command}` is rewritten word by word: {line}"
    );
    let (head, tail) = line.split_once(&prefix).expect("the line runs the command");
    let tokens = rewrite(tail.split_whitespace().collect());
    block.replace(line, &format!("{head}{prefix}{}", tokens.join(" ")))
}

/// The match of the template with the feeds given as files, so that nothing is fetched; its refresh policy is
/// dropped, as `forewarn` refuses one when nothing is fetched.
fn with_local_feeds(block: &str) -> String {
    rewritten(block, "match", |tokens| {
        let at = tokens
            .iter()
            .position(|token| *token == "--refresh" || token.starts_with("--refresh="))
            .unwrap_or_else(|| {
                panic!("{TEMPLATE}: the match gives a refresh policy, dropped here: {tokens:?}")
            });
        let refresh = if tokens[at] == "--refresh" {
            at..=at + 1
        } else {
            at..=at
        };
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
                .filter(|(i, _)| !refresh.contains(i))
                .map(|(_, token)| (*token).to_owned()),
        );
        args
    })
}

/// The upload of the template as a dry run: nothing sent, no token read.
fn as_dry_run(block: &str) -> String {
    rewritten(block, "upload", |tokens| {
        std::iter::once("--dry-run".to_owned())
            .chain(tokens.into_iter().map(str::to_owned))
            .collect()
    })
}

/// A run of the job: the trigger's variables of GitHub and the directory of the product.
struct Job {
    _scratch: TempDir,
    product: PathBuf,
    bin: PathBuf,
    home: PathBuf,
    output: PathBuf,
    env: Vec<(&'static str, String)>,
    steps: BTreeMap<String, TemplateStep>,
}

impl Job {
    fn new(env: &[(&'static str, &str)]) -> Self {
        let template = fs::read_to_string(fixture(TEMPLATE)).expect("the template is read");
        let scratch = TempDir::new().expect("a temporary directory");
        let product = scratch.path().join("acme-app");
        let bin = scratch.path().join("bin");
        let home = scratch.path().join("home");
        let output = scratch.path().join("github-output");
        for directory in [&product, &bin, &home] {
            fs::create_dir(directory).expect("a directory is created");
        }
        // The install step, replaced: the binary of this commit, first on `PATH`.
        symlink(env!("CARGO_BIN_EXE_forewarn"), bin.join("forewarn"))
            .expect("the binary is linked");
        Self {
            _scratch: scratch,
            product,
            bin,
            home,
            output,
            env: env
                .iter()
                .map(|(name, value)| (*name, (*value).to_owned()))
                .collect(),
            steps: run_steps(&template),
        }
    }

    /// A step of the template, as it writes it.
    fn template_step(&self, step: &str) -> &TemplateStep {
        self.steps
            .get(step)
            .unwrap_or_else(|| panic!("{TEMPLATE} has no step `{step}` with a `run:`"))
    }

    /// Runs `script` as GitHub runs a `run:` block that names no `shell:` on Linux (`bash -e {0}`, no `pipefail`), in
    /// the product, with the variables of the job and of the step only: none of the caller's (`GIT_DIR`, its Git
    /// configuration, `BASH_ENV`) reaches it.
    fn run(&self, script: &str, step_env: &[(&str, &str)]) -> Run {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("bash");
        command
            .env_clear()
            .current_dir(&self.product)
            .env("PATH", path)
            .env("HOME", &self.home)
            .env("XDG_CACHE_HOME", self.home.join(".cache"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GITHUB_OUTPUT", &self.output)
            .env("GITHUB_REPOSITORY", "acme/acme-app")
            .envs(self.env.iter().map(|(name, value)| (*name, value.as_str())));
        let env: Vec<(&str, Option<&str>)> = step_env
            .iter()
            .map(|(name, value)| (*name, Some(*value)))
            .collect();
        run_command(command, &["-e", "-c", script], None, &env)
    }

    /// Runs a step of the template, `rewrite` applied to its block, with a value for each variable of its `env:`, and
    /// expects its exit code.
    fn step(
        &self,
        step: &str,
        rewrite: impl Fn(&str) -> String,
        step_env: &[(&str, &str)],
        code: i32,
    ) -> Run {
        let template_step = self.template_step(step);
        assert_eq!(
            step_env
                .iter()
                .map(|(name, _)| (*name).to_owned())
                .collect::<BTreeSet<_>>(),
            template_step.env,
            "{TEMPLATE}: the variables of the step `{step}`"
        );
        let script = rewrite(&template_step.run);
        let ran = self.run(&script, step_env);
        assert_eq!(
            ran.code, code,
            "step `{step}`:\n{script}\nstdout:\n{}\nstderr:\n{}",
            ran.stdout, ran.stderr
        );
        ran
    }

    /// The outputs the steps wrote to `GITHUB_OUTPUT`, one `name=value` per line.
    fn outputs(&self) -> BTreeMap<String, String> {
        fs::read_to_string(&self.output)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                assert!(
                    !line.contains("<<"),
                    "a multiline output, read here as `name=value` only: {line}"
                );
                let (name, value) = line
                    .split_once('=')
                    .unwrap_or_else(|| panic!("an output `name=value`: {line}"));
                (name.to_owned(), value.to_owned())
            })
            .collect()
    }

    /// The SBOM step, replaced: the fixture SBOM where `syft` writes it.
    fn produce_sbom(&self, fixture_name: &str) {
        assert!(
            self.template_step(PRODUCE_SBOM)
                .run
                .contains("sbom.cdx.json"),
            "{TEMPLATE}: the SBOM step writes sbom.cdx.json"
        );
        fs::copy(
            fixture(&format!(
                "crates/forewarn/tests/fixtures/ci-template/{fixture_name}"
            )),
            self.product.join("sbom.cdx.json"),
        )
        .expect("the SBOM is copied");
    }

    fn git(&self, args: &[&str]) -> String {
        let ran = self.run(
            &format!(
                "git -c user.name=ci -c user.email=ci@example.invalid {}",
                args.join(" ")
            ),
            &[],
        );
        assert_eq!(ran.code, 0, "git {args:?}: {}", ran.stderr);
        ran.stdout.trim().to_owned()
    }

    fn report(&self) -> Value {
        let text =
            fs::read_to_string(self.product.join("forewarn.json")).expect("the report is written");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"))
    }
}

fn unchanged(block: &str) -> String {
    block.to_owned()
}

#[test]
fn the_test_runs_or_replaces_each_step_of_the_template_with_a_run() {
    let template = fs::read_to_string(fixture(TEMPLATE)).expect("the template is read");
    let found = run_steps(&template);
    // The steps run must run where and how this test runs them; the replaced ones are not run.
    for (name, step) in found
        .iter()
        .filter(|(name, _)| ![INSTALL, PRODUCE_SBOM].contains(&name.as_str()))
    {
        for key in ["shell", "working-directory"] {
            assert!(
                !step.keys.contains(key),
                "{TEMPLATE}: the step `{name}` gives a `{key}`, not run here"
            );
        }
    }
    let steps: BTreeSet<String> = found.into_keys().collect();
    assert_eq!(
        steps,
        BTreeSet::from([CHECK_OUT, INSTALL, PRODUCE_SBOM, CHECK, MATCH, UPLOAD].map(str::to_owned)),
        "{TEMPLATE}: a step this test neither runs nor replaces"
    );
}

#[test]
fn a_daily_run_checks_the_latest_tag_and_fails_on_an_actively_exploited_match() {
    let job = Job::new(&[
        ("GITHUB_REF_TYPE", "branch"),
        ("GITHUB_REF_NAME", "main"),
        ("GITHUB_SHA", "0000000000000000000000000000000000000000"),
    ]);
    job.git(&["init", "--quiet"]);
    fs::write(job.product.join("README"), "1.2.0\n").expect("written");
    job.git(&["add", "README"]);
    job.git(&["commit", "--quiet", "-m", "release"]);
    job.git(&["tag", "v1.2.0"]);
    let release = job.git(&["rev-parse", "HEAD"]);
    fs::write(job.product.join("README"), "next\n").expect("written");
    job.git(&["commit", "--quiet", "-am", "next"]);

    job.step(CHECK_OUT, unchanged, &[], 0);
    assert_eq!(
        job.git(&["rev-parse", "HEAD"]),
        release,
        "the latest tag is checked out"
    );
    let outputs = job.outputs();
    assert_eq!(outputs.get("name").map(String::as_str), Some("acme-app"));
    assert_eq!(outputs.get("version").map(String::as_str), Some("1.2.0"));

    job.produce_sbom("exploited.cdx.json");
    job.step(CHECK, unchanged, &[], 0);
    job.step(MATCH, with_local_feeds, &[], 6);

    let report = job.report();
    assert_eq!(report["exploitedCount"], 1, "{report}");
    assert!(
        job.product
            .join("drafts/acme-app-CVE-2021-44228.md")
            .is_file(),
        "the draft early warning of the exploited CVE is written"
    );
}

#[test]
fn a_tag_run_passes_on_a_match_not_exploited_and_uploads_the_sbom() {
    let job = Job::new(&[
        ("GITHUB_REF_TYPE", "tag"),
        ("GITHUB_REF_NAME", "v1.2.0"),
        ("GITHUB_SHA", "0000000000000000000000000000000000000000"),
    ]);

    job.step(CHECK_OUT, unchanged, &[], 0);
    assert_eq!(
        job.outputs().get("version").map(String::as_str),
        Some("1.2.0")
    );

    job.produce_sbom("affected.cdx.json");
    job.step(CHECK, unchanged, &[], 0);
    job.step(MATCH, with_local_feeds, &[], 0);
    let report = job.report();
    assert_eq!(report["exploitedCount"], 0, "{report}");
    assert!(
        !report["affected"].as_array().expect("an array").is_empty(),
        "time 0.1.43 is affected: {report}"
    );

    // A secret GitHub does not give (a pull request from a fork) is empty: the dry run reads no token.
    let upload = job.step(
        UPLOAD,
        as_dry_run,
        &[
            ("FOREWARN_ENDPOINT", "https://forewarn.example.invalid"),
            ("FOREWARN_TOKEN", ""),
        ],
        0,
    );
    assert!(
        upload.stdout.contains("acme-app 1.2.0"),
        "the upload names the product and version of the SBOM: {}",
        upload.stdout
    );
}
