//! What the end-to-end tests of the binary share: running it and writing an SBOM.

// `expect` would fail in the test crates that use every helper.
#![allow(dead_code, reason = "each test crate uses a part of the helpers")]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

/// The output of a run, its streams decoded.
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs the binary with `args`, `stdin` on its standard input.
pub fn run(args: &[&str], stdin: Option<&[u8]>) -> Run {
    run_with(args, stdin, &[])
}

/// Runs the binary with `args`, `stdin` on its standard input, each variable of `env` set, or removed when `None`.
pub fn run_with(args: &[&str], stdin: Option<&[u8]>, env: &[(&str, Option<&str>)]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_forewarn"));
    for (name, value) in env {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    let mut child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts");
    let mut input = child.stdin.take().expect("stdin is piped");
    if let Some(bytes) = stdin {
        // The command may exit before reading (a usage error): a broken pipe is not a failure of the test.
        let _ = input.write_all(bytes);
    }
    drop(input);
    let Output {
        status,
        stdout,
        stderr,
    } = child.wait_with_output().expect("the binary runs");
    Run {
        code: status.code().expect("the binary exits with a code"),
        stdout: String::from_utf8(stdout).expect("stdout is UTF-8"),
        stderr: String::from_utf8(stderr).expect("stderr is UTF-8"),
    }
}

/// A CycloneDX JSON SBOM of that spec version holding these components.
pub fn bom(spec_version: &str, components: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "components": components,
    }))
    .expect("the SBOM serializes")
}

/// The JSON report a run printed.
pub fn json_report(run: &Run) -> Value {
    serde_json::from_str(&run.stdout).unwrap_or_else(|e| panic!("{e}: {}", run.stdout))
}
