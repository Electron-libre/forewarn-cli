//! The `forewarn` command line: parses the arguments and wires the adapters to the domain (`specs/cli-check.md`).

mod report;

use std::fs::File;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use forewarn_cyclonedx::{ReadError, read_json};
use forewarn_domain::completeness::check;
use forewarn_domain::sbom::Sbom;

/// Check a CycloneDX SBOM for the fields the EU Cyber Resilience Act expects.
#[derive(Parser)]
#[command(version, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the spec version of an SBOM and the components missing a supplier, a license or a hash.
    Check(CheckArgs),
}

#[derive(Args)]
struct CheckArgs {
    /// The CycloneDX JSON SBOM to check, `-` for standard input (`./-` for a file named `-`).
    sbom: PathBuf,
    /// The format of the report.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
    /// Exit with 0 when components are incomplete, so that a CI job reports the gaps without failing.
    #[arg(long)]
    allow_incomplete: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// Text for a person at a terminal.
    Human,
    /// One JSON document for a machine.
    Json,
}

/// The exit codes of CHK-7; a usage error exits with 2, through `clap`.
const INCOMPLETE: u8 = 1;
const UNREADABLE: u8 = 3;
const UNWRITABLE: u8 = 4;

fn main() -> ExitCode {
    let Command::Check(args) = Cli::parse().command;
    run_check(&args)
}

fn run_check(args: &CheckArgs) -> ExitCode {
    let sbom = match read_sbom(&args.sbom) {
        Ok(sbom) => sbom,
        Err(error) => {
            eprintln!("error: {}: {error}", input_name(&args.sbom).display());
            return ExitCode::from(UNREADABLE);
        }
    };
    let completeness = check(&sbom.components);
    let text = match args.format {
        Format::Human => report::human(&sbom, &completeness),
        Format::Json => report::json(&sbom, &completeness),
    };
    match io::stdout().lock().write_all(text.as_bytes()) {
        // A closed pipe (`forewarn check sbom.json | head`) is not an error of the check.
        Err(error) if error.kind() != ErrorKind::BrokenPipe => {
            eprintln!("error: cannot write the report to standard output: {error}");
            return ExitCode::from(UNWRITABLE);
        }
        _ => {}
    }
    if completeness.is_complete() || args.allow_incomplete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(INCOMPLETE)
    }
}

fn read_sbom(path: &Path) -> Result<Sbom, ReadError> {
    if is_stdin(path) {
        read_json(io::stdin().lock())
    } else {
        let file = File::open(path).map_err(|e| ReadError::Io(e.to_string()))?;
        read_json(file)
    }
}

fn is_stdin(path: &Path) -> bool {
    path.as_os_str() == "-"
}

fn input_name(path: &Path) -> &Path {
    if is_stdin(path) {
        Path::new("standard input")
    } else {
        path
    }
}
