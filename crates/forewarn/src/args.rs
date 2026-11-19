//! The arguments of the `forewarn` command line and the parsers of their values (`specs/cli-check.md`,
//! `specs/cli-match.md`, `specs/cli-match-exploited.md`, `specs/cli-upload.md`).

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use forewarn_domain::date::{Date, Moment};
use forewarn_osv::fetch::Refresh;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Check a CycloneDX SBOM for the fields the EU Cyber Resilience Act expects, and match its components against known
/// vulnerabilities.
#[derive(Parser)]
#[command(version, arg_required_else_help = true)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Print the spec version of an SBOM and the components missing a supplier, a license or a hash.
    Check(CheckArgs),
    /// Print the components of an SBOM affected by known OSV vulnerabilities, those the CISA KEV catalog or EUVD names
    /// marked actively exploited with their CRA reporting deadlines, and those that could not be evaluated.
    Match(Box<MatchArgs>),
    /// Upload an SBOM as is to a Forewarn service, for the product name and version it describes, with the token of
    /// the environment variable `FOREWARN_TOKEN`.
    Upload(UploadArgs),
}

#[derive(Args)]
pub(crate) struct UploadArgs {
    /// The CycloneDX JSON SBOM to upload, `-` for standard input (`./-` for a file named `-`).
    pub(crate) sbom: PathBuf,
    /// The root URL of the Forewarn service, HTTPS (plain HTTP to a loopback host only) [env: `FOREWARN_ENDPOINT`].
    #[arg(long, value_name = "URL")]
    pub(crate) endpoint: Option<String>,
    /// The product name to upload under, instead of the name of the SBOM's `metadata.component`.
    #[arg(long, value_name = "NAME")]
    pub(crate) product: Option<String>,
    /// The version to upload under, instead of the version of the SBOM's `metadata.component`.
    #[arg(long, value_name = "VERSION")]
    pub(crate) product_version: Option<String>,
    /// Print the endpoint, the product name, the version and the size of the SBOM, and send nothing; the token is not
    /// read.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub(crate) struct CheckArgs {
    /// The CycloneDX JSON SBOM to check, `-` for standard input (`./-` for a file named `-`).
    pub(crate) sbom: PathBuf,
    /// The format of the report.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub(crate) format: Format,
    /// Exit with 0 when components are incomplete, so that a CI job reports the gaps without failing.
    #[arg(long)]
    pub(crate) allow_incomplete: bool,
}

#[derive(Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is a flag of the command line"
)]
pub(crate) struct MatchArgs {
    /// The CycloneDX JSON SBOM to match, `-` for standard input (`./-` for a file named `-`).
    pub(crate) sbom: PathBuf,
    /// An OSV record file, or a directory of them (an extracted OSV archive), read instead of fetching the OSV
    /// archives; repeat it for several.
    #[arg(long, conflicts_with = "osv_url")]
    pub(crate) osv: Vec<PathBuf>,
    /// The cache of the OSV archives, of the CISA KEV catalog (`cisa-kev`) and of the EUVD list (`euvd-exploited`)
    /// [default:
    /// `$XDG_CACHE_HOME/forewarn/osv`, else `$HOME/.cache/forewarn/osv`].
    #[arg(long)]
    pub(crate) cache: Option<PathBuf>,
    /// When to download an archive, the CISA KEV catalog or the EUVD list again: `offline`, `if-missing`, `always`, or
    /// when older than an age (`30m`, `12h`, `7d`) [default: 1d].
    #[arg(long, value_parser = parse_refresh)]
    pub(crate) refresh: Option<Refresh>,
    /// The URL the OSV archives are downloaded from (`<url>/<ecosystem>/all.zip`), a mirror for example
    /// [default: `https://osv-vulnerabilities.storage.googleapis.com`].
    #[arg(long)]
    pub(crate) osv_url: Option<String>,
    /// Query the OSV API instead of fetching the OSV archives: sends the OSV ecosystem, name and version of each
    /// component to the OSV API, out of the CI; the answer depends on the moment of the query.
    #[arg(long, conflicts_with_all = ["osv", "osv_url"])]
    pub(crate) osv_api: bool,
    /// The URL of the OSV API queried with `--osv-api` [default: `https://api.osv.dev`].
    #[arg(long, requires = "osv_api")]
    pub(crate) osv_api_url: Option<String>,
    /// A CISA KEV catalog file (`known_exploited_vulnerabilities.json`) the matches are flagged against, read instead
    /// of fetching the catalog into the cache.
    #[arg(long, conflicts_with_all = ["no_kev", "kev_url"])]
    pub(crate) kev: Option<PathBuf>,
    /// Flag no match against the CISA KEV catalog: neither fetch nor read it.
    #[arg(long, conflicts_with = "kev_url")]
    pub(crate) no_kev: bool,
    /// The URL the CISA KEV catalog is downloaded from, a mirror for example [default:
    /// `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`].
    #[arg(long)]
    pub(crate) kev_url: Option<String>,
    /// An EUVD exploited list file (`{"items": [...]}`, the pages of its search or a copy of the cache's
    /// `euvd-exploited/exploited.json`) the matches are flagged against, read instead of paging the list into the
    /// cache.
    #[arg(long, conflicts_with_all = ["no_euvd", "euvd_url"])]
    pub(crate) euvd: Option<PathBuf>,
    /// Flag no match against the exploited list of EUVD: neither page nor read it.
    #[arg(long, conflicts_with = "euvd_url")]
    pub(crate) no_euvd: bool,
    /// The URL of the EUVD search the exploited list is paged from, a mirror for example [default:
    /// `https://euvdservices.enisa.europa.eu/api/search`].
    #[arg(long)]
    pub(crate) euvd_url: Option<String>,
    /// The moment the vendor became aware of the actively exploited vulnerabilities, an RFC 3339 instant
    /// (`2026-11-13T09:30:00Z`, an offset is converted to UTC), from which their early warning (24 h) and notification
    /// (72 h) deadlines are computed [default: the moment of the run].
    #[arg(long, value_name = "INSTANT", value_parser = parse_moment)]
    pub(crate) aware_since: Option<GivenMoment>,
    /// The moment a corrective or mitigating measure became available, an RFC 3339 instant, from which the final
    /// report deadline (14 days) is computed; without it the final report is due 14 days after a measure is
    /// available.
    #[arg(long, value_name = "INSTANT", value_parser = parse_moment)]
    pub(crate) measure_available: Option<GivenMoment>,
    /// The moment the deadlines are checked at, an RFC 3339 instant, for the time left before each or how long it is
    /// overdue, printed in the human report only [default: the moment of the run].
    #[arg(long, value_name = "INSTANT", value_parser = parse_moment)]
    pub(crate) now: Option<GivenMoment>,
    /// Write the draft CRA early warning of each actively exploited CVE into this directory, created when missing,
    /// one Markdown file per CVE named `<product>-<CVE>.md`, replaced on a rerun.
    #[arg(long, value_name = "DIR")]
    pub(crate) drafts: Option<PathBuf>,
    /// A JSON file of the moment of awareness of each actively exploited CVE per product, created when missing: the
    /// deadlines of a CVE it records count from its moment, and the CVEs it does not record are recorded at the moment
    /// of awareness of the run (`--aware-since`, else the moment of the run). Keep it between CI runs.
    #[arg(long, value_name = "FILE")]
    pub(crate) awareness: Option<PathBuf>,
    /// A CycloneDX VEX document whose verdicts are applied after those of the SBOM; repeat it for several. A match
    /// every verdict naming it says `not_affected`, `false_positive` or `resolved` is set aside: listed apart, out of
    /// the exit code and the drafts.
    #[arg(long, value_name = "PATH")]
    pub(crate) vex: Vec<PathBuf>,
    /// The format of the report.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub(crate) format: Format,
    /// Exit with 0 when components are affected and none is actively exploited, so that a CI job fails only on an
    /// actively exploited vulnerability (exit code 6).
    #[arg(long)]
    pub(crate) allow_affected: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Format {
    /// Text for a person at a terminal.
    Human,
    /// One JSON document for a machine.
    Json,
}

/// A moment given on the command line, with the text it was read from, so that an error names what the user typed.
#[derive(Clone)]
pub(crate) struct GivenMoment {
    pub(crate) text: String,
    pub(crate) moment: Moment,
}

/// Reads an RFC 3339 instant into a moment of UTC, its offset applied and its fraction of a second dropped, so that no
/// deadline is computed later (MXL-19, MXL-20).
pub(crate) fn parse_moment(text: &str) -> Result<GivenMoment, String> {
    let time = OffsetDateTime::parse(text, &Rfc3339)
        .map_err(|error| format!("an RFC 3339 instant such as `2026-11-13T09:30:00Z`: {error}"))?;
    let moment =
        moment(time).ok_or_else(|| "an instant of the years 1 to 9999 in UTC".to_owned())?;
    Ok(GivenMoment {
        text: text.to_owned(),
        moment,
    })
}

/// The moment of UTC of a time, to the second; `None` outside the years 1 to 9999.
pub(crate) fn moment(time: OffsetDateTime) -> Option<Moment> {
    let utc = time.checked_to_offset(time::UtcOffset::UTC)?;
    let date = Date::new(
        u16::try_from(utc.year()).ok()?,
        u8::from(utc.month()),
        utc.day(),
    )
    .ok()?;
    Moment::new(date, utc.hour(), utc.minute(), utc.second()).ok()
}

/// Reads a refresh policy: `offline`, `if-missing`, `always`, or an age, a positive whole number of `m`, `h` or `d`.
pub(crate) fn parse_refresh(text: &str) -> Result<Refresh, String> {
    match text {
        "offline" => return Ok(Refresh::Offline),
        "if-missing" => return Ok(Refresh::IfMissing),
        "always" => return Ok(Refresh::Always),
        _ => {}
    }
    let refused = || {
        format!(
            "`offline`, `if-missing`, `always`, or a positive age such as `30m`, `12h`, `7d`, not {text:?}"
        )
    };
    // The unit is the last character, which may not be ASCII (`1é`).
    let Some((count, unit)) = text
        .char_indices()
        .last()
        .map(|(at, unit)| (&text[..at], unit))
    else {
        return Err(refused());
    };
    let seconds = match unit {
        'm' => 60,
        'h' => 60 * 60,
        'd' => 24 * 60 * 60,
        _ => return Err(refused()),
    };
    if count.is_empty() || !count.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refused());
    }
    match count
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(seconds))
    {
        Some(age) if age > 0 => Ok(Refresh::OlderThan(Duration::from_secs(age))),
        _ => Err(refused()),
    }
}
