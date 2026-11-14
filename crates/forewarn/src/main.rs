//! The `forewarn` command line: parses the arguments and wires the adapters to the domain (`specs/cli-check.md`,
//! `specs/cli-match.md`, `specs/cli-match-exploited.md`).

mod drafts;
mod early_warning;
mod escape;
mod report;

use std::collections::HashSet;
use std::env;
use std::fmt::Display;
use std::fs::File;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use forewarn_cyclonedx::{ReadError, read_json};
use forewarn_domain::completeness::check;
use forewarn_domain::date::{Date, Moment};
use forewarn_domain::deadlines::{DeadlinePastRange, reporting_deadlines};
use forewarn_domain::early_warning::draft_early_warnings;
use forewarn_domain::exploited::{ExploitedList, FlaggedReport, flag_exploited};
use forewarn_domain::matching::{ComponentPackage, match_components};
use forewarn_domain::sbom::Sbom;
use forewarn_domain::vulnerability::Vulnerability;
use forewarn_exploited::{euvd, kev};
use forewarn_osv::api::{Api, Package};
use forewarn_osv::fetch::{Archives, Refresh};
use forewarn_osv::{ReadError as OsvReadError, read_directory, read_record};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use report::{Awareness, ExploitedSource, Origin, Source};

/// Check a CycloneDX SBOM for the fields the EU Cyber Resilience Act expects, and match its components against known
/// vulnerabilities.
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
    /// Print the components of an SBOM affected by known OSV vulnerabilities, those the CISA KEV catalog or EUVD names
    /// marked actively exploited with their CRA reporting deadlines, and those that could not be evaluated.
    Match(Box<MatchArgs>),
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

#[derive(Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is a flag of the command line"
)]
struct MatchArgs {
    /// The CycloneDX JSON SBOM to match, `-` for standard input (`./-` for a file named `-`).
    sbom: PathBuf,
    /// An OSV record file, or a directory of them (an extracted OSV archive), read instead of fetching the OSV
    /// archives; repeat it for several.
    #[arg(long, conflicts_with = "osv_url")]
    osv: Vec<PathBuf>,
    /// The cache of the OSV archives, of the CISA KEV catalog (`cisa-kev`) and of the EUVD list (`euvd-exploited`)
    /// [default:
    /// `$XDG_CACHE_HOME/forewarn/osv`, else `$HOME/.cache/forewarn/osv`].
    #[arg(long)]
    cache: Option<PathBuf>,
    /// When to download an archive, the CISA KEV catalog or the EUVD list again: `offline`, `if-missing`, `always`, or
    /// when older than an age (`30m`, `12h`, `7d`) [default: 1d].
    #[arg(long, value_parser = parse_refresh)]
    refresh: Option<Refresh>,
    /// The URL the OSV archives are downloaded from (`<url>/<ecosystem>/all.zip`), a mirror for example
    /// [default: `https://osv-vulnerabilities.storage.googleapis.com`].
    #[arg(long)]
    osv_url: Option<String>,
    /// Query the OSV API instead of fetching the OSV archives: sends the OSV ecosystem, name and version of each
    /// component to the OSV API, out of the CI; the answer depends on the moment of the query.
    #[arg(long, conflicts_with_all = ["osv", "osv_url"])]
    osv_api: bool,
    /// The URL of the OSV API queried with `--osv-api` [default: `https://api.osv.dev`].
    #[arg(long, requires = "osv_api")]
    osv_api_url: Option<String>,
    /// A CISA KEV catalog file (`known_exploited_vulnerabilities.json`) the matches are flagged against, read instead
    /// of fetching the catalog into the cache.
    #[arg(long, conflicts_with_all = ["no_kev", "kev_url"])]
    kev: Option<PathBuf>,
    /// Flag no match against the CISA KEV catalog: neither fetch nor read it.
    #[arg(long, conflicts_with = "kev_url")]
    no_kev: bool,
    /// The URL the CISA KEV catalog is downloaded from, a mirror for example [default:
    /// `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`].
    #[arg(long)]
    kev_url: Option<String>,
    /// An EUVD exploited list file (`{"items": [...]}`, the pages of its search or a copy of the cache's
    /// `euvd-exploited/exploited.json`) the matches are flagged against, read instead of paging the list into the
    /// cache.
    #[arg(long, conflicts_with_all = ["no_euvd", "euvd_url"])]
    euvd: Option<PathBuf>,
    /// Flag no match against the exploited list of EUVD: neither page nor read it.
    #[arg(long, conflicts_with = "euvd_url")]
    no_euvd: bool,
    /// The URL of the EUVD search the exploited list is paged from, a mirror for example [default:
    /// `https://euvdservices.enisa.europa.eu/api/search`].
    #[arg(long)]
    euvd_url: Option<String>,
    /// The moment the vendor became aware of the actively exploited vulnerabilities, an RFC 3339 instant
    /// (`2026-11-13T09:30:00Z`, an offset is converted to UTC), from which their early warning (24 h) and notification
    /// (72 h) deadlines are computed [default: the moment of the run].
    #[arg(long, value_name = "INSTANT", value_parser = parse_moment)]
    aware_since: Option<GivenMoment>,
    /// The moment a corrective or mitigating measure became available, an RFC 3339 instant, from which the final
    /// report deadline (14 days) is computed; without it the final report is due 14 days after a measure is
    /// available.
    #[arg(long, value_name = "INSTANT", value_parser = parse_moment)]
    measure_available: Option<GivenMoment>,
    /// The moment the deadlines are checked at, an RFC 3339 instant, for the time left before each or how long it is
    /// overdue, printed in the human report only [default: the moment of the run].
    #[arg(long, value_name = "INSTANT", value_parser = parse_moment)]
    now: Option<GivenMoment>,
    /// Write the draft CRA early warning of each actively exploited CVE into this directory, created when missing,
    /// one Markdown file per CVE named `<product>-<CVE>.md`, replaced on a rerun.
    #[arg(long, value_name = "DIR")]
    drafts: Option<PathBuf>,
    /// The format of the report.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
    /// Exit with 0 when components are affected and none is actively exploited, so that a CI job fails only on an
    /// actively exploited vulnerability (exit code 6).
    #[arg(long)]
    allow_affected: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// Text for a person at a terminal.
    Human,
    /// One JSON document for a machine.
    Json,
}

/// The exit codes of CHK-7 and MCH-10; a usage error exits with 2, through `clap`.
const FOUND: u8 = 1;
const UNREADABLE: u8 = 3;
const UNWRITABLE: u8 = 4;
const NO_RECORDS: u8 = 5;
const EXPLOITED: u8 = 6;
const DRAFT_UNWRITABLE: u8 = 7;

fn main() -> ExitCode {
    let outcome = match Cli::parse().command {
        Command::Check(args) => run_check(&args),
        Command::Match(args) => run_match(&args),
    };
    outcome.unwrap_or_else(ExitCode::from)
}

fn run_check(args: &CheckArgs) -> Result<ExitCode, u8> {
    let sbom = read_sbom(&args.sbom)?;
    let completeness = check(&sbom.components);
    write_report(&match args.format {
        Format::Human => report::human(&sbom, &completeness),
        Format::Json => report::json(&sbom, &completeness),
    })?;
    Ok(exit(!completeness.is_complete() && !args.allow_incomplete))
}

fn run_match(args: &MatchArgs) -> Result<ExitCode, u8> {
    // The arguments are checked before the SBOM is read (MCH-10).
    let awareness = awareness(args);
    let fetches_archives = args.osv.is_empty() && !args.osv_api;
    let fetches_kev = args.kev.is_none() && !args.no_kev;
    let fetches_euvd = args.euvd.is_none() && !args.no_euvd;
    let fetches_any = fetches_archives || fetches_kev || fetches_euvd;
    if !fetches_any && (args.cache.is_some() || args.refresh.is_some()) {
        usage_error(
            clap::error::ErrorKind::ArgumentConflict,
            "--cache and --refresh apply to what is fetched: neither the OSV archives (--osv, --osv-api), the \
             CISA KEV catalog (--kev, --no-kev) nor the EUVD list (--euvd, --no-euvd) are",
        );
    }
    let cache =
        fetches_any.then(|| cache_directory(args, fetches_archives, fetches_kev, fetches_euvd));
    let refresh = args.refresh.unwrap_or(DEFAULT_REFRESH);
    let archives = cache
        .clone()
        .filter(|_| fetches_archives)
        .map(|cache| archives(args, cache, refresh));
    let feed = cache
        .clone()
        .filter(|_| fetches_kev)
        .map(|cache| kev_feed(args, cache, refresh));
    let euvd_feed = cache
        .filter(|_| fetches_euvd)
        .map(|cache| euvd_feed(args, cache, refresh));
    let sbom = read_sbom(&args.sbom)?;
    let mut records = Records::default();
    let mut fetched = Vec::new();
    if let Some(archives) = archives {
        let snapshots = archives
            .fetch(&ecosystems(&sbom), SystemTime::now)
            .map_err(|error| no_records(&error))?;
        for snapshot in snapshots {
            let count = records.add(snapshot.vulnerabilities);
            fetched.push((snapshot.ecosystem, snapshot.freshness, count));
        }
    }
    let mut queried = None;
    if args.osv_api {
        let answer = api(args)
            .query(&packages(&sbom), SystemTime::now)
            .map_err(|error| no_records(&error))?;
        let count = records.add(answer.vulnerabilities);
        queried = Some((answer.freshness, count));
    }
    let mut local = Vec::new();
    for path in &args.osv {
        let read = read_osv(path).map_err(|error| no_records(&error))?;
        local.push((path, records.add(read)));
    }
    // The exploited lists come after the OSV records, so that a local error is reported before a download.
    let (catalog, euvd_list) = exploited_lists(args, feed, euvd_feed)?;
    // CISA KEV, then EUVD: the order of the evidence (EXF-5, MXL-6).
    let exploited: Vec<ExploitedSource> = catalog
        .iter()
        .map(KevCatalog::source)
        .chain(euvd_list.iter().map(EuvdList::source))
        .collect();
    let matching = flag_exploited(
        match_components(&sbom.components, &records.vulnerabilities),
        exploited.iter().map(|source| source.list),
    );
    let sources: Vec<Source> = fetched
        .iter()
        .map(|(ecosystem, freshness, records)| Source::Archive {
            ecosystem,
            freshness,
            records: *records,
        })
        .chain(queried.iter().map(|(freshness, records)| Source::Api {
            freshness,
            records: *records,
        }))
        .chain(local.iter().map(|(path, records)| Source::Local {
            path,
            records: *records,
        }))
        .collect();
    // The drafts before the report, so that a draft not written leaves standard output empty (MXL-33).
    let drafts = args
        .drafts
        .as_ref()
        .map(|directory| write_drafts(directory, &sbom, &awareness, &matching))
        .transpose()?;
    let report = report::MatchReport {
        sbom: &sbom,
        sources: &sources,
        exploited: &exploited,
        awareness: &awareness,
        matching: &matching,
        drafts: drafts.as_deref(),
    };
    write_report(&match args.format {
        Format::Human => report::matching_human(&report),
        Format::Json => report::matching_json(&report),
    })?;
    if matching.exploited_count() > 0 {
        return Ok(ExitCode::from(EXPLOITED));
    }
    Ok(exit(!matching.matches().is_empty() && !args.allow_affected))
}

/// Writes the draft early warning of each actively exploited CVE into `directory` (MXL-27), or prints why one cannot
/// be written and returns the code 7 (MXL-33).
fn write_drafts(
    directory: &Path,
    sbom: &Sbom,
    awareness: &Awareness,
    matching: &FlaggedReport,
) -> Result<Vec<drafts::Written>, u8> {
    let drafted = draft_early_warnings(
        matching,
        sbom.product.as_ref(),
        awareness.since,
        awareness.measure_available,
    )
    .expect("the deadlines of the moments given were checked before the SBOM was read");
    drafts::write(directory, &drafted).map_err(|error| {
        eprintln!("error: {}", escape::escaped(&error.to_string()));
        DRAFT_UNWRITABLE
    })
}

/// The moments the reporting deadlines of the run are computed from, those deadlines and the moment they are checked
/// at (MXL-14 to MXL-17, MXL-23); exits with 2, naming the option and the value given, when a deadline falls past the
/// year 9999 (MXL-20).
fn awareness(args: &MatchArgs) -> Awareness {
    // The clock is read once, for the moment of awareness and the moment of the check alike (MXL-23).
    let run = (args.aware_since.is_none() || args.now.is_none()).then(|| {
        report::offset_date_time(SystemTime::now())
            .and_then(moment)
            .unwrap_or_else(|| {
                let missing = [
                    (args.aware_since.is_none(), "--aware-since"),
                    (args.now.is_none(), "--now"),
                ]
                .into_iter()
                .filter_map(|(missing, option)| missing.then_some(option))
                .collect::<Vec<_>>()
                .join(" and ");
                usage_error(
                    clap::error::ErrorKind::InvalidValue,
                    &format!(
                        "the clock of the system gives no moment of the years 1 to 9999: give {missing}"
                    ),
                )
            })
    });
    let given_or_run = |given: Option<&GivenMoment>| {
        given
            .map(|given| given.moment)
            .or(run)
            .expect("the clock is read when a moment is not given")
    };
    let since = given_or_run(args.aware_since.as_ref());
    // The moment of awareness first, so that the error of a final report names the measure (MXL-20).
    reporting_deadlines(since, None)
        .unwrap_or_else(|error| past_range("--aware-since", args.aware_since.as_ref(), error));
    let measure_available = args.measure_available.as_ref().map(|given| given.moment);
    let deadlines = reporting_deadlines(since, measure_available).unwrap_or_else(|error| {
        past_range(
            "--measure-available",
            args.measure_available.as_ref(),
            error,
        )
    });
    Awareness {
        since,
        given: args.aware_since.is_some(),
        measure_available,
        deadlines,
        checked_at: given_or_run(args.now.as_ref()),
        checked_given: args.now.is_some(),
    }
}

/// Exits with 2 naming the option and the value given whose deadline falls past the year 9999 (MXL-20).
fn past_range(option: &str, given: Option<&GivenMoment>, error: DeadlinePastRange) -> ! {
    let text = given.map_or_else(|| error.0.to_string(), |given| given.text.clone());
    usage_error(
        clap::error::ErrorKind::InvalidValue,
        &format!("invalid value '{text}' for '{option}': {error}"),
    )
}

/// A moment given on the command line, with the text it was read from, so that an error names what the user typed.
#[derive(Clone)]
struct GivenMoment {
    text: String,
    moment: Moment,
}

/// Reads an RFC 3339 instant into a moment of UTC, its offset applied and its fraction of a second dropped, so that no
/// deadline is computed later (MXL-19, MXL-20).
fn parse_moment(text: &str) -> Result<GivenMoment, String> {
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
fn moment(time: OffsetDateTime) -> Option<Moment> {
    let utc = time.checked_to_offset(time::UtcOffset::UTC)?;
    let date = Date::new(
        u16::try_from(utc.year()).ok()?,
        u8::from(utc.month()),
        utc.day(),
    )
    .ok()?;
    Moment::new(date, utc.hour(), utc.minute(), utc.second()).ok()
}

/// The CISA KEV catalog and the EUVD list of a run, the files given read before a list is fetched (MXL-2, MXL-3,
/// MXL-6, MXL-7).
fn exploited_lists(
    args: &MatchArgs,
    kev_feed: Option<kev::Feed>,
    euvd_feed: Option<euvd::Feed>,
) -> Result<(Option<KevCatalog<'_>>, Option<EuvdList<'_>>), u8> {
    // A list is either given or fetched, never both (MCH-10).
    let local_kev = args
        .kev
        .as_ref()
        .map(|path| kev::read_file(path).map(|catalog| KevCatalog::Local(catalog, path)))
        .transpose()
        .map_err(|error| no_records(&error))?;
    let local_euvd = args
        .euvd
        .as_ref()
        .map(|path| euvd::read_file(path).map(|list| EuvdList::Local(list, path)))
        .transpose()
        .map_err(|error| no_records(&error))?;
    let fetched_kev = kev_feed
        .map(|feed| feed.fetch(SystemTime::now).map(KevCatalog::Fetched))
        .transpose()
        .map_err(|error| no_records(&error))?;
    let fetched_euvd = euvd_feed
        .map(|feed| feed.fetch(SystemTime::now).map(EuvdList::Fetched))
        .transpose()
        .map_err(|error| no_records(&error))?;
    Ok((local_kev.or(fetched_kev), local_euvd.or(fetched_euvd)))
}

/// The CISA KEV catalog of a run: a file given with `--kev`, or fetched into the cache (MXL-2, MXL-3).
enum KevCatalog<'a> {
    Local(kev::Catalog, &'a Path),
    Fetched(kev::FetchedCatalog),
}

impl KevCatalog<'_> {
    fn source(&self) -> ExploitedSource<'_> {
        let (catalog, origin) = match self {
            Self::Local(catalog, path) => (catalog, Origin::Local(path)),
            Self::Fetched(fetched) => (&fetched.catalog, Origin::Fetched(&fetched.freshness)),
        };
        ExploitedSource {
            list: &catalog.list,
            release: Some((&catalog.version, catalog.released)),
            origin,
        }
    }
}

/// The exploited list of EUVD of a run: a file given with `--euvd`, or paged into the cache (MXL-6, MXL-7).
enum EuvdList<'a> {
    Local(ExploitedList, &'a Path),
    Fetched(euvd::FetchedList),
}

impl EuvdList<'_> {
    fn source(&self) -> ExploitedSource<'_> {
        let (list, origin) = match self {
            Self::Local(list, path) => (list, Origin::Local(path)),
            Self::Fetched(fetched) => (&fetched.list, Origin::Fetched(&fetched.freshness)),
        };
        ExploitedSource {
            list,
            release: None,
            origin,
        }
    }
}

/// Prints a usage error of `forewarn match` and exits with 2, as `clap` does for the errors it finds.
fn usage_error(kind: clap::error::ErrorKind, message: &str) -> ! {
    let mut cli = Cli::command();
    // Builds the names of the subcommands, so that the usage printed is that of `forewarn match`.
    cli.build();
    cli.find_subcommand_mut("match")
        .expect("the match subcommand")
        .error(kind, message)
        .exit()
}

/// The cache directory of MCH-12; exits with 2 when none can be found, naming the options that fetch no exploited list
/// when only those lists need it.
fn cache_directory(
    args: &MatchArgs,
    fetches_archives: bool,
    fetches_kev: bool,
    fetches_euvd: bool,
) -> PathBuf {
    args.cache
        .clone()
        .or_else(default_cache)
        .unwrap_or_else(|| {
            let mut message =
                "no cache directory: give --cache, or set XDG_CACHE_HOME or HOME".to_owned();
            if !fetches_archives {
                message.push_str(match (fetches_kev, fetches_euvd) {
                    (true, true) => {
                        ", or give --kev <file> or --no-kev, and --euvd <file> or --no-euvd, to fetch no \
                         exploited list"
                    }
                    (true, false) => ", or give --kev <file> or --no-kev to fetch no CISA KEV catalog",
                    (false, true) => ", or give --euvd <file> or --no-euvd to fetch no EUVD list",
                    (false, false) => "",
                });
            }
            usage_error(clap::error::ErrorKind::MissingRequiredArgument, &message)
        })
}

/// The archives of OSV the arguments name (MCH-13).
fn archives(args: &MatchArgs, cache: PathBuf, refresh: Refresh) -> Archives {
    let mut archives = Archives::new(cache, refresh);
    if let Some(url) = &args.osv_url {
        archives.base_url.clone_from(url);
    }
    archives
}

/// The EUVD list the arguments name, kept in the entry `euvd-exploited` of the cache (MXL-12, MXL-13).
fn euvd_feed(args: &MatchArgs, cache: PathBuf, refresh: Refresh) -> euvd::Feed {
    let mut feed = euvd::Feed::new(cache, refresh);
    if let Some(url) = &args.euvd_url {
        feed.url.clone_from(url);
    }
    feed
}

/// The CISA KEV catalog the arguments name, kept in the entry `cisa-kev` of the cache (MXL-10, MXL-11).
fn kev_feed(args: &MatchArgs, cache: PathBuf, refresh: Refresh) -> kev::Feed {
    let mut feed = kev::Feed::new(cache, refresh);
    if let Some(url) = &args.kev_url {
        feed.url.clone_from(url);
    }
    feed
}

/// The OSV API the arguments name (MCH-27).
fn api(args: &MatchArgs) -> Api {
    let mut api = Api::default();
    if let Some(url) = &args.osv_api_url {
        api.base_url.clone_from(url);
    }
    api
}

/// The refresh policy without `--refresh`: an archive older than a day is downloaded again (MCH-11).
const DEFAULT_REFRESH: Refresh = Refresh::OlderThan(Duration::from_secs(24 * 60 * 60));

/// `$XDG_CACHE_HOME/forewarn/osv`, else `$HOME/.cache/forewarn/osv`; a relative `XDG_CACHE_HOME` is ignored, as the
/// XDG Base Directory specification says, and a variable set to nothing counts as unset.
fn default_cache() -> Option<PathBuf> {
    env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|cache| cache.is_absolute())
        .or_else(|| {
            env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(|home| Path::new(&home).join(".cache"))
        })
        .map(|cache| cache.join("forewarn").join("osv"))
}

/// Reads a refresh policy: `offline`, `if-missing`, `always`, or an age, a positive whole number of `m`, `h` or `d`.
fn parse_refresh(text: &str) -> Result<Refresh, String> {
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

/// The OSV ecosystem of each component that maps to one, each once, in the order of its first component (MCH-5).
fn ecosystems(sbom: &Sbom) -> Vec<&'static str> {
    let mut ecosystems = Vec::new();
    for component in &sbom.components {
        if let Ok(package) = ComponentPackage::of(component)
            && !ecosystems.contains(&package.ecosystem)
        {
            ecosystems.push(package.ecosystem);
        }
    }
    ecosystems
}

/// The OSV ecosystem, name and version of each component that maps to an ecosystem, in the order of the SBOM; a Go
/// version without its leading `v`, as OSV writes the versions of Go modules (MCH-24).
fn packages(sbom: &Sbom) -> Vec<Package> {
    sbom.components
        .iter()
        .filter_map(|component| ComponentPackage::of(component).ok())
        .map(|package| Package {
            ecosystem: package.ecosystem.to_owned(),
            name: package.name,
            version: match (package.ecosystem, package.version.strip_prefix('v')) {
                ("Go", Some(bare)) => bare.to_owned(),
                _ => package.version,
            },
        })
        .collect()
}

/// The vulnerabilities read, each id once (MCH-21).
#[derive(Default)]
struct Records {
    vulnerabilities: Vec<Vulnerability>,
    ids: HashSet<String>,
}

impl Records {
    /// Adds the vulnerabilities of a source whose id was not read before; returns how many the source held.
    fn add(&mut self, read: Vec<Vulnerability>) -> usize {
        let count = read.len();
        for vulnerability in read {
            if self.ids.insert(vulnerability.id.clone()) {
                self.vulnerabilities.push(vulnerability);
            }
        }
        count
    }
}

/// Prints why the OSV records or the KEV catalog cannot be read or fetched (MCH-14).
fn no_records(error: &dyn Display) -> u8 {
    eprintln!("error: {}", escape::escaped(&error.to_string()));
    NO_RECORDS
}

/// Code 1 when the report found what a CI job fails on, else 0.
fn exit(found: bool) -> ExitCode {
    if found {
        ExitCode::from(FOUND)
    } else {
        ExitCode::SUCCESS
    }
}

/// Reads the SBOM, or prints why it cannot be read on standard error (CHK-8, MCH-14).
fn read_sbom(path: &Path) -> Result<Sbom, u8> {
    let sbom = if is_stdin(path) {
        read_json(io::stdin().lock())
    } else {
        File::open(path)
            .map_err(|e| ReadError::Io(e.to_string()))
            .and_then(read_json)
    };
    sbom.map_err(|error| {
        let error = format!("{}: {error}", input_name(path).display());
        eprintln!("error: {}", escape::escaped(&error));
        UNREADABLE
    })
}

/// Reads an OSV record file, or each record of a directory.
fn read_osv(path: &Path) -> Result<Vec<Vulnerability>, OsvReadError> {
    if path.is_dir() {
        read_directory(path)
    } else {
        read_record(path).map(|vulnerability| vec![vulnerability])
    }
}

/// Prints the report on standard output, or why it cannot be (CHK-13, MCH-20).
fn write_report(text: &str) -> Result<(), u8> {
    match io::stdout().lock().write_all(text.as_bytes()) {
        // A closed pipe (`forewarn check sbom.json | head`) is not an error of the command.
        Err(error) if error.kind() != ErrorKind::BrokenPipe => {
            eprintln!("error: cannot write the report to standard output: {error}");
            Err(UNWRITABLE)
        }
        _ => Ok(()),
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

#[cfg(test)]
mod tests {
    use clap::Parser;
    use forewarn_osv::api::OSV_API;
    use forewarn_osv::fetch::OSV_ARCHIVES;

    use forewarn_exploited::euvd::EUVD_SEARCH;
    use forewarn_exploited::kev::KEV_CATALOG;

    use super::{Cli, Command, DEFAULT_REFRESH, api, archives, euvd_feed, kev_feed};

    // spec: MCH-27 (internal: a query of the OSV API needs the network)
    #[test]
    fn the_api_is_osv_dev_unless_a_url_is_given() {
        let base_url = |args: &[&str]| {
            let Command::Match(args) = Cli::parse_from(args).command else {
                panic!("a match command")
            };
            api(&args).base_url
        };
        assert_eq!(base_url(&["forewarn", "match", "--osv-api", "-"]), OSV_API);
        let mirror = [
            "forewarn",
            "match",
            "--osv-api",
            "--osv-api-url",
            "http://m",
            "-",
        ];
        assert_eq!(base_url(&mirror), "http://m");
    }

    // spec: MCH-13 (internal: a download from the OSV bucket needs the network)
    #[test]
    fn the_archives_come_from_the_osv_bucket_unless_a_url_is_given() {
        let base_url = |args: &[&str]| {
            let Command::Match(args) = Cli::parse_from(args).command else {
                panic!("a match command")
            };
            archives(&args, "c".into(), DEFAULT_REFRESH).base_url
        };
        let default = ["forewarn", "match", "--cache", "c", "-"];
        assert_eq!(base_url(&default), OSV_ARCHIVES);
        let mirror = [
            "forewarn",
            "match",
            "--cache",
            "c",
            "--osv-url",
            "http://m",
            "-",
        ];
        assert_eq!(base_url(&mirror), "http://m");
    }

    // spec: MXL-10 (internal: a download from cisa.gov needs the network)
    #[test]
    fn the_kev_catalog_comes_from_cisa_unless_a_url_is_given() {
        let url = |args: &[&str]| {
            let Command::Match(args) = Cli::parse_from(args).command else {
                panic!("a match command")
            };
            kev_feed(&args, "c".into(), DEFAULT_REFRESH).url
        };
        assert_eq!(url(&["forewarn", "match", "-"]), KEV_CATALOG);
        let mirror = ["forewarn", "match", "--kev-url", "http://m/kev.json", "-"];
        assert_eq!(url(&mirror), "http://m/kev.json");
    }

    // spec: MXL-12 (internal: paging the EUVD search needs the network)
    #[test]
    fn the_euvd_list_comes_from_enisa_unless_a_url_is_given() {
        let url = |args: &[&str]| {
            let Command::Match(args) = Cli::parse_from(args).command else {
                panic!("a match command")
            };
            euvd_feed(&args, "c".into(), DEFAULT_REFRESH).url
        };
        assert_eq!(url(&["forewarn", "match", "-"]), EUVD_SEARCH);
        let mirror = [
            "forewarn",
            "match",
            "--euvd-url",
            "http://m/api/search",
            "-",
        ];
        assert_eq!(url(&mirror), "http://m/api/search");
    }
}
