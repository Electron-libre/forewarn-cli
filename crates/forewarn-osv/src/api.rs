//! Querying the OSV API for the records of some packages: `/v1/querybatch`, then `/v1/vulns/<id>` for each id it names
//! (`specs/osv-reading.md`, ADR 0006). A request sends the ecosystem, the name and the version of each package, part
//! of the inventory: the caller opts in.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::time::SystemTime;

use forewarn_domain::vulnerability::Vulnerability;
use serde::{Deserialize, Serialize};

use crate::{Cause, ReadError, fetch, parse_record};

/// Where the OSV API answers.
pub const OSV_API: &str = "https://api.osv.dev";

/// The most queries `querybatch` takes in one request.
const BATCH: usize = 1000;

/// The most bytes read from one answer.
const ANSWER_LIMIT: u64 = 256 * 1024 * 1024;

/// The OSV API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Api {
    /// The URL of the API, [`OSV_API`] by default.
    pub base_url: String,
}

impl Default for Api {
    fn default() -> Self {
        Self {
            base_url: OSV_API.to_owned(),
        }
    }
}

/// A package and version to query.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Package {
    /// The OSV ecosystem (`crates.io`).
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// The records the API named for the packages, and how fresh they are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub freshness: QueryFreshness,
    /// Each record once, in the byte order of the ids.
    pub vulnerabilities: Vec<Vulnerability>,
}

/// When and where the API was queried (OSR-25).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryFreshness {
    /// The time the query started, as the caller's clock gave it.
    pub queried_at: SystemTime,
    /// The URL of the API.
    pub url: String,
}

/// Why a query failed (OSR-31).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryError {
    /// The API cannot be reached, or does not answer 200.
    Request { url: String, reason: String },
    /// An answer of `querybatch` is not JSON, or not one result per query; the reason.
    InvalidAnswer(String),
    /// An id of a result cannot name a path of the API.
    InvalidId(String),
    /// The record of an id cannot be read.
    Record { id: String, cause: Cause },
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request { url, reason } => write!(f, "cannot query the OSV API {url}: {reason}"),
            Self::InvalidAnswer(reason) => write!(f, "invalid OSV API answer: {reason}"),
            Self::InvalidId(id) => write!(
                f,
                "invalid record id {id:?} in an OSV API answer: only ASCII letters, digits, `.`, `-`, `_` and `:`, not first `.`"
            ),
            // The message of a record read from a file, the id in place of its path.
            Self::Record { id, cause } => write!(
                f,
                "OSV record {}",
                ReadError {
                    path: id.into(),
                    cause: cause.clone(),
                }
            ),
        }
    }
}

impl std::error::Error for QueryError {}

/// A query of `querybatch`, with the token of its next page once there is one.
#[derive(Serialize)]
struct Query<'a> {
    package: QueryPackage<'a>,
    version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

/// Only the ecosystem and the name of a package leave the CI (OSR-27).
#[derive(Clone, Copy, Serialize)]
struct QueryPackage<'a> {
    ecosystem: &'a str,
    name: &'a str,
}

#[derive(Serialize)]
struct Batch<'a, 'q> {
    queries: &'q [Query<'a>],
}

#[derive(Deserialize)]
struct BatchAnswer {
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<Named>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct Named {
    id: String,
}

impl Api {
    /// Returns the records the API names for the packages, each once; `clock` gives the time recorded for the query,
    /// read before its first request. A package listed twice is queried once; no package sends no request.
    ///
    /// # Errors
    ///
    /// The first [`QueryError`] met: a failed request, an answer that cannot be read, an id refused, a record that
    /// cannot be read.
    pub fn query(
        &self,
        packages: &[Package],
        clock: impl Fn() -> SystemTime,
    ) -> Result<Answer, QueryError> {
        let freshness = QueryFreshness {
            queried_at: clock(),
            url: self.base_url.clone(),
        };
        let base = self.base_url.trim_end_matches('/');
        let agent = fetch::agent();
        let mut seen = HashSet::new();
        let mut pending: Vec<Query> = packages
            .iter()
            .filter(|package| seen.insert(*package))
            .map(|package| Query {
                package: QueryPackage {
                    ecosystem: &package.ecosystem,
                    name: &package.name,
                },
                version: &package.version,
                page_token: None,
            })
            .collect();
        let mut ids = BTreeSet::new();
        let url = format!("{base}/v1/querybatch");
        while !pending.is_empty() {
            let mut next = Vec::new();
            for batch in pending.chunks(BATCH) {
                let body = serde_json::to_vec(&Batch { queries: batch })
                    .map_err(|e| QueryError::InvalidAnswer(e.to_string()))?;
                let answer: BatchAnswer = serde_json::from_slice(&post(&agent, &url, body)?)
                    .map_err(|e| QueryError::InvalidAnswer(e.to_string()))?;
                if answer.results.len() != batch.len() {
                    return Err(QueryError::InvalidAnswer(format!(
                        "{} results for {} queries",
                        answer.results.len(),
                        batch.len()
                    )));
                }
                for (query, result) in batch.iter().zip(answer.results) {
                    ids.extend(result.vulns.into_iter().map(|named| named.id));
                    if let Some(token) = result.next_page_token {
                        next.push(Query {
                            package: query.package,
                            version: query.version,
                            page_token: Some(token),
                        });
                    }
                }
            }
            pending = next;
        }
        // Every id is checked before the first record is requested.
        if let Some(id) = ids.iter().find(|id| !is_valid_id(id)) {
            return Err(QueryError::InvalidId(id.clone()));
        }
        let vulnerabilities = ids
            .into_iter()
            .map(|id| {
                let bytes = get(&agent, &format!("{base}/v1/vulns/{id}"))?;
                parse_record(&bytes).map_err(|cause| QueryError::Record { id, cause })
            })
            .collect::<Result<_, _>>()?;
        Ok(Answer {
            freshness,
            vulnerabilities,
        })
    }
}

/// Whether an id can name a path of the API as it is (OSR-31).
fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('.')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
}

fn post(agent: &ureq::Agent, url: &str, body: Vec<u8>) -> Result<Vec<u8>, QueryError> {
    let response = agent
        .post(url)
        .header("Content-Type", "application/json")
        .send(body);
    read(url, response)
}

fn get(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, QueryError> {
    read(url, agent.get(url).call())
}

/// The body of a response, or why the request failed.
fn read(
    url: &str,
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<Vec<u8>, QueryError> {
    let failed = |reason: String| QueryError::Request {
        url: url.to_owned(),
        reason,
    };
    let response = response.map_err(|e| failed(e.to_string()))?;
    if response.status() != 200 {
        return Err(failed(format!("the server answered {}", response.status())));
    }
    response
        .into_body()
        .with_config()
        .limit(ANSWER_LIMIT)
        .read_to_vec()
        .map_err(|e| failed(e.to_string()))
}
