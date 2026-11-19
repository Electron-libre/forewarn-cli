//! The endpoint of an upload: the root of a Forewarn service, HTTPS or a loopback host in plain HTTP (UPL-2, UPL-6),
//! named without its credentials (UPL-11).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use ureq::http::Uri;

/// The root of a Forewarn service, checked (UPL-6): the URL as the caller gave it, without a trailing `/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    named: String,
    /// `http`, to a loopback host.
    plain: bool,
}

/// Why an endpoint is refused (UPL-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndpointProblem {
    /// Not an absolute URL with a host.
    NotAnUrl,
    /// A scheme other than `https` and `http`.
    Scheme,
    /// `http` to a host that is not loopback (UPL-2).
    PlainHttp,
    /// User information before the host: the token is given apart.
    UserInformation,
    /// A query.
    Query,
    /// A fragment.
    Fragment,
}

/// An endpoint refused before anything is sent, named with its user information written `***` (UPL-11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidEndpoint {
    pub endpoint: String,
    pub problem: EndpointProblem,
}

impl fmt::Display for InvalidEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Quoted, its control characters escaped: the endpoint is the caller's text, not a URL checked yet.
        let endpoint = format!("{:?}", self.endpoint);
        match self.problem {
            EndpointProblem::NotAnUrl => {
                write!(f, "the endpoint {endpoint} is not an absolute URL")
            }
            EndpointProblem::Scheme => {
                write!(f, "the endpoint {endpoint} is neither https nor http")
            }
            EndpointProblem::PlainHttp => write!(
                f,
                "the endpoint {endpoint} is plain http to a host that is not loopback: use https"
            ),
            EndpointProblem::UserInformation => write!(
                f,
                "the endpoint {endpoint} holds credentials: give the token apart"
            ),
            EndpointProblem::Query => write!(f, "the endpoint {endpoint} holds a query"),
            EndpointProblem::Fragment => write!(f, "the endpoint {endpoint} holds a fragment"),
        }
    }
}

impl std::error::Error for InvalidEndpoint {}

impl Endpoint {
    /// Checks the root of a service (UPL-6).
    ///
    /// # Errors
    /// [`InvalidEndpoint`] for an endpoint that is not an absolute `https` URL, or `http` to a loopback host, or that
    /// holds user information, a query or a fragment.
    pub fn parse(endpoint: &str) -> Result<Self, InvalidEndpoint> {
        let named = endpoint.trim_end_matches('/');
        // Any `@` first, wherever it is: the error names no character before it (UPL-11).
        if named.contains('@') {
            return Err(InvalidEndpoint {
                endpoint: without_user_information(named),
                problem: EndpointProblem::UserInformation,
            });
        }
        let refuse = |problem| InvalidEndpoint {
            endpoint: named.to_owned(),
            problem,
        };
        let Some((scheme, rest)) = endpoint.split_once("://") else {
            return Err(refuse(EndpointProblem::NotAnUrl));
        };
        let plain = if scheme.eq_ignore_ascii_case("https") {
            false
        } else if scheme.eq_ignore_ascii_case("http") {
            true
        } else if !scheme.is_empty() && scheme.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(refuse(EndpointProblem::Scheme));
        } else {
            return Err(refuse(EndpointProblem::NotAnUrl));
        };
        let tail = &rest[rest.find(['/', '?', '#']).unwrap_or(rest.len())..];
        match tail.find(['?', '#']).map(|at| tail.as_bytes()[at]) {
            Some(b'?') => return Err(refuse(EndpointProblem::Query)),
            Some(_) => return Err(refuse(EndpointProblem::Fragment)),
            None => {}
        }
        let host = endpoint
            .parse::<Uri>()
            .ok()
            .and_then(|uri| checked_host(&uri).map(str::to_owned))
            .ok_or_else(|| refuse(EndpointProblem::NotAnUrl))?;
        if plain && !is_loopback(&host) {
            return Err(refuse(EndpointProblem::PlainHttp));
        }
        Ok(Self {
            named: named.to_owned(),
            plain,
        })
    }

    /// Whether the endpoint is plain `http`, to a loopback host: reached directly, never through a proxy (UPL-13).
    pub(crate) fn is_plain_http(&self) -> bool {
        self.plain
    }

    /// The endpoint as the caller gave it, without a trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.named
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.named)
    }
}

/// The host the URI names, the URI that `ureq` connects to: none when it is empty, when an IPv6 host is not an
/// address, or when the authority holds anything after it but a port of 0 to 65535.
fn checked_host(uri: &Uri) -> Option<&str> {
    let authority = uri.authority()?;
    let host = authority.host();
    if host.is_empty() {
        return None;
    }
    if let Some(v6) = host.strip_prefix('[') {
        v6.strip_suffix(']')?.parse::<Ipv6Addr>().ok()?;
    }
    match authority.as_str().strip_prefix(host)? {
        "" => Some(host),
        after => after.strip_prefix(':')?.parse::<u16>().ok().map(|_| host),
    }
}

/// `localhost`, an IPv4 address of `127.0.0.0/8` or `[::1]` (UPL-6).
fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6.parse::<Ipv6Addr>().is_ok_and(|ip| ip.is_loopback());
    }
    host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
}

/// The endpoint with everything before its last `@`, past its `scheme://`, written `***` (UPL-11).
fn without_user_information(endpoint: &str) -> String {
    let at = endpoint.rfind('@').unwrap_or(0);
    let scheme = endpoint[..at]
        .find("://")
        .map_or("", |end| &endpoint[..end + 3]);
    format!("{scheme}***{}", &endpoint[at..])
}
