//! A package URL read by the package URL specification, the parts matching needs: type, namespace, name, version
//! (`specs/vulnerability-matching.md`, VMT-5).

/// The parts of a package URL; its qualifiers and subpath are dropped ([`points_to_local_path`] and [`qualifier`] read
/// its qualifiers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageUrl {
    /// The type, in lower case (`cargo`, `npm`…).
    pub purl_type: String,
    /// The namespace segments, percent-decoded, joined by `/`; empty when there is none.
    pub namespace: String,
    /// The name, percent-decoded.
    pub name: String,
    /// The version, percent-decoded.
    pub version: Option<String>,
}

/// The package URL does not follow the specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidPackageUrl;

impl PackageUrl {
    /// Reads a package URL: `pkg:type/namespace/name@version?qualifiers#subpath`.
    ///
    /// # Errors
    ///
    /// [`InvalidPackageUrl`] when it does not follow the specification.
    pub fn parse(purl: &str) -> Result<Self, InvalidPackageUrl> {
        let (scheme, rest) = purl.split_once(':').ok_or(InvalidPackageUrl)?;
        if !scheme.eq_ignore_ascii_case("pkg") {
            return Err(InvalidPackageUrl);
        }
        let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
        let rest = rest.split_once('?').map_or(rest, |(before, _)| before);
        let rest = rest.trim_matches('/');
        let (purl_type, path) = rest.split_once('/').ok_or(InvalidPackageUrl)?;
        if !is_valid_type(purl_type) {
            return Err(InvalidPackageUrl);
        }
        // The version follows the last `@` of the path, but not one opening a namespace segment: an npm scope
        // written without percent-encoding (`@babel/core`).
        let at = path
            .char_indices()
            .rev()
            .find(|&(i, c)| {
                let opens_segment = i == 0 || path[..i].ends_with('/');
                c == '@' && !(opens_segment && path[i..].contains('/'))
            })
            .map(|(i, _)| i);
        let (path, version) = match at {
            Some(at) => (&path[..at], Some(decode(&path[at + 1..])?)),
            None => (path, None),
        };
        let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let name = decode(segments.pop().ok_or(InvalidPackageUrl)?)?;
        if name.is_empty() {
            return Err(InvalidPackageUrl);
        }
        let namespace = segments
            .into_iter()
            .map(decode)
            .collect::<Result<Vec<_>, _>>()?
            .join("/");
        Ok(Self {
            purl_type: purl_type.to_ascii_lowercase(),
            namespace,
            name,
            version: version.filter(|v| !v.is_empty()),
        })
    }
}

/// Whether a package URL points to a local path: one of its qualifiers is `download_url`, its key in any ASCII case,
/// and the first five characters of its value, percent-decoded, are `file:` in any ASCII case
/// (`specs/vulnerability-matching.md`, VMT-31). An escape the specification refuses after them does not hide the path.
#[must_use]
pub fn points_to_local_path(purl: &str) -> bool {
    let purl = purl.split_once('#').map_or(purl, |(before, _)| before);
    let Some((_, qualifiers)) = purl.split_once('?') else {
        return false;
    };
    qualifiers
        .split('&')
        .filter_map(|qualifier| qualifier.split_once('='))
        .any(|(key, value)| {
            key.eq_ignore_ascii_case("download_url")
                && decoded_prefix(value, 5).eq_ignore_ascii_case(b"file:")
        })
}

/// The value of the first qualifier of a package URL whose key is `key` in any ASCII case, percent-decoded, or `None`
/// when it has none or its value does not decode (VMT-5).
#[must_use]
pub fn qualifier(purl: &str, key: &str) -> Option<String> {
    let purl = purl.split_once('#').map_or(purl, |(before, _)| before);
    let (_, qualifiers) = purl.split_once('?')?;
    qualifiers
        .split('&')
        .filter_map(|qualifier| qualifier.split_once('='))
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .and_then(|(_, value)| decode(value).ok())
}

/// The first `length` bytes of a value, percent-decoded, a `%` not followed by two hexadecimal digits kept as it is.
fn decoded_prefix(value: &str, length: usize) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(length);
    let mut i = 0;
    while i < bytes.len() && decoded.len() < length {
        match bytes.get(i + 1..i + 3) {
            Some(hex) if bytes[i] == b'%' && hex.iter().all(u8::is_ascii_hexdigit) => {
                decoded.push(hex_value(hex[0]) << 4 | hex_value(hex[1]));
                i += 3;
            }
            _ => {
                decoded.push(bytes[i]);
                i += 1;
            }
        }
    }
    decoded
}

/// A type is ASCII letters, digits, `.`, `+` and `-`, and does not start with a digit.
fn is_valid_type(purl_type: &str) -> bool {
    purl_type
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || matches!(first, '.' | '+' | '-'))
        && purl_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
}

/// Percent-decodes a segment into UTF-8.
pub(crate) fn decode(segment: &str) -> Result<String, InvalidPackageUrl> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                .ok_or(InvalidPackageUrl)?;
            let high = hex_value(hex[0]);
            let low = hex_value(hex[1]);
            decoded.push(high << 4 | low);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| InvalidPackageUrl)
}

/// The value of an ASCII hexadecimal digit.
fn hex_value(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => digit - b'A' + 10,
    }
}

#[cfg(test)]
mod tests {
    use super::{InvalidPackageUrl, PackageUrl};

    #[test]
    fn keeps_the_namespace_segments() {
        let purl = PackageUrl::parse("pkg:golang/github.com/foo/bar@v1.0.0").expect("valid");
        assert_eq!(purl.purl_type, "golang");
        assert_eq!(purl.namespace, "github.com/foo");
        assert_eq!(purl.name, "bar");
        assert_eq!(purl.version.as_deref(), Some("v1.0.0"));
    }

    #[test]
    fn refuses_a_truncated_or_signed_escape() {
        assert_eq!(PackageUrl::parse("pkg:cargo/a%4"), Err(InvalidPackageUrl));
        assert_eq!(PackageUrl::parse("pkg:cargo/a%+4b"), Err(InvalidPackageUrl));
    }
}
