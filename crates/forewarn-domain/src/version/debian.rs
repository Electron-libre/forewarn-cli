//! The ordering of the `Debian:<release>` versions, as Debian Policy 5.6.12 and `dpkg` read them (VOR-7).

use std::cmp::Ordering;

use super::{Number, VersionOrder};

/// The ordering of `Debian:<release>`, as `dpkg` compares versions (VOR-7).
pub(crate) struct Debian;

/// A Debian version: its epoch, upstream version and revision.
#[derive(Debug)]
pub(crate) struct DebianKey {
    epoch: Number,
    upstream: String,
    /// The revision, `0` when the version has none.
    revision: String,
}

impl VersionOrder for Debian {
    type Key = DebianKey;

    fn parse(version: &str) -> Option<Self::Key> {
        let version = version.trim();
        let (epoch, rest) = match version.split_once(':') {
            Some((epoch, rest)) => {
                if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                (Number::of(epoch), rest)
            }
            None => (Number::of(""), version),
        };
        let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, "0"));
        let colon_allowed = version.contains(':');
        let upstream_valid = upstream.bytes().next().is_some_and(|b| b.is_ascii_digit())
            && upstream.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'.' | b'+' | b'~' | b'-')
                    || (b == b':' && colon_allowed)
            });
        let revision_valid = !revision.is_empty()
            && revision
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~'));
        (upstream_valid && revision_valid).then(|| DebianKey {
            epoch,
            upstream: upstream.to_owned(),
            revision: revision.to_owned(),
        })
    }

    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering {
        a.epoch
            .cmp(&b.epoch)
            .then_with(|| compare_part(&a.upstream, &b.upstream))
            .then_with(|| compare_part(&a.revision, &b.revision))
    }
}

/// Compares an upstream version or a revision as `dpkg` does: runs of non-digits, then of digits, in turn.
fn compare_part(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() || !b.is_empty() {
        let (a_text, a_rest) = split_run(a, false);
        let (b_text, b_rest) = split_run(b, false);
        let text = compare_text(a_text, b_text);
        if text.is_ne() {
            return text;
        }
        let (a_digits, a_rest) = split_run(a_rest, true);
        let (b_digits, b_rest) = split_run(b_rest, true);
        let digits = number(a_digits).cmp(&number(b_digits));
        if digits.is_ne() {
            return digits;
        }
        (a, b) = (a_rest, b_rest);
    }
    Ordering::Equal
}

/// The leading run of digits, or of non-digits, and what follows it.
fn split_run(text: &[u8], digits: bool) -> (&[u8], &[u8]) {
    let length = text
        .iter()
        .take_while(|b| b.is_ascii_digit() == digits)
        .count();
    text.split_at(length)
}

/// A run of ASCII digits as a number, an empty run as `0`.
fn number(digits: &[u8]) -> Number {
    Number::of(std::str::from_utf8(digits).unwrap_or_default())
}

/// Compares two runs of non-digits character by character: `~` before the end, the end before a letter, a letter
/// before any other character.
fn compare_text(a: &[u8], b: &[u8]) -> Ordering {
    let length = a.len().max(b.len());
    (0..length)
        .map(|i| weight(a.get(i)).cmp(&weight(b.get(i))))
        .find(|order| order.is_ne())
        .unwrap_or(Ordering::Equal)
}

/// The weight of a character of a run of non-digits, `None` at its end.
fn weight(c: Option<&u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(*c),
        Some(c) => i32::from(*c) + 256,
    }
}
