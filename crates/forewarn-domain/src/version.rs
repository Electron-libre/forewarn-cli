//! The version orderings a range is compared by (`specs/vulnerability-matching.md`, VMT-9, VMT-23).

use std::cmp::Ordering;

use crate::vulnerability::RangeKind;

/// How the versions of a range are read and ordered.
pub(crate) trait VersionOrder {
    /// A version read in this ordering.
    type Key;

    /// The version read in this ordering, or `None` when it does not follow it.
    fn parse(version: &str) -> Option<Self::Key>;

    /// The order of two versions read in this ordering.
    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering;
}

/// The orderings matching knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    /// Semantic Versioning 2.0, a leading `v` ignored.
    Semver,
    /// PEP 440, the versions of `PyPI` (VMT-24).
    Pep440,
    /// The ordering of `Maven` (VMT-25).
    Maven,
}

impl Scheme {
    /// The ordering a range of this kind naming a package of this ecosystem is compared by, or `None` when matching
    /// does not compare it (VMT-9, VMT-23).
    pub(crate) fn of(kind: RangeKind, ecosystem: &str) -> Option<Self> {
        match (kind, ecosystem) {
            (RangeKind::Semver, _) | (RangeKind::Ecosystem, "crates.io" | "npm" | "Go") => {
                Some(Self::Semver)
            }
            (RangeKind::Ecosystem, "PyPI") => Some(Self::Pep440),
            (RangeKind::Ecosystem, "Maven") => Some(Self::Maven),
            _ => None,
        }
    }
}

/// Semantic Versioning 2.0, build metadata ignored, a leading `v` ignored.
pub(crate) struct Semver;

impl VersionOrder for Semver {
    type Key = semver::Version;

    fn parse(version: &str) -> Option<Self::Key> {
        let version = version.trim();
        let version = version.strip_prefix('v').unwrap_or(version);
        semver::Version::parse(version).ok()
    }

    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering {
        a.cmp_precedence(b)
    }
}

/// A number of any length, ordered as a number: its leading zeros dropped, then by length, then by digits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Number(String);

impl Number {
    /// The number these ASCII digits write.
    fn of(digits: &str) -> Self {
        Self(digits.trim_start_matches('0').to_owned())
    }

    fn is_zero(&self) -> bool {
        self.0.is_empty()
    }
}

impl Ord for Number {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A cursor over the ASCII text of a version.
struct Cursor<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, at: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    fn is_done(&self) -> bool {
        self.at == self.text.len()
    }

    /// Consumes `prefix` when the rest starts with it.
    fn eat(&mut self, prefix: &str) -> bool {
        let found = self.rest().starts_with(prefix);
        if found {
            self.at += prefix.len();
        }
        found
    }

    /// Consumes the first of these words the rest starts with, and returns its place in the list.
    fn eat_word(&mut self, words: &[&str]) -> Option<usize> {
        let place = words
            .iter()
            .position(|word| self.rest().starts_with(word))?;
        self.at += words[place].len();
        Some(place)
    }

    /// Consumes a run of ASCII digits, if any.
    fn digits(&mut self) -> Option<Number> {
        let length = self.rest().bytes().take_while(u8::is_ascii_digit).count();
        (length > 0).then(|| {
            let number = Number::of(&self.rest()[..length]);
            self.at += length;
            number
        })
    }

    /// Whether the rest starts with an ASCII digit.
    fn at_digit(&self) -> bool {
        self.rest()
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_digit())
    }

    /// Consumes one of the PEP 440 separators `.`, `-`, `_`.
    fn separator(&mut self) -> bool {
        self.eat_word(&[".", "-", "_"]).is_some()
    }

    /// Consumes an optional separator and the number that follows it; a separator followed by no number is left.
    fn separated_number(&mut self) -> Option<Number> {
        let start = self.at;
        self.separator();
        let number = self.digits();
        if number.is_none() {
            self.at = start;
        }
        number
    }
}

/// PEP 440, the versions of `PyPI` (VMT-24).
pub(crate) struct Pep440;

/// A PEP 440 version, as the fields it is ordered by, in order (the `_cmpkey` of the `packaging` project).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Pep440Key {
    epoch: Number,
    /// The release, its trailing zeros dropped.
    release: Vec<Number>,
    /// A dev release of no pre-release nor post-release first, then `a`, `b`, `rc`, then no pre-release.
    pre: (u8, Number),
    /// No post-release first.
    post: Option<Number>,
    /// A dev release before none.
    dev: (u8, Number),
    /// No local version first.
    local: Option<Vec<LocalSegment>>,
}

/// A segment of a local version: text before numbers (PEP 440).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LocalSegment {
    Text(String),
    Number(Number),
}

impl VersionOrder for Pep440 {
    type Key = Pep440Key;

    fn parse(version: &str) -> Option<Self::Key> {
        let text = version.trim().to_ascii_lowercase();
        let mut cursor = Cursor::new(&text);
        cursor.eat("v");
        let start = cursor.at;
        let epoch = match cursor.digits() {
            Some(epoch) if cursor.eat("!") => epoch,
            _ => {
                cursor.at = start;
                Number::of("0")
            }
        };
        let mut release = vec![cursor.digits()?];
        while cursor.rest().starts_with('.')
            && cursor.rest()[1..].starts_with(|c: char| c.is_ascii_digit())
        {
            cursor.eat(".");
            release.push(cursor.digits()?);
        }
        while release.last().is_some_and(Number::is_zero) {
            release.pop();
        }
        let pre = pre_release(&mut cursor);
        let post = post_release(&mut cursor);
        let dev = {
            let start = cursor.at;
            cursor.separator();
            if cursor.eat("dev") {
                Some(cursor.separated_number().unwrap_or_else(|| Number::of("0")))
            } else {
                cursor.at = start;
                None
            }
        };
        let local = if cursor.eat("+") {
            Some(local_version(&mut cursor)?)
        } else {
            None
        };
        if !cursor.is_done() {
            return None;
        }
        let pre = match (pre, &post, &dev) {
            (Some(pre), _, _) => pre,
            (None, None, Some(_)) => (0, Number::of("0")),
            (None, _, _) => (4, Number::of("0")),
        };
        let dev = dev.map_or((1, Number::of("0")), |dev| (0, dev));
        Some(Pep440Key {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering {
        a.cmp(b)
    }
}

/// The pre-release segment, its kind ranked `a` 1, `b` 2, `rc` 3, if the cursor is at one.
fn pre_release(cursor: &mut Cursor) -> Option<(u8, Number)> {
    const WORDS: [(&str, u8); 8] = [
        ("preview", 3),
        ("alpha", 1),
        ("beta", 2),
        ("pre", 3),
        ("rc", 3),
        ("a", 1),
        ("b", 2),
        ("c", 3),
    ];
    let start = cursor.at;
    cursor.separator();
    let words = WORDS.map(|(word, _)| word);
    let Some(place) = cursor.eat_word(&words) else {
        cursor.at = start;
        return None;
    };
    let number = cursor.separated_number().unwrap_or_else(|| Number::of("0"));
    Some((WORDS[place].1, number))
}

/// The post-release segment, explicit or implicit (`1.0-1`), if the cursor is at one.
fn post_release(cursor: &mut Cursor) -> Option<Number> {
    let start = cursor.at;
    if cursor.eat("-") && cursor.at_digit() {
        return cursor.digits();
    }
    cursor.at = start;
    cursor.separator();
    if cursor.eat_word(&["post", "rev", "r"]).is_some() {
        return Some(cursor.separated_number().unwrap_or_else(|| Number::of("0")));
    }
    cursor.at = start;
    None
}

/// The segments of a local version, separated by `.`, `-` or `_`, each of ASCII letters and digits.
fn local_version(cursor: &mut Cursor) -> Option<Vec<LocalSegment>> {
    let mut segments = Vec::new();
    loop {
        let length = cursor
            .rest()
            .bytes()
            .take_while(u8::is_ascii_alphanumeric)
            .count();
        if length == 0 {
            return None;
        }
        let segment = &cursor.rest()[..length];
        segments.push(if segment.bytes().all(|b| b.is_ascii_digit()) {
            LocalSegment::Number(Number::of(segment))
        } else {
            LocalSegment::Text(segment.to_owned())
        });
        cursor.at += length;
        if cursor.is_done() {
            return Some(segments);
        }
        if !cursor.separator() {
            return None;
        }
    }
}

/// The ordering of `Maven`, by the version order specification of Maven's `ComparableVersion` (VMT-25).
pub(crate) struct Maven;

/// What separates a Maven token from the one before it: a hyphen also stands for a change between digits and letters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Separator {
    Dot,
    Hyphen,
}

/// The value of a Maven token.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MavenValue {
    Number(Number),
    /// A qualifier in lower case, its aliases resolved (`cr` as `rc`; `ga`, `final`, `release` as the empty one).
    Qualifier(String),
}

impl MavenValue {
    /// Whether the value is a null one, trimmed at the end of a hyphen group: `0` or the empty qualifier.
    fn is_null(&self) -> bool {
        match self {
            Self::Number(number) => number.is_zero(),
            Self::Qualifier(qualifier) => qualifier.is_empty(),
        }
    }
}

/// A Maven version: its tokens, each with the separator before it.
#[derive(Debug)]
pub(crate) struct MavenKey(Vec<(Separator, MavenValue)>);

impl VersionOrder for Maven {
    type Key = MavenKey;

    fn parse(version: &str) -> Option<Self::Key> {
        let text = version.trim().to_lowercase();
        let mut raw: Vec<(Separator, String, bool)> = Vec::new();
        let mut separator = Separator::Dot;
        let mut current = String::new();
        for c in text.chars() {
            match c {
                '.' | '-' => {
                    raw.push((separator, std::mem::take(&mut current), false));
                    separator = if c == '.' {
                        Separator::Dot
                    } else {
                        Separator::Hyphen
                    };
                }
                _ => {
                    let is_digit = c.is_ascii_digit();
                    if current
                        .chars()
                        .last()
                        .is_some_and(|last| last.is_ascii_digit() != is_digit)
                    {
                        raw.push((separator, std::mem::take(&mut current), is_digit));
                        separator = Separator::Hyphen;
                    }
                    current.push(c);
                }
            }
        }
        raw.push((separator, current, false));
        let mut groups: Vec<Vec<(Separator, MavenValue)>> = Vec::new();
        for (separator, token, followed_by_digit) in raw {
            let value = maven_value(&token, followed_by_digit);
            match groups.last_mut() {
                Some(group) if separator == Separator::Dot => group.push((separator, value)),
                _ => groups.push(vec![(separator, value)]),
            }
        }
        let mut tokens = Vec::new();
        for mut group in groups {
            while group.last().is_some_and(|(_, value)| value.is_null()) {
                group.pop();
            }
            tokens.extend(group);
        }
        Some(MavenKey(tokens))
    }

    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering {
        let length = a.0.len().max(b.0.len());
        (0..length)
            .map(|i| match (a.0.get(i), b.0.get(i)) {
                (Some(a), Some(b)) => compare_maven_tokens(a, b),
                (Some(a), None) => compare_maven_to_null(a),
                (None, Some(b)) => compare_maven_to_null(b).reverse(),
                (None, None) => Ordering::Equal,
            })
            .find(|order| order.is_ne())
            .unwrap_or(Ordering::Equal)
    }
}

/// The value of a token: empty as `0`, digits as a number, `a`, `b`, `m` directly followed by a digit as `alpha`,
/// `beta`, `milestone`, and the aliases of the qualifiers resolved.
fn maven_value(token: &str, followed_by_digit: bool) -> MavenValue {
    if token.is_empty() {
        return MavenValue::Number(Number::of("0"));
    }
    if token.bytes().all(|b| b.is_ascii_digit()) {
        return MavenValue::Number(Number::of(token));
    }
    let qualifier = match (token, followed_by_digit) {
        ("a", true) => "alpha",
        ("b", true) => "beta",
        ("m", true) => "milestone",
        ("cr", _) => "rc",
        ("ga" | "final" | "release", _) => "",
        (other, _) => other,
    };
    MavenValue::Qualifier(qualifier.to_owned())
}

/// The order of the kinds of token: a qualifier, then a number after a hyphen, then a number after a dot.
fn maven_kind((separator, value): &(Separator, MavenValue)) -> u8 {
    match (value, separator) {
        (MavenValue::Qualifier(_), _) => 0,
        (MavenValue::Number(_), Separator::Hyphen) => 1,
        (MavenValue::Number(_), Separator::Dot) => 2,
    }
}

fn compare_maven_tokens(a: &(Separator, MavenValue), b: &(Separator, MavenValue)) -> Ordering {
    match (&a.1, &b.1) {
        (MavenValue::Number(x), MavenValue::Number(y)) if a.0 == b.0 => x.cmp(y),
        (MavenValue::Qualifier(x), MavenValue::Qualifier(y)) => compare_qualifiers(x, y),
        _ => maven_kind(a).cmp(&maven_kind(b)),
    }
}

/// The order of a token against the missing token of a shorter version: `0` against a number, the release (the
/// empty qualifier) against a qualifier.
fn compare_maven_to_null(token: &(Separator, MavenValue)) -> Ordering {
    match &token.1 {
        MavenValue::Number(number) => number.cmp(&Number::of("0")),
        MavenValue::Qualifier(qualifier) => compare_qualifiers(qualifier, ""),
    }
}

/// `alpha` < `beta` < `milestone` < `rc` < `snapshot` < the release < `sp` < any other, by text.
fn compare_qualifiers(a: &str, b: &str) -> Ordering {
    const KNOWN: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];
    let rank = |qualifier: &str| {
        KNOWN
            .iter()
            .position(|known| *known == qualifier)
            .unwrap_or(KNOWN.len())
    };
    rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
}
