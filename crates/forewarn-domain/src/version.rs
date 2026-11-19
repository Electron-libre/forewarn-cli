//! The version orderings a range is compared by (`specs/version-ordering.md`, VOR-1; VMT-9); the Debian
//! ordering in its module.

use std::cmp::Ordering;

use crate::vulnerability::RangeKind;

mod debian;

pub(crate) use debian::Debian;

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
    /// PEP 440, the versions of `PyPI` (VOR-2).
    Pep440,
    /// The ordering of `Maven` (VOR-3).
    Maven,
    /// The ordering of `RubyGems`, as `Gem::Version` (VOR-4).
    RubyGems,
    /// The ordering of `NuGet`, as `NuGet.Versioning` (VOR-5).
    NuGet,
    /// The ordering of `Packagist`, as Composer normalizes versions and PHP compares them (VOR-6).
    Packagist,
    /// The ordering of `Debian:<release>`, as `dpkg` compares versions (VOR-7).
    Debian,
}

impl Scheme {
    /// The ordering a range of this kind is compared by, for a package whose ecosystem orders its versions by
    /// `ecosystem`, or `None` when matching does not compare it (VMT-9, VOR-1).
    pub(crate) fn of(kind: RangeKind, ecosystem: Self) -> Option<Self> {
        match kind {
            RangeKind::Semver => Some(Self::Semver),
            RangeKind::Ecosystem => Some(ecosystem),
            RangeKind::Git => None,
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

/// PEP 440, the versions of `PyPI` (VOR-2).
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

/// The ordering of `Maven`, by the algorithm of Maven's `ComparableVersion` (VOR-3).
pub(crate) struct Maven;

/// An item of a Maven version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MavenItem {
    Number(Number),
    /// A qualifier in lower case, its aliases resolved (`cr` as `rc`; `ga`, `final`, `release` as the empty one).
    Qualifier(String),
    /// The items after a hyphen or a change between digits and letters.
    List(Vec<MavenItem>),
}

impl MavenItem {
    /// Whether the item is a null one, dropped at the end of a list: `0`, the empty qualifier or an empty list.
    fn is_null(&self) -> bool {
        match self {
            Self::Number(number) => number.is_zero(),
            Self::Qualifier(qualifier) => qualifier.is_empty(),
            Self::List(items) => items.is_empty(),
        }
    }
}

impl VersionOrder for Maven {
    /// The items of the version, the outer list.
    type Key = Vec<MavenItem>;

    fn parse(version: &str) -> Option<Self::Key> {
        let text: Vec<char> = version.trim().to_lowercase().chars().collect();
        let token = |from: usize, to: usize| text[from..to].iter().collect::<String>();
        // The open lists, each nested as the last item of the one before it once closed.
        let mut lists: Vec<Vec<MavenItem>> = vec![Vec::new()];
        let mut is_digit = false;
        let mut start = 0;
        for (i, &c) in text.iter().enumerate() {
            let list = lists.len() - 1;
            if c == '.' || c == '-' {
                let item = if i == start {
                    MavenItem::Number(Number::of("0"))
                } else {
                    maven_item(is_digit, &token(start, i), false)
                };
                lists[list].push(item);
                start = i + 1;
                if c == '-' {
                    lists.push(Vec::new());
                }
            } else if c.is_ascii_digit() {
                if !is_digit && i > start {
                    lists[list].push(maven_item(false, &token(start, i), true));
                    start = i;
                    lists.push(Vec::new());
                }
                is_digit = true;
            } else {
                if is_digit && i > start {
                    lists[list].push(maven_item(true, &token(start, i), false));
                    start = i;
                    lists.push(Vec::new());
                }
                is_digit = false;
            }
        }
        if text.len() > start {
            let last = lists.len() - 1;
            lists[last].push(maven_item(is_digit, &token(start, text.len()), false));
        }
        loop {
            let mut list = lists.pop()?;
            normalize(&mut list);
            match lists.last_mut() {
                Some(parent) => parent.push(MavenItem::List(list)),
                None => return Some(list),
            }
        }
    }

    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering {
        compare_maven_lists(a, b)
    }
}

/// Drops the null items at the end of a list, past its nested lists, up to its last number or qualifier not null.
fn normalize(list: &mut Vec<MavenItem>) {
    let mut i = list.len();
    while i > 0 {
        i -= 1;
        if list[i].is_null() {
            list.remove(i);
        } else if !matches!(list[i], MavenItem::List(_)) {
            break;
        }
    }
}

/// A number, or a qualifier: `a`, `b`, `m` directly followed by a digit read as `alpha`, `beta`, `milestone`, and the
/// aliases resolved.
fn maven_item(is_digit: bool, token: &str, followed_by_digit: bool) -> MavenItem {
    if is_digit {
        return MavenItem::Number(Number::of(token));
    }
    let qualifier = match (token, followed_by_digit) {
        ("a", true) => "alpha",
        ("b", true) => "beta",
        ("m", true) => "milestone",
        ("cr", _) => "rc",
        ("ga" | "final" | "release", _) => "",
        (other, _) => other,
    };
    MavenItem::Qualifier(qualifier.to_owned())
}

/// The order of an item against another, or against the missing item of a shorter list: a qualifier before a list, a
/// list before a number; a missing item reads as `0` against a number, the release against a qualifier, and against a
/// list as the list's first item does.
fn compare_maven_items(a: &MavenItem, b: Option<&MavenItem>) -> Ordering {
    use MavenItem::{List, Number as Num, Qualifier};
    match (a, b) {
        (Num(a), None) => a.cmp(&Number::of("0")),
        (Num(a), Some(Num(b))) => a.cmp(b),
        (Num(_), Some(_)) | (List(_), Some(Qualifier(_))) => Ordering::Greater,
        (Qualifier(a), None) => compare_qualifiers(a, ""),
        (Qualifier(a), Some(Qualifier(b))) => compare_qualifiers(a, b),
        (Qualifier(_) | List(_), Some(Num(_))) | (Qualifier(_), Some(List(_))) => Ordering::Less,
        (List(a), None) => a
            .first()
            .map_or(Ordering::Equal, |first| compare_maven_items(first, None)),
        (List(a), Some(List(b))) => compare_maven_lists(a, b),
    }
}

fn compare_maven_lists(a: &[MavenItem], b: &[MavenItem]) -> Ordering {
    (0..a.len().max(b.len()))
        .map(|i| match (a.get(i), b.get(i)) {
            (Some(a), b) => compare_maven_items(a, b),
            (None, Some(b)) => compare_maven_items(b, None).reverse(),
            (None, None) => Ordering::Equal,
        })
        .find(|order| order.is_ne())
        .unwrap_or(Ordering::Equal)
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

/// The ordering of `RubyGems`, as `Gem::Version` reads and compares versions (VOR-4).
pub(crate) struct RubyGems;

/// A segment of a `RubyGems` version: text (a pre-release) before numbers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GemSegment {
    Text(String),
    Number(Number),
}

impl VersionOrder for RubyGems {
    /// The canonical segments: the zeros at the end of the numbers before the first text dropped, and those at the
    /// end of the rest.
    type Key = Vec<GemSegment>;

    fn parse(version: &str) -> Option<Self::Key> {
        let version = match version.trim() {
            "" => "0",
            version => version,
        };
        if !is_gem_version(version) {
            return None;
        }
        let version = version.replace('-', ".pre.");
        let mut segments = Vec::new();
        let mut rest = version.as_str();
        while let Some(start) = rest.find(|c: char| c.is_ascii_alphanumeric()) {
            rest = &rest[start..];
            let is_digit = rest.starts_with(|c: char| c.is_ascii_digit());
            let length = rest
                .find(|c: char| !c.is_ascii_alphanumeric() || c.is_ascii_digit() != is_digit)
                .unwrap_or(rest.len());
            let segment = &rest[..length];
            segments.push(if is_digit {
                GemSegment::Number(Number::of(segment))
            } else {
                GemSegment::Text(segment.to_owned())
            });
            rest = &rest[length..];
        }
        let first_text = segments
            .iter()
            .position(|segment| matches!(segment, GemSegment::Text(_)))
            .unwrap_or(segments.len());
        let mut text = segments.split_off(first_text);
        drop_trailing_zeros(&mut segments);
        drop_trailing_zeros(&mut text);
        segments.extend(text);
        Some(segments)
    }

    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering {
        let zero = GemSegment::Number(Number::of("0"));
        (0..a.len().max(b.len()))
            .map(|i| a.get(i).unwrap_or(&zero).cmp(b.get(i).unwrap_or(&zero)))
            .find(|order| order.is_ne())
            .unwrap_or(Ordering::Equal)
    }
}

fn drop_trailing_zeros(segments: &mut Vec<GemSegment>) {
    while matches!(segments.last(), Some(GemSegment::Number(number)) if number.is_zero()) {
        segments.pop();
    }
}

/// Whether the version follows the pattern of `Gem::Version`: `[0-9]+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?`.
fn is_gem_version(version: &str) -> bool {
    let (release, pre) = match version.split_once('-') {
        Some((release, pre)) => (release, Some(pre)),
        None => (version, None),
    };
    let mut parts = release.split('.');
    let starts_with_number = parts
        .next()
        .is_some_and(|first| !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit()));
    let release_ok = starts_with_number
        && parts.all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric()));
    let pre_ok = pre.is_none_or(|pre| {
        pre.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    });
    release_ok && pre_ok
}

/// The ordering of `NuGet`, as `NuGet.Versioning` reads and compares versions by default (VOR-5).
pub(crate) struct NuGet;

/// A `NuGet` version, as the fields it is ordered by, its build metadata dropped.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NuGetKey {
    /// The four numeric parts, the missing ones as `0`.
    parts: [Number; 4],
    /// The pre-release labels, if any.
    pre: Option<Vec<NuGetLabel>>,
}

/// A pre-release label of a `NuGet` version: numbers before text, text compared without regard to case.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum NuGetLabel {
    Number(Number),
    Text(String),
}

impl VersionOrder for NuGet {
    type Key = NuGetKey;

    fn parse(version: &str) -> Option<Self::Key> {
        let (main, metadata) = match version.trim().split_once('+') {
            Some((main, metadata)) => (main, Some(metadata)),
            None => (version.trim(), None),
        };
        let (release, pre) = match main.split_once('-') {
            Some((release, pre)) => (release, Some(pre)),
            None => (main, None),
        };
        let numbers: Vec<&str> = release.split('.').collect();
        if numbers.len() > 4
            || !numbers
                .iter()
                .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        if !metadata.is_none_or(are_nuget_labels) || !pre.is_none_or(are_nuget_labels) {
            return None;
        }
        let parts = std::array::from_fn(|i| Number::of(numbers.get(i).copied().unwrap_or("0")));
        let pre = pre.map(|pre| {
            pre.split('.')
                .map(|label| {
                    if label.bytes().all(|b| b.is_ascii_digit()) {
                        NuGetLabel::Number(Number::of(label))
                    } else {
                        NuGetLabel::Text(label.to_ascii_lowercase())
                    }
                })
                .collect()
        });
        Some(NuGetKey { parts, pre })
    }

    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering {
        a.parts.cmp(&b.parts).then_with(|| match (&a.pre, &b.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        })
    }
}

/// Whether the text is made of non-empty labels of ASCII letters, digits and `-`, separated by `.`.
fn are_nuget_labels(text: &str) -> bool {
    text.split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// The ordering of `Packagist`: a version normalized as Composer's `VersionParser` does, then compared by PHP's
/// `version_compare` (VOR-6).
pub(crate) struct Packagist;

/// A part of a normalized `Packagist` version, in the order of `version_compare`: `dev` < `alpha` < `beta` < `RC` <
/// a number < `patch`, two numbers compared as numbers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PhpPart {
    Dev,
    Alpha,
    Beta,
    Rc,
    Number(Number),
    Patch,
}

/// `x` in a branch such as `1.x-dev`.
const BRANCH_X: &str = "9999999";

impl VersionOrder for Packagist {
    /// The parts of the normalized version, in order.
    type Key = Vec<PhpPart>;

    fn parse(version: &str) -> Option<Self::Key> {
        let version = version.trim().to_ascii_lowercase();
        if version.starts_with("dev-") || version.contains(char::is_whitespace) {
            return None;
        }
        let version = match version.split_once('+') {
            Some((main, metadata))
                if !main.is_empty() && !metadata.is_empty() && !main.contains(',') =>
            {
                main
            }
            Some(_) => return None,
            None => &version,
        };
        let version = version.strip_prefix('v').unwrap_or(version);
        classical(version)
            .or_else(|| dated(version))
            .or_else(|| branch(version))
    }

    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering {
        // A version going on past the other: after it when it goes on with a number, else as its word against one.
        let going_on = |part: &PhpPart| match part {
            PhpPart::Number(_) => Ordering::Greater,
            word => word.cmp(&PhpPart::Number(Number::of("0"))),
        };
        a.iter()
            .zip(b)
            .map(|(a, b)| a.cmp(b))
            .find(|order| order.is_ne())
            .unwrap_or_else(|| match (a.get(b.len()), b.get(a.len())) {
                (Some(rest), _) => going_on(rest),
                (_, Some(rest)) => going_on(rest).reverse(),
                (None, None) => Ordering::Equal,
            })
    }
}

/// A classical version: one to four numbers, the first of at most five digits, padded with `0` to four, then the
/// modifier.
fn classical(version: &str) -> Option<Vec<PhpPart>> {
    let mut cursor = Cursor::new(version);
    let major = cursor.rest().bytes().take_while(u8::is_ascii_digit).count();
    if !(1..=5).contains(&major) {
        return None;
    }
    let mut parts = vec![PhpPart::Number(cursor.digits()?)];
    while parts.len() < 4
        && cursor.rest().starts_with('.')
        && cursor.rest()[1..].starts_with(|c: char| c.is_ascii_digit())
    {
        cursor.eat(".");
        parts.push(PhpPart::Number(cursor.digits()?));
    }
    parts.resize_with(4, || PhpPart::Number(Number::of("0")));
    parts.extend(modifier(cursor.rest())?);
    Some(parts)
}

/// A date version: four digits, one to six groups of two, then up to two groups of one to three, each group after an
/// optional `.`, `:` or `-`, the numbers kept as they are written, then the modifier.
fn dated(version: &str) -> Option<Vec<PhpPart>> {
    let date_length = version
        .bytes()
        .take_while(|b| b.is_ascii_digit() || matches!(b, b'.' | b':' | b'-'))
        .count();
    (4..=date_length).rev().find_map(|end| {
        let (date, rest) = version.split_at(end);
        if !is_date(date.as_bytes()) {
            return None;
        }
        let mut parts: Vec<PhpPart> = date
            .split(|c: char| !c.is_ascii_digit())
            .filter(|digits| !digits.is_empty())
            .map(|digits| PhpPart::Number(Number::of(digits)))
            .collect();
        parts.extend(modifier(rest)?);
        Some(parts)
    })
}

/// Whether the text matches `\d{4}(?:[.:-]?\d{2}){1,6}(?:[.:-]?\d{1,3}){0,2}` whole.
fn is_date(text: &[u8]) -> bool {
    /// Whether the text is the groups left after `twos` groups of two digits and `tails` of one to three.
    fn groups(text: &[u8], twos: usize, tails: usize) -> bool {
        if text.is_empty() {
            return twos >= 1;
        }
        let text = match text[0] {
            b'.' | b':' | b'-' => &text[1..],
            _ => text,
        };
        let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
        let two = tails == 0 && twos < 6 && digits >= 2 && groups(&text[2..], twos + 1, 0);
        two || (twos >= 1
            && tails < 2
            && (1..=digits.min(3)).any(|length| groups(&text[length..], twos, tails + 1)))
    }
    text.len() >= 4 && text[..4].iter().all(u8::is_ascii_digit) && groups(&text[4..], 0, 0)
}

/// A branch such as `1.x-dev`: one to four numbers or `x` (`*`), the missing ones as `x`, each `x` as `9999999`.
fn branch(version: &str) -> Option<Vec<PhpPart>> {
    let name = version.strip_suffix("dev")?;
    let name = name.strip_suffix(['.', '-']).unwrap_or(name);
    let items: Vec<&str> = name.split('.').collect();
    let is_number = |item: &str| !item.is_empty() && item.bytes().all(|b| b.is_ascii_digit());
    if items.len() > 4
        || !is_number(items[0])
        || !items[1..]
            .iter()
            .all(|item| is_number(item) || matches!(*item, "x" | "*"))
    {
        return None;
    }
    let mut parts: Vec<PhpPart> = (0..4)
        .map(|i| match items.get(i) {
            Some(item) if is_number(item) => PhpPart::Number(Number::of(item)),
            _ => PhpPart::Number(Number::of(BRANCH_X)),
        })
        .collect();
    parts.push(PhpPart::Dev);
    Some(parts)
}

/// The modifier after the numbers, whole: an optional `.`, `_` or `-`, an optional stability with its numbers, an
/// optional `dev` after an optional `.` or `-`.
fn modifier(text: &str) -> Option<Vec<PhpPart>> {
    /// The stabilities, in the order Composer tries them, with the word they normalize to (`None`: `stable`).
    const STABILITIES: [(&str, Option<PhpPart>); 9] = [
        ("stable", None),
        ("beta", Some(PhpPart::Beta)),
        ("b", Some(PhpPart::Beta)),
        ("rc", Some(PhpPart::Rc)),
        ("alpha", Some(PhpPart::Alpha)),
        ("a", Some(PhpPart::Alpha)),
        ("patch", Some(PhpPart::Patch)),
        ("pl", Some(PhpPart::Patch)),
        ("p", Some(PhpPart::Patch)),
    ];
    let mut cursor = Cursor::new(text);
    cursor.eat_word(&[".", "_", "-"]);
    let mut parts = Vec::new();
    let mut stable = false;
    if let Some(place) = cursor.eat_word(&STABILITIES.map(|(word, _)| word)) {
        if let Some(word) = &STABILITIES[place].1 {
            parts.push(word.clone());
        } else {
            stable = true;
        }
        loop {
            let start = cursor.at;
            cursor.eat_word(&[".", "-"]);
            match cursor.digits() {
                Some(number) if !stable => parts.push(PhpPart::Number(number)),
                Some(_) => {}
                None => {
                    cursor.at = start;
                    break;
                }
            }
        }
    }
    let start = cursor.at;
    cursor.eat_word(&[".", "-"]);
    if cursor.eat("dev") {
        if !stable {
            parts.push(PhpPart::Dev);
        }
    } else {
        cursor.at = start;
    }
    cursor.is_done().then_some(parts)
}
