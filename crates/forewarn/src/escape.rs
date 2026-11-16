//! The escaping of a value read from the SBOM or a feed, shared by the reports and the error lines (`report`, `main`,
//! CHK-14, MCH-18, MCH-23) and the early warning draft (`early_warning`, EWD-16) so that the writers cannot drift.

/// Passes `c` to `push`, or its escape when it is a control character (`\n`, `\u{1b}`) or a character that hides or
/// reorders text (`\u{202e}`), so that it cannot forge a line or a terminal sequence, nor reorder or hide the text
/// around it. The backslash passes: the reports escape it (`push_escaped`), the draft as Markdown punctuation (EWD-16).
pub fn escape_char(c: char, mut push: impl FnMut(char)) {
    if c.is_control() {
        c.escape_default().for_each(push);
    } else if hides_text(c) {
        c.escape_unicode().for_each(push);
    } else {
        push(c);
    }
}

/// Pushes `value` with each of its characters escaped as `escape_char` does and each backslash as `\\`, so that each
/// escape reads back to one value (CHK-14, MCH-18).
pub fn push_escaped(text: &mut String, value: &str) {
    for c in value.chars() {
        if c == '\\' {
            text.push_str("\\\\");
        } else {
            escape_char(c, |e| text.push(e));
        }
    }
}

/// `value` escaped as `push_escaped` does, for a line of standard error (MCH-23).
pub fn escaped(value: &str) -> String {
    let mut text = String::with_capacity(value.len());
    push_escaped(&mut text, value);
    text
}

/// Whether `c` hides or reorders text (EWD-16): a `Default_Ignorable_Code_Point`, the separator U+2028 or U+2029, a
/// `White_Space` character other than the space U+0020, or U+2800 BRAILLE PATTERN BLANK, as Unicode 16.0 lists them
/// (`DerivedCoreProperties.txt`, `PropList.txt`). A viewer draws them as nothing or as a blank, or uses them to reorder
/// the text around them (the "Trojan Source" trick, the tag characters of "ASCII smuggling", the Hangul fillers); the
/// format characters it draws (U+0600, U+06DD, U+FFF9) pass, as the derivation of `Default_Ignorable_Code_Point`
/// leaves them out. The control characters among `White_Space` are escaped before it is asked. A test compares it, for
/// every scalar value, with the verbatim extracts of those files in `data/ucd-16.0.0` (Unicode License v3).
fn hides_text(c: char) -> bool {
    matches!(
        c,
        '\u{00a0}'
            | '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{1680}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{2000}'..='\u{200f}'
            | '\u{2028}'..='\u{202f}'
            | '\u{205f}'..='\u{206f}'
            | '\u{2800}'
            | '\u{3000}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

#[cfg(test)]
mod tests {
    use super::{escaped, hides_text};
    use std::collections::BTreeSet;

    /// The code points of a verbatim extract of the Unicode 16.0 data (`data/ucd-16.0.0`), checked against the version
    /// of its header, the property each of its lines names, the only one, and the `# Total code points` of its section,
    /// so that a wrong section or a dropped line fails.
    fn code_points_of(extract: &str, property: &str) -> BTreeSet<u32> {
        assert!(
            extract
                .lines()
                .next()
                .is_some_and(|line| line.ends_with("-16.0.0.txt")),
            "the extract is not of Unicode 16.0.0"
        );
        let mut code_points = BTreeSet::new();
        let mut total = None;
        for line in extract.lines() {
            if let Some(count) = line.strip_prefix("# Total code points: ") {
                total = Some(count.parse::<usize>().expect("a total"));
            } else if !line.starts_with('#') && !line.trim().is_empty() {
                let mut fields = line.split('#').next().expect("the data").split(';');
                let range = fields.next().expect("a range").trim();
                assert_eq!(
                    fields.next().map(str::trim),
                    Some(property),
                    "the extract holds another property"
                );
                let (first, last) = range.split_once("..").unwrap_or((range, range));
                let bound = |hex: &str| u32::from_str_radix(hex, 16).expect("a code point");
                code_points.extend(bound(first)..=bound(last));
            }
        }
        assert_eq!(Some(code_points.len()), total, "the extract lost a line");
        code_points
    }

    // spec: EWD-16 (internal: every scalar value against the Unicode data, which no SBOM fixture would walk through)
    #[test]
    fn the_characters_that_hide_text_are_those_the_unicode_data_lists() {
        let mut listed = code_points_of(
            include_str!(
                "../data/ucd-16.0.0/DerivedCoreProperties-Default_Ignorable_Code_Point.txt"
            ),
            "Default_Ignorable_Code_Point",
        );
        listed.extend(code_points_of(
            include_str!("../data/ucd-16.0.0/PropList-White_Space.txt"),
            "White_Space",
        ));
        listed.remove(&0x20);
        listed.extend([0x2028, 0x2029, 0x2800]);
        // The control characters among White_Space (`\t`, U+0085) are escaped before `hides_text` is asked.
        let wrong: Vec<String> = (0..=0x0010_ffff_u32)
            .filter_map(char::from_u32)
            .filter(|c| !c.is_control())
            .filter(|&c| hides_text(c) != listed.contains(&u32::from(c)))
            .map(|c| format!("U+{:04X}", u32::from(c)))
            .collect();
        assert!(
            wrong.is_empty(),
            "hides_text disagrees with Unicode 16.0 on {wrong:?}"
        );
    }

    // spec: EWD-16 (internal: samples of the table, which no SBOM fixture would walk through)
    #[test]
    fn each_character_that_hides_text_is_escaped_and_the_letters_around_it_are_not() {
        for c in [
            '\u{a0}',
            '\u{ad}',
            '\u{34f}',
            '\u{61c}',
            '\u{115f}',
            '\u{1160}',
            '\u{1680}',
            '\u{180e}',
            '\u{2000}',
            '\u{200a}',
            '\u{200c}',
            '\u{200d}',
            '\u{2028}',
            '\u{2029}',
            '\u{206a}',
            '\u{206f}',
            '\u{2800}',
            '\u{3000}',
            '\u{3164}',
            '\u{fe00}',
            '\u{fe0f}',
            '\u{ffa0}',
            '\u{e0001}',
            '\u{e0041}',
            '\u{e007f}',
            '\u{e0100}',
            '\u{e01ef}',
        ] {
            assert_eq!(
                escaped(&c.to_string()),
                format!("\\u{{{:x}}}", u32::from(c))
            );
        }
        for c in [
            'a',
            'é',
            'ی',
            'क',
            '\u{600}',
            '\u{6dd}',
            '\u{110bd}',
            '\u{3165}',
            '\u{fff9}',
            '\u{fffb}',
            '\u{fffc}',
            '\u{13430}',
            '\u{1f600}',
        ] {
            assert_eq!(escaped(&c.to_string()), c.to_string());
        }
    }
}
