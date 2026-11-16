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

/// Whether `c` hides or reorders text (EWD-16): of the general category Cf, the separator U+2028 or U+2029, or a
/// `Default_Ignorable_Code_Point`, as Unicode 16.0 lists them (`DerivedGeneralCategory.txt`,
/// `DerivedCoreProperties.txt`). A viewer draws most of them as nothing or uses them to reorder the text around them
/// (the "Trojan Source" trick, the tag characters of "ASCII smuggling", the Hangul fillers); the few format characters
/// it draws (U+0600, U+06DD) are escaped with the rest of Cf, as EWD-16 sets. A test compares it, for every
/// scalar value, with the verbatim extracts of those files in `data/ucd-16.0.0` (Unicode License v3).
fn hides_text(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

#[cfg(test)]
mod tests {
    use super::{escaped, hides_text};
    use std::collections::BTreeSet;

    /// The code points of the section `heading` of a verbatim extract of the Unicode 16.0 data (`data/ucd-16.0.0`),
    /// checked against the version of its header, its heading, the only one, and the `# Total code points` of the
    /// section, so that a wrong section or a dropped line fails.
    fn code_points_of(extract: &str, heading: &str) -> BTreeSet<u32> {
        assert!(
            extract
                .lines()
                .next()
                .is_some_and(|line| line.ends_with("-16.0.0.txt")),
            "the extract is not of Unicode 16.0.0"
        );
        let headings: Vec<&str> = extract
            .lines()
            .filter(|line| {
                line.starts_with("# General_Category=") || line.starts_with("# Derived Property: ")
            })
            .collect();
        assert_eq!(headings, [heading], "the extract holds another section");
        let mut code_points = BTreeSet::new();
        let mut total = None;
        for line in extract.lines() {
            if let Some(count) = line.strip_prefix("# Total code points: ") {
                total = Some(count.parse::<usize>().expect("a total"));
            } else if !line.starts_with('#') && !line.trim().is_empty() {
                let range = line.split(';').next().expect("a range").trim();
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
            include_str!("../data/ucd-16.0.0/DerivedGeneralCategory-Format.txt"),
            "# General_Category=Format",
        );
        listed.extend(code_points_of(
            include_str!(
                "../data/ucd-16.0.0/DerivedCoreProperties-Default_Ignorable_Code_Point.txt"
            ),
            "# Derived Property: Default_Ignorable_Code_Point",
        ));
        listed.extend([0x2028, 0x2029]);
        let wrong: Vec<String> = (0..=0x0010_ffff_u32)
            .filter_map(char::from_u32)
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
            '\u{ad}',
            '\u{34f}',
            '\u{600}',
            '\u{61c}',
            '\u{115f}',
            '\u{1160}',
            '\u{180e}',
            '\u{200c}',
            '\u{200d}',
            '\u{2028}',
            '\u{2029}',
            '\u{206a}',
            '\u{206f}',
            '\u{3164}',
            '\u{fe00}',
            '\u{fe0f}',
            '\u{ffa0}',
            '\u{fff9}',
            '\u{fffb}',
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
        for c in ['a', 'é', 'ی', 'क', '\u{3165}', '\u{fffc}', '\u{1f600}'] {
            assert_eq!(escaped(&c.to_string()), c.to_string());
        }
    }
}
