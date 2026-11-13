//! A day of the calendar, as the domain needs it: the date a list of exploited vulnerabilities gives for adding one
//! (`specs/exploited-flagging.md`), later the CRA reporting deadlines.

use std::fmt;

/// A day of the Gregorian calendar, ordered by year, then month, then day.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl Date {
    /// The date, when it exists in the Gregorian calendar, years 1 to 9999 (EXF-8).
    ///
    /// # Errors
    /// [`InvalidDate`] for a day that does not exist (`2026-02-30`, month `13`).
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, InvalidDate> {
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => 0,
        };
        if (1..=9999).contains(&year) && (1..=days).contains(&day) {
            Ok(Self { year, month, day })
        } else {
            Err(InvalidDate { year, month, day })
        }
    }

    #[must_use]
    pub fn year(self) -> u16 {
        self.year
    }

    #[must_use]
    pub fn month(self) -> u8 {
        self.month
    }

    #[must_use]
    pub fn day(self) -> u8 {
        self.day
    }
}

/// `YYYY-MM-DD`.
impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// A day that does not exist in the Gregorian calendar (EXF-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl fmt::Display for InvalidDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "not a date: `{:04}-{:02}-{:02}`",
            self.year, self.month, self.day
        )
    }
}

impl std::error::Error for InvalidDate {}
