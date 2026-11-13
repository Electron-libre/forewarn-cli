//! A day of the calendar, as the domain needs it: the date a list of exploited vulnerabilities gives for adding one
//! (`specs/exploited-flagging.md`), and a moment of UTC to the second, from which the CRA reporting deadlines are
//! computed (`specs/reporting-deadlines.md`, ADR 0011).

use std::fmt;
use std::time::Duration;

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

/// The seconds of a day: leap seconds are not counted (ADR 0011).
const SECONDS_PER_DAY: u64 = 86_400;

/// A moment of Coordinated Universal Time to the second, ordered by its date, then its time of day (RDL-5, RDL-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    date: Date,
    hour: u8,
    minute: u8,
    second: u8,
}

impl Instant {
    /// The moment of `date` at `hour:minute:second` UTC (RDL-5).
    ///
    /// # Errors
    /// [`InvalidTime`] for a time of day out of `00:00:00` to `23:59:59` (RDL-6).
    pub fn new(date: Date, hour: u8, minute: u8, second: u8) -> Result<Self, InvalidTime> {
        if hour < 24 && minute < 60 && second < 60 {
            Ok(Self {
                date,
                hour,
                minute,
                second,
            })
        } else {
            Err(InvalidTime {
                hour,
                minute,
                second,
            })
        }
    }

    #[must_use]
    pub fn date(self) -> Date {
        self.date
    }

    #[must_use]
    pub fn hour(self) -> u8 {
        self.hour
    }

    #[must_use]
    pub fn minute(self) -> u8 {
        self.minute
    }

    #[must_use]
    pub fn second(self) -> u8 {
        self.second
    }

    /// The moment `duration` later, its fraction of a second dropped; `None` past `9999-12-31T23:59:59Z` (RDL-9).
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let seconds = self.seconds().checked_add(duration.as_secs())?;
        Self::from_seconds(seconds)
    }

    /// The seconds since `0001-01-01T00:00:00Z`.
    fn seconds(self) -> u64 {
        days_from_civil(self.date) * SECONDS_PER_DAY
            + u64::from(self.hour) * 3600
            + u64::from(self.minute) * 60
            + u64::from(self.second)
    }

    /// The moment `seconds` after `0001-01-01T00:00:00Z`, `None` past the year 9999.
    fn from_seconds(seconds: u64) -> Option<Self> {
        let date = civil_from_days(seconds / SECONDS_PER_DAY)?;
        let of_day = seconds % SECONDS_PER_DAY;
        let [hour, minute, second] =
            [of_day / 3600, of_day / 60 % 60, of_day % 60].map(|part| u8::try_from(part).ok());
        Self::new(date, hour?, minute?, second?).ok()
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ`, RFC 3339 in UTC (RDL-7).
impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}T{:02}:{:02}:{:02}Z",
            self.date, self.hour, self.minute, self.second
        )
    }
}

/// A time of day out of `00:00:00` to `23:59:59` (RDL-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTime {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl fmt::Display for InvalidTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "not a time of day: `{:02}:{:02}:{:02}`",
            self.hour, self.minute, self.second
        )
    }
}

impl std::error::Error for InvalidTime {}

/// The days from `0001-01-01` to `date`, the proleptic Gregorian calendar counted in eras of 400 years (146 097 days).
fn days_from_civil(date: Date) -> u64 {
    // From March, so that the 29th of February ends a year: years 0 to 9999, never negative.
    let (year, month) = if date.month <= 2 {
        (u64::from(date.year) - 1, u64::from(date.month) + 9)
    } else {
        (u64::from(date.year), u64::from(date.month) - 3)
    };
    let era = year / 400;
    let year_of_era = year % 400;
    let day_of_year = (153 * month + 2) / 5 + u64::from(date.day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    // 306 days from 0000-03-01 to 0001-01-01.
    era * 146_097 + day_of_era - 306
}

/// The day `days` after `0001-01-01`, `None` past `9999-12-31`.
fn civil_from_days(days: u64) -> Option<Date> {
    let days = days.checked_add(306)?;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month + 2) / 5 + 1;
    let (year, month) = if month < 10 {
        (era * 400 + year_of_era, month + 3)
    } else {
        (era * 400 + year_of_era + 1, month - 9)
    };
    Date::new(
        u16::try_from(year).ok()?,
        u8::try_from(month).ok()?,
        u8::try_from(day).ok()?,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::{Date, civil_from_days, days_from_civil};

    // spec: RDL-9 (internal: every day of years 1 to 9999 through the private conversion, too many for the boundary)
    #[test]
    fn counts_every_day_of_the_calendar_once_in_order() {
        let mut expected = 0;
        for year in 1..=9999 {
            for month in 1..=12 {
                for day in 1..=31 {
                    let Ok(date) = Date::new(year, month, day) else {
                        continue;
                    };
                    assert_eq!(days_from_civil(date), expected, "{date}");
                    assert_eq!(civil_from_days(expected), Some(date), "{date}");
                    expected += 1;
                }
            }
        }
        assert_eq!(civil_from_days(expected), None);
    }
}
