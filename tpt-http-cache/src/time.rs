// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal HTTP-date parsing and formatting per RFC 9110 §5.6.7.
//!
//! This is a clean-room, dependency-free implementation supporting the three
//! historical date formats (`IMF-fixdate`, `RFC850`, and `asctime`) so that
//! `Date`, `Expires`, and `Last-Modified` headers can be interpreted without
//! pulling in a date library.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days since the Unix epoch (1970-01-01) for the given proleptic Gregorian
/// calendar date. Howard Hinnant's `days_from_civil` algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Weekday index for a calendar date, with Sunday = 0.
fn weekday_index(y: i64, m: u32, d: u32) -> u32 {
    let days = days_from_civil(y, m, d);
    (((days + 4) % 7) + 7) as u32 % 7
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn month_number(name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(&lower))
        .map(|i| i as u32 + 1)
}

fn parse_time(t: &str) -> Option<(u32, u32, u32)> {
    let mut it = t.splitn(3, ':');
    let h: u32 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let s: u32 = it.next()?.parse().ok()?;
    if h > 23 || m > 59 || s > 60 {
        return None;
    }
    Some((h, m, s))
}

fn parse_year(token: &str) -> Option<i64> {
    let y: i64 = token.parse().ok()?;
    if (0..=99).contains(&y) {
        // RFC 850 two-digit years are interpreted as 19yy.
        Some(1900 + y)
    } else {
        Some(y)
    }
}

/// Parse an `HTTP-date` (IMF-fixdate, RFC 850, or asctime) into a `SystemTime`.
///
/// Returns `None` if the value is not a recognisable date. Unparseable dates
/// are treated by callers as "already expired" where relevant (RFC 9111 §5.3).
pub(crate) fn parse_http_date(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let tokens: Vec<&str> = s.split_whitespace().collect();

    // asctime: "Sun Nov  6 08:49:37 1994" (no "GMT" suffix, year is last).
    if !tokens.last().is_some_and(|t| t.eq_ignore_ascii_case("GMT")) && tokens.len() >= 5 {
        // weekday month day time year
        let (month, day, time, year) = (tokens[1], tokens[2], tokens[3], tokens[4]);
        let (y, mo, d, (hh, mm, ss)) = (
            parse_year(year)?,
            month_number(month)?,
            day.parse().ok()?,
            parse_time(time)?,
        );
        let secs = date_to_secs(y, mo, d, hh, mm, ss)?;
        return Some(UNIX_EPOCH + Duration::from_secs(secs as u64));
    }

    // IMF-fixdate or RFC 850: both end with "GMT".
    if tokens.len() < 2 {
        return None;
    }
    // Drop a leading "Weekday," token if present.
    let body = if tokens[0].ends_with(',') {
        &tokens[1..]
    } else {
        &tokens[..]
    };
    if body.len() < 2 {
        return None;
    }

    let (day, month, year, time) = if body[0].contains('-') {
        // RFC 850: "06-Nov-94 08:49:37"
        let mut it = body[0].splitn(3, '-');
        let d: u32 = it.next()?.parse().ok()?;
        let mo = month_number(it.next()?)?;
        let y = parse_year(it.next()?)?;
        (d, mo, y, body[1].to_string())
    } else {
        // IMF-fixdate: "06 Nov 1994 08:49:37"
        if body.len() < 4 {
            return None;
        }
        let d: u32 = body[0].parse().ok()?;
        let mo = month_number(body[1])?;
        let y = parse_year(body[2])?;
        (d, mo, y, body[3].to_string())
    };

    let (hh, mm, ss) = parse_time(&time)?;
    let secs = date_to_secs(year, month, day, hh, mm, ss)?;
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

fn date_to_secs(y: i64, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    let secs = days * 86_400 + hh as i64 * 3_600 + mm as i64 * 60 + ss as i64;
    if secs < 0 {
        return None;
    }
    Some(secs)
}

/// Format a `SystemTime` as an `IMF-fixdate` string, e.g.
/// `"Sun, 06 Nov 1994 08:49:37 GMT"`.
pub(crate) fn format_http_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs - days * 86_400;
    let (hh, mm, ss) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);

    // Reconstruct the date from the epoch-day count.
    // Inverse of days_from_civil: search the civil date for this day count.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    let wd = WEEKDAYS[weekday_index(y, m as u32, d as u32) as usize];
    format!(
        "{wd}, {d:02} {} {y:04} {hh:02}:{mm:02}:{ss:02} GMT",
        MONTHS[(m - 1) as usize]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_imf_fixdate() {
        let t = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 784_111_777);
    }

    #[test]
    fn parse_rfc850() {
        let t = parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").unwrap();
        let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 784_111_777);
    }

    #[test]
    fn parse_asctime() {
        let t = parse_http_date("Sun Nov  6 08:49:37 1994").unwrap();
        let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 784_111_777);
    }

    #[test]
    fn round_trip_format() {
        let t = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(
            format_http_date(t).as_str(),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }

    #[test]
    fn invalid_returns_none() {
        assert!(parse_http_date("not a date").is_none());
        assert!(parse_http_date("0").is_none());
        assert!(parse_http_date("").is_none());
    }
}
