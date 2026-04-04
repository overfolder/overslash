use std::time::Duration;

/// Parse a TTL string like "24h", "30m", "7d", "1h30m" into a Duration.
/// Returns None if the string is empty or contains no valid segments.
pub fn parse_ttl(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let mut total_secs: u64 = 0;
    let mut num_buf = String::new();
    let mut found_any = false;

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num_buf.push(ch);
        } else {
            let n: u64 = num_buf.parse().ok()?;
            num_buf.clear();
            let multiplier = match ch {
                'd' => 86400,
                'h' => 3600,
                'm' => 60,
                's' => 1,
                _ => return None,
            };
            total_secs = total_secs.checked_add(n.checked_mul(multiplier)?)?;
            found_any = true;
        }
    }

    if !num_buf.is_empty() {
        // Trailing digits with no unit — invalid
        return None;
    }

    if found_any && total_secs > 0 {
        Some(Duration::from_secs(total_secs))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ttl() {
        assert_eq!(parse_ttl("24h"), Some(Duration::from_secs(86400)));
        assert_eq!(parse_ttl("30m"), Some(Duration::from_secs(1800)));
        assert_eq!(parse_ttl("7d"), Some(Duration::from_secs(604800)));
        assert_eq!(parse_ttl("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_ttl("1d12h"), Some(Duration::from_secs(129600)));
        assert_eq!(parse_ttl(""), None);
        assert_eq!(parse_ttl("abc"), None);
        assert_eq!(parse_ttl("24"), None); // no unit
        assert_eq!(parse_ttl("0h"), None); // zero duration
    }
}
