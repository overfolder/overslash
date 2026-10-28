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

/// Longest expiry a remembered permission rule may carry.
pub const MAX_RULE_TTL_SECS: u64 = 365 * 86400;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuleTtlError {
    #[error("invalid ttl: {0}")]
    Invalid(String),
    #[error("ttl must not exceed 365 days")]
    TooLong,
}

/// Parse the `ttl` a permission rule is written with: `"forever"` is no
/// expiry (`None`), anything else is a [`parse_ttl`] duration capped at
/// [`MAX_RULE_TTL_SECS`].
pub fn parse_rule_ttl(s: &str) -> Result<Option<Duration>, RuleTtlError> {
    if s == "forever" {
        return Ok(None);
    }
    let dur = parse_ttl(s).ok_or_else(|| RuleTtlError::Invalid(s.to_string()))?;
    if dur.as_secs() > MAX_RULE_TTL_SECS {
        return Err(RuleTtlError::TooLong);
    }
    Ok(Some(dur))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule_ttl() {
        assert_eq!(parse_rule_ttl("forever"), Ok(None));
        assert_eq!(parse_rule_ttl("7d"), Ok(Some(Duration::from_secs(604800))));
        assert_eq!(
            parse_rule_ttl("365d"),
            Ok(Some(Duration::from_secs(MAX_RULE_TTL_SECS)))
        );
        assert_eq!(parse_rule_ttl("366d"), Err(RuleTtlError::TooLong));
        assert_eq!(
            parse_rule_ttl("never"),
            Err(RuleTtlError::Invalid("never".into()))
        );
    }

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
