use rand::distr::{Distribution, Uniform};

/// Base62 alphabet (URL-safe; no visually ambiguous separators).
const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Generate a cryptographically random base62 slug of the requested length.
///
/// Uses the thread-local RNG, which in rand 0.10 is seeded from the OS CSPRNG
/// and uses ChaCha12. An attacker without access to process memory cannot
/// predict output — adequate for ephemeral short links wrapping already
/// token-authed URLs.
pub fn generate(len: usize) -> String {
    let range = Uniform::new(0u8, ALPHABET.len() as u8).expect("static alphabet len > 0");
    let mut rng = rand::rng();
    (0..len)
        .map(|_| ALPHABET[range.sample(&mut rng) as usize] as char)
        .collect()
}

/// Whether a candidate string matches the slug alphabet. Used defensively on
/// the redirect path to fail fast on obvious garbage.
pub fn is_valid(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| ALPHABET.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_respects_length() {
        assert_eq!(generate(8).len(), 8);
        assert_eq!(generate(10).len(), 10);
        assert_eq!(generate(20).len(), 20);
    }

    #[test]
    fn generate_uses_only_alphabet() {
        for _ in 0..50 {
            let s = generate(16);
            assert!(s.bytes().all(|b| ALPHABET.contains(&b)), "bad char in {s}");
        }
    }

    #[test]
    fn generate_is_nondeterministic() {
        let a = generate(10);
        let b = generate(10);
        // Not a statistical test — just a sanity check that two 10-char draws
        // from a 62^10 space don't collide.
        assert_ne!(a, b);
    }

    #[test]
    fn is_valid_rejects_empty_and_bad_chars() {
        assert!(!is_valid(""));
        assert!(!is_valid("abc-def"));
        assert!(!is_valid("abc def"));
        assert!(!is_valid("abc/def"));
    }

    #[test]
    fn is_valid_accepts_alphabet() {
        assert!(is_valid("a"));
        assert!(is_valid("abcDEF123"));
        assert!(is_valid("ZzAa09"));
    }
}
