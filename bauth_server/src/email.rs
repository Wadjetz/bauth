/// RFC 5321 limit for a full address.
const MAX_LEN: usize = 254;

/// Minimal sanity check; the verification email is the real proof the address works.
/// Surrounding spaces are allowed because SQL `btrim` removes them before storage.
pub fn is_valid(email: &str) -> bool {
    let email = email.trim_matches(' ');
    email.len() <= MAX_LEN
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.contains('@')
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        })
}

#[cfg(test)]
mod tests {
    use super::is_valid;

    #[test]
    fn accepts_common_addresses() {
        assert!(is_valid("alice@example.com"));
        assert!(is_valid("  Alice+test@Mail.Example.com "));
    }

    #[test]
    fn rejects_malformed_addresses() {
        for email in [
            "",
            "alice",
            "@example.com",
            "alice@",
            "alice@localhost",
            "a@b@c.fr",
            "alice@.fr",
            "alice@fr.",
            "e gor@example.com",
            "\talice@example.com",
        ] {
            assert!(!is_valid(email), "{email:?} should be invalid");
        }
        assert!(!is_valid(&format!("{}@example.com", "a".repeat(250))));
    }
}
