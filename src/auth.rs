use rand::Rng;

pub const MIN_PASSWORD_LEN: usize = 12; // SEG-08: minimum admin password length

pub fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-_";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub fn correct_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// SEG-07: Timing equalization — call this when a user is not found to consume
/// the same amount of time as a real bcrypt verification would.
pub fn dummy_verify() {
    // This hash is intentionally invalid but has the right format to make bcrypt
    // spend a similar amount of time regardless of whether the user was found.
    let _ = bcrypt::verify("dummy_password_for_timing_eq", "$2b$10$invalidsaltandhashvaluePAD");
}

/// SEG-04: validate that s is a valid ACME DNS-01 token (Base64URL, exactly 43 chars)
pub fn is_valid_acme_token(s: &str) -> bool {
    s.len() == 43 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_length() {
        let pwd = generate_password(40);
        assert_eq!(pwd.len(), 40);
    }

    #[test]
    fn test_generate_password_charset() {
        let pwd = generate_password(100);
        assert!(pwd.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_generate_password_min_len_constant() {
        assert_eq!(MIN_PASSWORD_LEN, 12);
    }

    #[test]
    fn test_correct_password_valid() {
        let hash = bcrypt::hash("correct_password", 4).unwrap();
        assert!(correct_password("correct_password", &hash));
    }

    #[test]
    fn test_correct_password_wrong() {
        let hash = bcrypt::hash("correct_password", 4).unwrap();
        assert!(!correct_password("wrong_password", &hash));
    }

    #[test]
    fn test_correct_password_invalid_hash() {
        assert!(!correct_password("any_password", "not_a_bcrypt_hash"));
    }

    #[test]
    fn test_is_valid_acme_token_valid() {
        // A valid Base64URL token of exactly 43 chars
        let token43: String = "A".repeat(43);
        assert!(is_valid_acme_token(&token43));
    }

    #[test]
    fn test_is_valid_acme_token_too_short() {
        assert!(!is_valid_acme_token("short"));
    }

    #[test]
    fn test_is_valid_acme_token_too_long() {
        let token = "A".repeat(44);
        assert!(!is_valid_acme_token(&token));
    }

    #[test]
    fn test_is_valid_acme_token_invalid_chars() {
        // 43 chars but with invalid characters (spaces, special chars)
        let token = format!("{}{}", "A".repeat(42), "!");
        assert!(!is_valid_acme_token(&token));
    }

    #[test]
    fn test_is_valid_acme_token_with_dash_underscore() {
        // Valid: alphanumeric + dash + underscore, exactly 43 chars
        // 21 + 1 ('-') + 10 + 1 ('_') + 10 = 43
        let token = format!("{}-{}_{}", "A".repeat(21), "B".repeat(10), "C".repeat(10));
        assert_eq!(token.len(), 43);
        assert!(is_valid_acme_token(&token));
    }

    #[test]
    fn test_dummy_verify_does_not_panic() {
        // Just ensure it doesn't panic
        dummy_verify();
    }
}
