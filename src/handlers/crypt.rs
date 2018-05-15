extern crate bcrypt;
extern crate hmac;
extern crate sha2;

use std::fmt::Write;
use self::bcrypt::{hash, verify};
use self::hmac::{Hmac, Mac};
use self::sha2::Sha256;

fn hmac_password(password: &str, hmac_key: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new(hmac_key).unwrap();
    mac.input(password.as_bytes());
    let result = mac.result().code();
    let mut result_hex = String::new();
    write!(&mut result_hex, "{:x}", result).unwrap();
    result_hex
}

pub fn hash_password(password: &str, hmac_key: &[u8], bcrypt_rounds: u32) -> String {
    let hmac_hex = hmac_password(password, hmac_key);
    let hashed = hash(hmac_hex.as_str(), bcrypt_rounds);
    hashed.unwrap()
}

pub fn verify_password(password: &str, hashed: &str, hmac_key: &[u8]) -> bool {
    let hmac_hex = hmac_password(password, hmac_key);
    verify(hmac_hex.as_str(), hashed).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_correct() {
        let hash = hash_password("test_password", b"my_key", 4);
        assert!(verify_password("test_password", hash.as_str(), b"my_key"));
    }

    #[test]
    fn test_verify_incorrect() {
        let hash = hash_password("test_password", b"my_key", 4);
        assert!(!verify_password("wrong_password", hash.as_str(), b"my_key"));
    }
}
