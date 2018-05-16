extern crate bcrypt;
extern crate hmac;
extern crate sha2;

use self::{
    bcrypt::{hash, verify, BcryptError},
    hmac::{crypto_mac::InvalidKeyLength, Hmac, Mac},
    sha2::Sha256,
};
use std::fmt::Write;

#[derive(Debug, PartialEq)]
pub enum PasswordError {
    InvalidKeyLength,
    CostNotAllowed(u32),
    InvalidHash(String),
}

fn hmac_password(
    password: &str,
    hmac_key: &[u8],
) -> Result<String, InvalidKeyLength> {
    let mut mac = Hmac::<Sha256>::new(hmac_key)?;
    mac.input(password.as_bytes());
    let result = mac.result().code();
    let mut result_hex = String::new();
    write!(&mut result_hex, "{:x}", result)
        .expect("The Hmac result should convert to hex.");
    Ok(result_hex)
}

pub fn hash_password(
    password: &str,
    hmac_key: &[u8],
    bcrypt_rounds: u32,
) -> Result<String, PasswordError> {
    let hmac_hex = match hmac_password(password, hmac_key) {
        Ok(result) => result,
        Err(InvalidKeyLength) => {
            return Err(PasswordError::InvalidKeyLength);
        },
    };
    let hashed = hash(hmac_hex.as_str(), bcrypt_rounds);
    match hashed {
        Ok(result) => Ok(result),
        Err(BcryptError::CostNotAllowed(cost)) => {
            Err(PasswordError::CostNotAllowed(cost))
        },
        Err(_) => panic!("Unexpected Bcrypt error."),
    }
}

pub fn verify_password(
    password: &str,
    hashed: &str,
    hmac_key: &[u8],
) -> Result<bool, PasswordError> {
    let hmac_hex = match hmac_password(password, hmac_key) {
        Ok(result) => result,
        Err(InvalidKeyLength) => {
            return Err(PasswordError::InvalidKeyLength);
        },
    };
    match verify(hmac_hex.as_str(), hashed) {
        Ok(bool) => Ok(bool),
        Err(BcryptError::InvalidCost(_))
        | Err(BcryptError::InvalidPrefix(_))
        | Err(BcryptError::InvalidHash(_))
        | Err(BcryptError::InvalidBase64(_, _)) => {
            Err(PasswordError::InvalidHash(hashed.to_string()))
        },
        Err(_) => panic!("Unexpected Bcrypt error."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_correct() {
        let hash = hash_password("test_password", b"my_key", 4)
            .expect("This should be a valid cost and hmac_key");
        assert!(
            verify_password("test_password", hash.as_str(), b"my_key")
                .expect("Hash and hmac_key should be valid.")
        );
    }

    #[test]
    fn test_verify_incorrect() {
        let hash = hash_password("test_password", b"my_key", 4)
            .expect("This should be a valid cost and hmac_key");
        assert!(
            !verify_password("wrong_password", hash.as_str(), b"my_key")
                .expect("Hash and hmac_key should be valid.")
        );
    }

    #[test]
    fn test_invalid_cost() {
        assert_eq!(
            hash_password("test_password", b"my_key", 1).err(),
            Some(PasswordError::CostNotAllowed(1)),
        );
    }

    #[test]
    fn test_invalid_hash() {
        assert_eq!(
            verify_password("wrong_password", "invalid_hash", b"my_key").err(),
            Some(PasswordError::InvalidHash(
                "invalid_hash".to_string()
            )),
        );
    }
}
