use hmac::{Hmac, Mac, NewMac};
use sha2::{Digest, Sha256};

use crate::error::{SigningError, SigningErrorCause::InvalidKeyLength};

type HmacSha256 = Hmac<Sha256>;

pub fn calculate_hmac_sha_256(key: &[u8], value: &str) -> Result<Vec<u8>, SigningError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|error| SigningError {
        cause: InvalidKeyLength(error.to_string()),
    })?;
    mac.update(value.as_bytes());
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

pub fn calculate_sha_256(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("{:X}", hasher.finalize()).to_lowercase()
}
