use alloy_primitives::Address;
use std::str::FromStr;

pub fn hash_to_name(hash: &str) -> String {
    if !hash.starts_with("0x0000") {
        return hash[1..6].to_lowercase();
    }
    let len = hash.len();
    let trimmed = hash.trim_start_matches("0x").trim_start_matches('0');
    let trimmed = if trimmed.len() < 4 { &hash[len - 4..] } else { trimmed };
    format!("x{}", &trimmed[..4].to_lowercase())
}

pub fn checksum(address: &str) -> String {
    match Address::from_str(address) {
        Ok(addr) => addr.to_checksum(None),
        Err(_) => address.to_string(),
    }
}
