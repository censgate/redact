//! Print the non-secret generation commitment for an operator-reviewed shard map.
//! Reads a base64 root key from TOKEN_STORE_ROOT_KEY_FILE; never prints the key.
use base64::Engine;
use std::io::Read;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    std::io::stdin()
        .take(64 * 1024)
        .read_to_string(&mut input)?;
    let routing: (Vec<String>, Vec<usize>) = serde_json::from_str(&input)?;
    if routing.0.is_empty()
        || routing.1.len() != 256
        || routing.1.iter().any(|n| *n >= routing.0.len())
    {
        return Err("invalid routing map".into());
    }
    let path = std::env::var("TOKEN_STORE_ROOT_KEY_FILE")?;
    let encoded = std::fs::read_to_string(path)?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.trim())?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "root key must have 32 bytes")?;
    println!(
        "{}",
        redact_token_store::Vault::configuration_commitment(&key, &serde_json::to_vec(&routing)?)
    );
    Ok(())
}
