//! Test helper: report whether serde accepts a legacy JSON value.
use std::io::Read;
fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let accepted = match std::env::args().nth(1).as_deref() {
        Some("receipt") => serde_json::from_str::<shared::Receipt>(&input).is_ok(),
        Some("claim") => serde_json::from_str::<shared::Claim>(&input).is_ok(),
        Some("credential-grant") => serde_json::from_str::<shared::CredentialGrant>(&input).is_ok(),
        _ => false,
    };
    if !accepted {
        std::process::exit(1);
    }
}
