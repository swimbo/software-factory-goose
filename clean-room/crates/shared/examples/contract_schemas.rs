//! Generate shape-only schemas for the current serde contracts.
use schemars::{JsonSchema, schema_for};
use serde_json::Value;
use shared::{Claim, CredentialGrant, Receipt};

fn schema<T: JsonSchema>(name: &str) -> Value {
    let mut value = serde_json::to_value(schema_for!(T)).expect("serialize schema");
    value["$id"] = format!("urn:software-factory:legacy-shape:{name}:v1").into();
    value
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/legacy-shape/v1");
    for (name, schema) in [
        ("receipt", schema::<Receipt>("receipt")),
        ("claim", schema::<Claim>("claim")),
        (
            "credential-grant",
            schema::<CredentialGrant>("credential-grant"),
        ),
    ] {
        let mut bytes = serde_json::to_vec_pretty(&schema)?;
        bytes.push(b'\n');
        std::fs::write(root.join(format!("{name}.schema.json")), bytes)?;
    }
    Ok(())
}
