//! Experimental, unregistered Goose request-shape validation. Not an authorization boundary.

use serde_json::Value;

/// Parse a bounded raw request while rejecting duplicate object keys at every nesting level.
/// This remains an experimental shape check, not caller authentication or spend authority.
pub fn validate_goose_fixture_bytes(
    raw: &[u8],
    model: &str,
    trusted_tool: &Value,
    max_tokens: u64,
    max_bytes: usize,
) -> anyhow::Result<Value> {
    anyhow::ensure!(
        (1..=1_048_576).contains(&max_bytes) && raw.len() <= max_bytes,
        "request exceeds limit"
    );
    let parsed: UniqueJson =
        serde_json::from_slice(raw).map_err(|_| anyhow::anyhow!("invalid or ambiguous JSON"))?;
    validate_goose_fixture_request(&parsed.0, model, trusted_tool, max_tokens, max_bytes)?;
    Ok(parsed.0)
}

struct UniqueJson(Value);
impl<'de> serde::Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{Error, MapAccess, SeqAccess, Visitor};
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(v)))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::from(v)))
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::from(v)))
            }
            fn visit_f64<E: Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(v.into())))
            }
            fn visit_string<E: Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(v)))
            }
            fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element::<UniqueJson>()? {
                    out.push(item.0);
                }
                Ok(UniqueJson(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueJson>()? {
                    if out.contains_key(&key) {
                        return Err(A::Error::custom("duplicate object key"));
                    }
                    out.insert(key, value.0);
                }
                Ok(UniqueJson(Value::Object(out)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

/// Check the exact two-turn tool exchange observed in the local Goose fixture. Configuration
/// must be trusted: this function neither authenticates a client nor reserves inference spend.
/// Callers with raw JSON should use `validate_goose_fixture_bytes`; callers must independently
/// bind tool results to earlier provider responses. This is not wired to a live gateway.
pub fn validate_goose_fixture_request(
    value: &Value,
    model: &str,
    trusted_tool: &Value,
    max_tokens: u64,
    max_bytes: usize,
) -> anyhow::Result<()> {
    use anyhow::ensure;
    ensure!(
        !model.is_empty()
            && model.len() <= 256
            && max_tokens > 0
            && (1..=1_048_576).contains(&max_bytes),
        "invalid fixture configuration"
    );
    ensure!(
        trusted_tool["type"] == "function" && trusted_tool["function"]["name"] == "factory__shell",
        "invalid trusted tool"
    );
    ensure!(
        serde_json::to_vec(value)?.len() <= max_bytes,
        "request exceeds limit"
    );
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("request is not an object"))?;
    ensure!(
        obj.len() == 6
            && obj.get("model").and_then(Value::as_str) == Some(model)
            && obj
                .get("tools")
                .and_then(Value::as_array)
                .is_some_and(|tools| tools.as_slice() == [trusted_tool.clone()])
            && obj
                .get("max_tokens")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0 && n <= max_tokens)
            && obj.get("stream") == Some(&Value::Bool(true))
            && obj.get("stream_options") == Some(&serde_json::json!({"include_usage":true})),
        "unreviewed request fields"
    );
    let messages = obj
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("missing messages"))?;
    ensure!(
        matches!(messages.len(), 2 | 4),
        "unsupported message sequence"
    );
    for (message, role) in messages.iter().zip(["system", "user"]) {
        let m = message
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid message"))?;
        ensure!(
            m.len() == 2
                && m.get("role").and_then(Value::as_str) == Some(role)
                && m.get("content").is_some_and(Value::is_string),
            "invalid message"
        );
    }
    if messages.len() == 4 {
        let assistant = messages[2]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid assistant"))?;
        let calls = assistant
            .get("tool_calls")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("missing tool calls"))?;
        ensure!(
            assistant.len() == 3
                && assistant.get("role").and_then(Value::as_str) == Some("assistant")
                && assistant.get("content") == Some(&Value::Null)
                && calls.len() == 1,
            "invalid tool call"
        );
        let call = calls[0]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid tool call"))?;
        let id = call
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing call ID"))?;
        let function = call
            .get("function")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow::anyhow!("invalid function"))?;
        ensure!(
            call.len() == 3
                && !id.is_empty()
                && id.len() <= 128
                && id.bytes().all(|b| b.is_ascii_graphic())
                && call.get("type").and_then(Value::as_str) == Some("function")
                && function.len() == 2
                && function.get("name").and_then(Value::as_str) == Some("factory__shell"),
            "invalid call binding"
        );
        let arguments: UniqueJson = serde_json::from_str(
            function
                .get("arguments")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing arguments"))?,
        )?;
        ensure!(arguments.0.is_object(), "invalid tool arguments");
        let result = messages[3]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid result"))?;
        ensure!(
            result.len() == 3
                && result.get("role").and_then(Value::as_str) == Some("tool")
                && result.get("tool_call_id").and_then(Value::as_str) == Some(id)
                && result.get("content").is_some_and(Value::is_string),
            "unpaired result"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn tool() -> Value {
        json!({"type":"function","function":{"name":"factory__shell","description":"fixed fixture","parameters":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"],"additionalProperties":false}}})
    }
    fn request() -> Value {
        json!({"model":"fixture-model","messages":[{"role":"system","content":"system"},{"role":"user","content":"task"}],"tools":[tool()],"max_tokens":100,"stream":true,"stream_options":{"include_usage":true}})
    }
    fn exchange() -> Value {
        let mut req = request();
        req["messages"].as_array_mut().unwrap().extend([
            json!({"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"factory__shell","arguments":"{\"command\":\"echo hi\"}"}}]}),
            json!({"role":"tool","tool_call_id":"c1","content":"safe result"})]);
        req
    }
    fn validate(value: &Value) -> bool {
        validate_goose_fixture_request(value, "fixture-model", &tool(), 100, 8192).is_ok()
    }
    #[test]
    fn accepts_observed_initial_and_tool_result_request() {
        assert!(validate(&request()));
        assert!(validate(&exchange()));
    }
    #[test]
    fn rejects_unpriced_or_ambiguous_fields_before_any_forwarding() {
        for field in ["extra", "temperature", "n"] {
            let mut req = request();
            req[field] = json!(1);
            assert!(!validate(&req));
        }
        for change in 0..5 {
            let mut req = request();
            match change {
                0 => req["model"] = json!("other"),
                1 => req["tools"][0]["function"]["name"] = json!("untrusted"),
                2 => req["max_tokens"] = json!(101),
                3 => req["stream"] = json!(false),
                _ => req["messages"][0]["content"] = json!([{"image_url":"fixture"}]),
            }
            assert!(!validate(&req));
        }
        assert!(
            validate_goose_fixture_request(&request(), "fixture-model", &tool(), 100, 8).is_err()
        );
    }
    #[test]
    fn rejects_unpaired_or_malformed_tool_messages() {
        for change in 0..5 {
            let mut req = exchange();
            match change {
                0 => req["messages"][3]["tool_call_id"] = json!("other"),
                1 => req["messages"][2]["tool_calls"][0]["function"]["name"] = json!("other"),
                2 => {
                    req["messages"][2]["tool_calls"][0]["function"]["arguments"] = json!("not-json")
                }
                3 => req["messages"][2]["tool_calls"][0]["id"] = json!(""),
                _ => req["messages"]
                    .as_array_mut()
                    .unwrap()
                    .pop()
                    .map(drop)
                    .unwrap(),
            }
            assert!(!validate(&req));
        }
    }

    #[test]
    fn bounded_raw_json_rejects_duplicate_keys_at_all_object_depths() {
        let raw = serde_json::to_string(&request()).unwrap();
        assert!(
            validate_goose_fixture_bytes(raw.as_bytes(), "fixture-model", &tool(), 100, 8192)
                .is_ok()
        );
        for text in [
            raw.replace(
                "\"model\":\"fixture-model\"",
                "\"model\":\"fixture-model\",\"model\":\"fixture-model\"",
            ),
            raw.replace(
                "\"role\":\"system\"",
                "\"role\":\"system\",\"role\":\"system\"",
            ),
            raw.replace(
                "\"include_usage\":true",
                "\"include_usage\":true,\"include_usage\":true",
            ),
            format!("{raw}null"),
        ] {
            assert_ne!(text, raw);
            assert!(
                validate_goose_fixture_bytes(text.as_bytes(), "fixture-model", &tool(), 100, 8192)
                    .is_err()
            );
        }
        assert!(
            validate_goose_fixture_bytes(raw.as_bytes(), "fixture-model", &tool(), 100, 8).is_err()
        );
        let mut embedded = exchange();
        embedded["messages"][2]["tool_calls"][0]["function"]["arguments"] =
            json!("{\"command\":\"one\",\"command\":\"two\"}");
        let bytes = serde_json::to_vec(&embedded).unwrap();
        assert!(validate_goose_fixture_bytes(&bytes, "fixture-model", &tool(), 100, 8192).is_err());
    }
}
