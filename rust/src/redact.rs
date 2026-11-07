//! One redaction rule for JSON that leaves the engine.
//!
//! The local GUI server and the desktop control channel both pass service
//! status to a less trusted reader. They share this rule so one of them cannot
//! drift behind the other. Redaction is a last defense. A response should not
//! carry a credential in the first place.

use serde_json::Value;

/// Text that replaces the value of a sensitive field.
pub const REDACTED: &str = "[redacted]";

/// Whether a JSON field name looks like it holds a credential.
pub fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("password")
        || lower.contains("passphrase")
        || lower.contains("authorization")
        || lower.contains("bearer")
        || lower.contains("secret")
        || lower.contains("credential")
        || lower == "auth"
        || lower.ends_with("key")
}

/// Replace the value of every sensitive field, at any depth, with
/// `"[redacted]"`. Other values are unchanged.
pub fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if is_sensitive_field(key) {
                    *value = Value::String(REDACTED.into());
                } else {
                    redact_json(value);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json(item);
            }
        }
        _ => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_credential_named_fields_are_redacted() {
        let mut value = json!({
            "ok": true,
            "list": [{"credential": "secret-a", "name": "visible"}],
            "outer": {
                "inner": {
                    "proxy_credentials": {"user": "u", "pass": "secret-b"},
                    "Bearer": "secret-c",
                    "passphrase": "secret-d",
                    "api_key": "secret-e",
                    "auth": "secret-f",
                    "tcp_setup_timeout_phone_auth": 5,
                    "note": "visible"
                }
            }
        });
        redact_json(&mut value);
        assert_eq!(value["ok"], true);
        assert_eq!(value["list"][0]["credential"], REDACTED);
        assert_eq!(value["list"][0]["name"], "visible");
        let inner = &value["outer"]["inner"];
        assert_eq!(inner["proxy_credentials"], REDACTED);
        assert_eq!(inner["Bearer"], REDACTED);
        assert_eq!(inner["passphrase"], REDACTED);
        assert_eq!(inner["api_key"], REDACTED);
        assert_eq!(inner["auth"], REDACTED);
        assert_eq!(inner["tcp_setup_timeout_phone_auth"], 5);
        assert_eq!(inner["note"], "visible");
        let text = value.to_string();
        for secret in [
            "secret-a", "secret-b", "secret-c", "secret-d", "secret-e", "secret-f",
        ] {
            assert!(!text.contains(secret), "{secret} leaked");
        }
    }
}
