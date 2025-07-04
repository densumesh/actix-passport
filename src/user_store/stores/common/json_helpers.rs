//! JSON serialization helpers for user metadata and OAuth providers.

use crate::{types::AuthUser, OAuthUser};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

/// Converts user metadata `HashMap` to JSON for database storage.
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn metadata_to_json(metadata: &HashMap<String, JsonValue>) -> JsonValue {
    JsonValue::Object(
        metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}

/// Converts JSON from database to user metadata `HashMap`.
#[must_use]
pub fn json_to_metadata(json: &JsonValue) -> HashMap<String, JsonValue> {
    match json {
        JsonValue::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => HashMap::new(),
    }
}

/// Extracts OAuth provider list from user metadata.
#[must_use]
pub fn get_oauth_providers(user: &AuthUser) -> Vec<OAuthUser> {
    user.metadata
        .get("oauth_providers")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(_, value)| serde_json::from_value(value.clone()).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default()
}

/// Converts OAuth providers list to JSON for database storage.
#[must_use]
pub fn oauth_providers_to_json(providers: &[OAuthUser]) -> JsonValue {
    serde_json::to_value(providers).unwrap_or_default()
}

/// Converts JSON from database to OAuth providers list.
#[must_use]
pub fn json_to_oauth_providers(json: &JsonValue) -> Vec<OAuthUser> {
    match json.get("oauth_providers") {
        Some(JsonValue::Array(arr)) => arr
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect(),
        _ => Vec::new(),
    }
}

/// Helper to safely get string value from JSON.
#[must_use]
pub fn get_string_from_json(json: &JsonValue, key: &str) -> Option<String> {
    json.get(key)?
        .as_str()
        .map(std::string::ToString::to_string)
}

/// Helper to safely get optional string value from JSON.
#[must_use]
pub fn get_optional_string_from_json(json: &JsonValue, key: &str) -> Option<Option<String>> {
    match json.get(key) {
        Some(JsonValue::Null) => Some(None),
        Some(v) => Some(v.as_str().map(std::string::ToString::to_string)),
        None => None,
    }
}
