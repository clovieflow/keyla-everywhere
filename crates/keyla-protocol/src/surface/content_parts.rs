//! Shared content-part helpers. Port of `src/transport/surface/content-parts.ts`.

use keyla_core::ContentPart;
use serde_json::Value;

use crate::primitives::split_data_url;

pub fn text_part(text: impl Into<String>) -> ContentPart {
    ContentPart::Text { text: text.into() }
}

/// Normalizes an inline file payload into `{ data, media_type }`. A whole
/// `data:` URI is split, and the URI's declared type is the fallback when the
/// explicit field is absent.
pub fn normalize_inline_file(data: &Value, media_type: Option<&str>) -> (Value, String) {
    let inline = data.as_str();
    let split = inline.and_then(split_data_url);
    let declared = media_type.filter(|value| !value.is_empty());
    let normalized_data = split
        .as_ref()
        .map(|split| Value::String(split.data.clone()))
        .unwrap_or_else(|| {
            if data.is_null() {
                Value::String(String::new())
            } else {
                data.clone()
            }
        });
    let normalized_media_type = declared
        .map(str::to_owned)
        .or_else(|| split.map(|split| split.media_type))
        .unwrap_or_else(|| "application/octet-stream".into());
    (normalized_data, normalized_media_type)
}
