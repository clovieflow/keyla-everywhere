//! Event-to-text helpers and reasoning summary separation. Port of
//! `src/transport/surface/adapters.ts` (`eventText`) and
//! `src/transport/surface/reasoning-summary.ts`.

use keyla_core::CanonicalEvent;

pub fn event_text(event: &CanonicalEvent) -> Option<&str> {
    match event {
        CanonicalEvent::ContentDelta {
            content: keyla_core::ContentPart::Text { text },
            ..
        } => Some(text),
        _ => None,
    }
}

/// Audio output payload carried as an `audio` extension content part.
pub fn event_audio(event: &CanonicalEvent) -> Option<&serde_json::Map<String, serde_json::Value>> {
    match event {
        CanonicalEvent::ContentDelta { content, .. } => match content {
            keyla_core::ContentPart::Extension { name, payload }
                if name == "audio" && payload.is_object() =>
            {
                payload.as_object()
            }
            _ => None,
        },
        _ => None,
    }
}

pub fn event_reasoning_text(event: &CanonicalEvent) -> Option<&str> {
    let CanonicalEvent::ContentDelta { content, .. } = event else {
        return None;
    };
    let keyla_core::ContentPart::Reasoning {
        payload,
        opaque,
        summary,
        ..
    } = content
    else {
        return None;
    };
    if *opaque == Some(true) {
        return None;
    }
    payload.as_str().or(summary.as_deref())
}

pub fn event_obfuscation(event: &CanonicalEvent) -> Option<&str> {
    match event {
        CanonicalEvent::ContentDelta { content, .. } => match content {
            keyla_core::ContentPart::Extension { name, payload } if name.contains("obfuscat") => {
                payload.as_str()
            }
            _ => None,
        },
        _ => None,
    }
}

/// The source identity of one reasoning-summary delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasoningSummaryIdentity {
    pub item_id: Option<String>,
    pub output_index: Option<i64>,
    pub summary_index: Option<i64>,
}

pub fn reasoning_summary_identity(event: &CanonicalEvent) -> Option<ReasoningSummaryIdentity> {
    let CanonicalEvent::ContentDelta {
        content,
        item_id,
        output_index,
        ..
    } = event
    else {
        return None;
    };
    let keyla_core::ContentPart::Reasoning { summary_index, .. } = content else {
        return None;
    };
    if item_id.is_none() && output_index.is_none() && summary_index.is_none() {
        return None;
    }
    Some(ReasoningSummaryIdentity {
        item_id: item_id.clone(),
        output_index: *output_index,
        summary_index: *summary_index,
    })
}

fn reasoning_summary_has_boundary(
    previous: Option<&ReasoningSummaryIdentity>,
    current: Option<&ReasoningSummaryIdentity>,
) -> bool {
    let (Some(previous), Some(current)) = (previous, current) else {
        return false;
    };
    (previous.item_id.is_some() && current.item_id.is_some() && previous.item_id != current.item_id)
        || (previous.output_index.is_some()
            && current.output_index.is_some()
            && previous.output_index != current.output_index)
        || (previous.summary_index.is_some()
            && current.summary_index.is_some()
            && previous.summary_index != current.summary_index)
}

/// Separates distinct summary parts without splitting token fragments.
pub fn reasoning_summary_separator(
    previous: Option<&ReasoningSummaryIdentity>,
    current: Option<&ReasoningSummaryIdentity>,
    previous_text: Option<&str>,
    current_text: &str,
) -> &'static str {
    if !reasoning_summary_has_boundary(previous, current) {
        return "";
    }
    let previous_ends_with_space =
        previous_text.is_some_and(|text| text.chars().last().is_some_and(char::is_whitespace));
    let current_starts_with_space = current_text.chars().next().is_some_and(char::is_whitespace);
    if previous_ends_with_space || current_starts_with_space {
        return "";
    }
    "\n\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reasoning_delta(text: &str, item: Option<&str>, output: Option<i64>) -> CanonicalEvent {
        CanonicalEvent::ContentDelta {
            sequence_number: 1,
            content: keyla_core::ContentPart::Reasoning {
                payload: json!(text),
                opaque: None,
                summary: None,
                summary_index: Some(0),
                signature: None,
                encrypted_content: None,
            },
            event_id: None,
            response_id: None,
            item_id: item.map(str::to_owned),
            output_index: output,
            content_index: None,
            timestamp: None,
        }
    }

    #[test]
    fn separation_only_on_identity_change_without_whitespace() {
        let first = reasoning_delta("one", Some("a"), Some(0));
        let second = reasoning_delta("two", Some("b"), Some(1));
        let previous = reasoning_summary_identity(&first);
        let current = reasoning_summary_identity(&second);
        assert_eq!(
            reasoning_summary_separator(previous.as_ref(), current.as_ref(), Some("one"), "two"),
            "\n\n"
        );
        assert_eq!(
            reasoning_summary_separator(previous.as_ref(), current.as_ref(), Some("one "), "two"),
            ""
        );
        let same = reasoning_summary_identity(&reasoning_delta("three", Some("a"), Some(0)));
        assert_eq!(
            reasoning_summary_separator(previous.as_ref(), same.as_ref(), Some("one"), "three"),
            ""
        );
    }
}
