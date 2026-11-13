//! Stable per-tool index pinning and argument accumulation. Port of
//! `src/transport/tool-identity.ts` (the tracker half).

use std::collections::HashMap;

/// Accumulated arguments and pinned index for one in-progress tool call.
#[derive(Debug, Clone)]
pub struct ToolCallState {
    pub id: String,
    pub name: Option<String>,
    pub arguments: String,
    pub index: i64,
}

#[derive(Debug, Default, Clone)]
pub struct ToolCallTracker {
    pub index_by_id: HashMap<String, i64>,
    pub states: HashMap<String, ToolCallState>,
    pub next_index: i64,
}

impl ToolCallTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.index_by_id.clear();
        self.states.clear();
        self.next_index = 0;
    }

    /// Pins a stable per-tool index and accumulates streamed `arguments`.
    /// Index precedence: explicit non-negative wire index, then the pinned
    /// index for a known id, then `fallback_index`, then the tracker counter.
    pub fn track(
        &mut self,
        id: &str,
        name: Option<&str>,
        args: Option<&str>,
        index: Option<i64>,
        fallback_index: Option<i64>,
    ) -> (i64, bool, ToolCallState) {
        let prior_index = self.index_by_id.get(id).copied();
        let pinned = match index {
            Some(index) if index >= 0 => index,
            _ => prior_index.or(fallback_index).unwrap_or_else(|| {
                let next = self.next_index;
                self.next_index += 1;
                next
            }),
        };
        self.index_by_id.insert(id.to_owned(), pinned);
        self.next_index = self.next_index.max(pinned + 1);

        let prior = self.states.get(id).cloned();
        let resolved_name = name
            .map(str::to_owned)
            .or_else(|| prior.as_ref().and_then(|state| state.name.clone()));
        let mut arguments = prior
            .as_ref()
            .map(|state| state.arguments.clone())
            .unwrap_or_default();
        arguments.push_str(args.unwrap_or(""));
        let state = ToolCallState {
            id: if id.is_empty() {
                prior
                    .as_ref()
                    .map(|state| state.id.clone())
                    .unwrap_or_default()
            } else {
                id.to_owned()
            },
            name: resolved_name,
            arguments,
            index: pinned,
        };
        self.states.insert(id.to_owned(), state.clone());
        (pinned, prior.is_none(), state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_explicit_indexes_and_accumulates_arguments() {
        let mut tracker = ToolCallTracker::new();
        let (index, first, state) =
            tracker.track("call_1", Some("read"), Some("{\"a\""), None, None);
        assert_eq!(index, 0);
        assert!(first);
        assert_eq!(state.arguments, "{\"a\"");
        assert_eq!(state.name.as_deref(), Some("read"));

        let (index, first, state) = tracker.track("call_1", None, Some(":1}"), None, None);
        assert_eq!(index, 0);
        assert!(!first);
        assert_eq!(state.arguments, "{\"a\":1}");

        let (index, _, _) = tracker.track("call_2", Some("write"), None, Some(5), None);
        assert_eq!(index, 5);
        let (index, _, _) = tracker.track("call_3", None, None, None, Some(9));
        assert_eq!(index, 9);
    }
}

/// Collapses provider-specific duplicate spellings of one logical call id.
pub fn tool_identity_key(call_id: &str) -> &str {
    call_id
        .strip_prefix("call_")
        .or_else(|| call_id.strip_prefix("fc_"))
        .unwrap_or(call_id)
}

#[derive(Debug, Clone, Default)]
struct LedgerEntry {
    name: Option<String>,
    arguments: Option<String>,
    streamed_arguments: bool,
}

/// Per-stream tool-call emission ledger: one entry per logical call.
#[derive(Debug, Default)]
pub struct ToolEmitLedger {
    entries: HashMap<String, LedgerEntry>,
    orphan_seq: u64,
}

impl ToolEmitLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// True when this call has not been defined yet; marks it seen.
    pub fn claim_first_emission(
        &mut self,
        call_id: &str,
        name: Option<&str>,
        args: Option<&str>,
    ) -> bool {
        let key = tool_identity_key(call_id).to_owned();
        if self.entries.contains_key(&key) {
            return false;
        }
        self.entries.insert(
            key,
            LedgerEntry {
                name: name.map(str::to_owned),
                arguments: args.map(str::to_owned),
                streamed_arguments: false,
            },
        );
        true
    }

    pub fn has_streamed_arguments(&self, call_id: &str) -> bool {
        self.entries
            .get(tool_identity_key(call_id))
            .is_some_and(|entry| entry.streamed_arguments)
    }

    /// True when a *different* logical call already claimed the same name and
    /// substantive arguments.
    pub fn is_duplicate_definition(&self, call_id: &str, name: &str, args: &str) -> bool {
        if args.trim().is_empty() {
            return false;
        }
        if call_id.starts_with("call_") || call_id.starts_with("fc_") {
            return false;
        }
        let key = tool_identity_key(call_id);
        self.entries.iter().any(|(id, entry)| {
            id != key
                && entry.name.as_deref() == Some(name)
                && entry.arguments.as_deref() == Some(args)
        })
    }

    pub fn mark_streamed_arguments(&mut self, call_id: &str) {
        let key = tool_identity_key(call_id).to_owned();
        match self.entries.get_mut(&key) {
            Some(entry) => entry.streamed_arguments = true,
            None => {
                self.entries.insert(
                    key,
                    LedgerEntry {
                        streamed_arguments: true,
                        ..Default::default()
                    },
                );
            }
        }
    }

    pub fn next_orphan_id(&mut self, prefix: &str) -> String {
        self.orphan_seq += 1;
        format!("{prefix}-orphan-{}", self.orphan_seq)
    }

    pub fn reset(&mut self) {
        self.entries.clear();
        self.orphan_seq = 0;
    }
}

#[cfg(test)]
mod ledger_tests {
    use super::*;

    #[test]
    fn duplicate_definitions_require_substantive_arguments() {
        let mut ledger = ToolEmitLedger::new();
        assert!(ledger.claim_first_emission("weird-1", Some("read"), Some("{\"a\":1}")));
        assert!(ledger.is_duplicate_definition("weird-2", "read", "{\"a\":1}"));
        assert!(!ledger.is_duplicate_definition("weird-2", "read", ""));
        assert!(!ledger.is_duplicate_definition("call_2", "read", "{\"a\":1}"));
        assert!(!ledger.is_duplicate_definition("weird-1", "read", "{\"a\":1}"));
    }

    #[test]
    fn identity_key_strips_one_known_prefix() {
        assert_eq!(tool_identity_key("call_abc"), "abc");
        assert_eq!(tool_identity_key("fc_abc"), "abc");
        assert_eq!(tool_identity_key("abc"), "abc");
        assert_eq!(tool_identity_key("call_call_abc"), "call_abc");
    }
}
