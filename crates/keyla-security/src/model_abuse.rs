//! Graduated strikes for clients that repeatedly request models they may not
//! use. A valid-model request clears the counter; a ban lapses on its own.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

const MAX_KEYS: usize = 10_000;

/// Process-wide strike store shared by the data plane and the console.
pub fn global() -> Arc<ModelAbuse> {
    static GLOBAL: OnceLock<Arc<ModelAbuse>> = OnceLock::new();
    Arc::clone(GLOBAL.get_or_init(|| Arc::new(ModelAbuse::from_env())))
}

#[derive(Debug, Default, Clone, Copy)]
struct Strike {
    count: i64,
    expires_at: i64,
}

#[derive(Debug)]
pub struct ModelAbuse {
    threshold: i64,
    window_ms: i64,
    ban_ttl_ms: i64,
    strikes: Mutex<HashMap<String, Strike>>,
    bans: Mutex<HashMap<String, i64>>,
}

impl ModelAbuse {
    pub fn new(threshold: i64, window_ms: i64, ban_ttl_ms: i64) -> Self {
        Self {
            threshold: threshold.max(1),
            window_ms: window_ms.max(1),
            ban_ttl_ms: ban_ttl_ms.max(1),
            strikes: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_env() -> Self {
        let threshold = env_i64("KEYLA_MODEL_STRIKE_THRESHOLD", 1_000_000);
        let window = env_i64("KEYLA_MODEL_STRIKE_WINDOW_MS", 300_000);
        let ttl = env_i64("KEYLA_MODEL_BAN_TTL_MS", 3_600_000);
        Self::new(threshold, window, ttl)
    }

    fn expired_ban(&self, ip: &str, now: i64) -> bool {
        let bans = self
            .bans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match bans.get(ip) {
            Some(until) if *until > now => true,
            Some(_) => false,
            None => false,
        }
    }

    /// Pre-parse gate; `true` closes the request before authentication.
    pub fn is_banned(&self, ip: &str, now: i64) -> bool {
        self.expired_ban(ip, now)
    }

    /// Records an invalid-model attempt. Returns `(banned_now, strikes)`.
    pub fn record_invalid(&self, ip: &str, now: i64) -> (bool, i64) {
        let mut strikes = self
            .strikes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if strikes.len() >= MAX_KEYS {
            strikes.retain(|_, strike| strike.expires_at > now);
        }
        let entry = strikes.entry(ip.to_owned()).or_insert(Strike {
            count: 0,
            expires_at: now + self.window_ms,
        });
        if entry.expires_at <= now {
            entry.count = 0;
            entry.expires_at = now + self.window_ms;
        }
        entry.count += 1;
        let count = entry.count;
        drop(strikes);
        if count >= self.threshold {
            if let Ok(mut bans) = self.bans.lock() {
                bans.insert(ip.to_owned(), now + self.ban_ttl_ms);
            }
            return (true, count);
        }
        (false, count)
    }

    /// A valid-model request clears the consecutive counter.
    pub fn note_valid(&self, ip: &str) {
        if let Ok(mut strikes) = self.strikes.lock() {
            strikes.remove(ip);
        }
    }
}

impl ModelAbuse {
    /// Active bans for the console, newest expiry first.
    pub fn list_bans(&self, now: i64) -> Vec<(String, i64)> {
        let mut bans = self
            .bans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        bans.retain(|_, until| *until > now);
        let mut entries: Vec<(String, i64)> = bans
            .iter()
            .map(|(ip, until)| (ip.clone(), *until))
            .collect();
        entries.sort_by_key(|(_, until)| *until);
        entries
    }

    /// Lifts one ban. Returns whether it existed.
    pub fn unban(&self, identity: &str) -> bool {
        let mut bans = self
            .bans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        bans.remove(identity).is_some()
    }
}

fn env_i64(name: &str, fallback: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(fallback)
}
