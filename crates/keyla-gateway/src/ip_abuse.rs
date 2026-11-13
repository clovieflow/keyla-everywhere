//! Per-identity admission on `/v1/*`: a sliding one-minute window plus an
//! escalating one-hour ban once the threshold is crossed.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use keyla_core::{GatewayError, GatewayErrorCode};
use serde_json::{Map, json};

const WINDOW_MS: i64 = 60_000;
const BAN_MS: i64 = 60 * 60 * 1000;
const MAX_KEYS: usize = 10_000;

#[derive(Debug)]
pub struct IpAbuse {
    limit: i64,
    threshold: i64,
    windows: Mutex<HashMap<String, VecDeque<i64>>>,
    bans: Mutex<HashMap<String, i64>>,
    identity_counts: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl IpAbuse {
    pub fn new(limit: i64) -> Self {
        Self {
            limit: limit.max(1),
            threshold: (limit.max(1) * 2).max(limit.max(1) + 1),
            windows: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
            identity_counts: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_env() -> Self {
        let limit =
            keyla_config::resolve_ip_rate_limit(&keyla_config::ProcessEnv).unwrap_or(240) as i64;
        Self::new(limit)
    }

    fn prune(queue: &mut VecDeque<i64>, cutoff: i64) {
        while queue.front().is_some_and(|value| *value <= cutoff) {
            queue.pop_front();
        }
    }

    /// Records one attempt and decides it. The route window bounds per-path
    /// traffic; the identity counter triggers a ban when the caller spreads
    /// the same volume across paths.
    pub fn check(&self, identity: &str, route: &str, now: i64) -> Result<(), GatewayError> {
        let expired = {
            let bans = self
                .bans
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match bans.get(identity) {
                Some(until) if *until > now => {
                    return Err(self.refusal(now, *until - now, "banned"));
                }
                Some(_) => true,
                None => false,
            }
        };
        if expired {
            if let Ok(mut bans) = self.bans.lock() {
                bans.remove(identity);
            }
        }
        let cutoff = now - WINDOW_MS;
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if windows.len() >= MAX_KEYS {
            windows.retain(|_, queue| queue.back().is_some_and(|value| *value > cutoff));
        }
        let key = format!("{identity}\u{0}{route}");
        let queue = windows.entry(key).or_default();
        Self::prune(queue, cutoff);
        queue.push_back(now);
        let count = queue.len() as i64;
        let oldest = queue.front().copied().unwrap_or(now);
        drop(windows);

        let mut counts = self
            .identity_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if counts.len() >= MAX_KEYS {
            counts.retain(|_, queue| queue.back().is_some_and(|value| *value > cutoff));
        }
        let identity_queue = counts.entry(identity.to_owned()).or_default();
        Self::prune(identity_queue, cutoff);
        identity_queue.push_back(now);
        let identity_count = identity_queue.len() as i64;
        drop(counts);

        if identity_count >= self.threshold {
            let until = now + BAN_MS;
            if let Ok(mut bans) = self.bans.lock() {
                bans.insert(identity.to_owned(), until);
            }
            return Err(self.refusal(now, BAN_MS, "banned_now"));
        }
        if count > self.limit {
            return Err(self.refusal(now, (oldest + WINDOW_MS - now).max(0), "rate_limited"));
        }
        Ok(())
    }

    fn refusal(&self, _now: i64, retry_after_ms: i64, reason: &str) -> GatewayError {
        let mut details = Map::new();
        details.insert("scope".into(), json!("ip"));
        details.insert("reason".into(), json!(reason));
        details.insert("retryAfterMs".into(), json!(retry_after_ms));
        details.insert("limit".into(), json!(self.limit));
        GatewayError::new(
            GatewayErrorCode::QuotaExceeded,
            429,
            if reason == "rate_limited" {
                "ip_rate_limited: too many requests from this address"
            } else {
                "ip_banned: this address is temporarily blocked"
            },
            details,
        )
    }
}

/// Resolves the client identity at the trusted-proxy boundary. Without an
/// operator allowlist, only the TCP peer is trusted; `platform` mode reads the
/// first forwarded hop.
pub fn client_identity(
    peer: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    boundary: &keyla_config::TrustedProxyMode,
) -> std::net::IpAddr {
    match boundary {
        keyla_config::TrustedProxyMode::Disabled => peer,
        keyla_config::TrustedProxyMode::Platform => headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(peer),
        keyla_config::TrustedProxyMode::Trusted { allowlist } => {
            if allowlist.iter().any(|entry| cidr_contains(entry, peer)) {
                headers
                    .get("x-forwarded-for")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(',').next())
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(peer)
            } else {
                peer
            }
        }
    }
}

fn cidr_contains(entry: &str, address: std::net::IpAddr) -> bool {
    let Some((network, prefix)) = entry.split_once('/') else {
        return entry.parse::<std::net::IpAddr>() == Ok(address);
    };
    let Ok(network) = network.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    match (network, address) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(address)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(network) & mask) == (u32::from(address) & mask)
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(address)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(network) & mask) == (u128::from(address) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn rate_window_rejects_after_limit_and_recovers() {
        let abuse = IpAbuse::new(2);
        let start = 1_000_000i64;
        assert!(
            abuse
                .check("1.2.3.4", "/v1/chat/completions", start)
                .is_ok()
        );
        assert!(
            abuse
                .check("1.2.3.4", "/v1/chat/completions", start + 1)
                .is_ok()
        );
        let error = abuse
            .check("1.2.3.4", "/v1/chat/completions", start + 2)
            .unwrap_err();
        assert_eq!(error.status, 429);
        assert_eq!(error.details["reason"], "rate_limited");
        assert!(error.details["retryAfterMs"].as_i64().unwrap_or(0) > 0);
        assert!(
            abuse
                .check("1.2.3.4", "/v1/chat/completions", start + WINDOW_MS + 1)
                .is_ok()
        );
    }

    #[test]
    fn identity_ban_survives_route_rotation() {
        let abuse = IpAbuse::new(2);
        let start = 2_000_000i64;
        assert!(
            abuse
                .check("1.2.3.4", "/v1/chat/completions", start)
                .is_ok()
        );
        assert!(
            abuse
                .check("1.2.3.4", "/v1/chat/completions", start + 1)
                .is_ok()
        );
        assert!(abuse.check("1.2.3.4", "/v1/models", start + 2).is_ok());
        let error = abuse
            .check("1.2.3.4", "/v1/responses", start + 3)
            .unwrap_err();
        assert_eq!(error.details["reason"], "banned_now");
        let blocked = abuse
            .check("1.2.3.4", "/v1/chat/completions", start + 4)
            .unwrap_err();
        assert_eq!(blocked.details["reason"], "banned");
        assert!(
            abuse
                .check("1.2.3.4", "/v1/chat/completions", start + BAN_MS + 10)
                .is_ok()
        );
    }

    #[test]
    fn forwarded_headers_are_only_trusted_from_an_allowlisted_peer() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9, 10.0.0.5".parse().unwrap());
        let disabled = keyla_config::TrustedProxyMode::Disabled;
        assert_eq!(client_identity(peer, &headers, &disabled), peer);
        let trusted = keyla_config::TrustedProxyMode::Trusted {
            allowlist: vec!["10.0.0.0/8".into()],
        };
        assert_eq!(
            client_identity(peer, &headers, &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        let untrusted = keyla_config::TrustedProxyMode::Trusted {
            allowlist: vec!["192.168.0.0/16".into()],
        };
        assert_eq!(client_identity(peer, &headers, &untrusted), peer);
    }
}
