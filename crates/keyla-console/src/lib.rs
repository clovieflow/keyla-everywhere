#![recursion_limit = "256"]
//! Console authentication, sessions, and API domains.

pub mod access;
pub mod accounts;
pub mod auth;
pub mod backup;
pub mod bansos;
pub mod cli_tools;
pub mod keys;
pub mod live;
pub mod logs;
pub mod moderation;
pub mod network;
pub mod oauth;
pub mod observability;
pub mod prompt_injection;
pub mod providers;
pub mod public_share;
pub mod quota;
pub mod quota_fetch;
pub mod routes;
pub mod routing;
pub mod settings;
pub mod studio;

pub use routes::{
    ConsoleState, LiveInFlightSnapshot, console_router, console_router_with_live,
    console_router_with_policy,
};
