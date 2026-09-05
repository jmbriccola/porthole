//! The firewall backend abstraction.
//!
//! A backend turns a validated [`OpenRequest`] into a rule and hands back a
//! [`RuleHandle`] — the exact specification needed to remove that rule again.
//! The handle is serialised into the state file, so removal does not depend on
//! being able to reconstruct the rule from scratch later.
//!
//! No backend ever writes a permanent rule. On firewalld that means never
//! `--permanent`; on nftables it means never touching `/etc/nftables.conf`; on
//! ufw, which has no runtime-only concept at all, it means milestone 3 has to
//! clean up explicitly.

pub mod fake;
pub mod firewalld;

use crate::command::CommandRunner;
use crate::error::{Error, Result};
use crate::model::OpenRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendId {
    Firewalld,
    Ufw,
    Nftables,
}

impl std::fmt::Display for BackendId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendId::Firewalld => f.write_str("firewalld"),
            BackendId::Ufw => f.write_str("ufw"),
            BackendId::Nftables => f.write_str("nftables"),
        }
    }
}

/// Everything needed to remove a rule that porthole created.
///
/// Serialised into `/run/porthole/state.json`, so changing a variant's shape is
/// a state-file format change.
///
/// Note on markers: ufw and nftables rules will carry a `porthole:<uuid>`
/// comment (milestone 3). firewalld rich rules cannot — the rich language has
/// no comment element — so for firewalld the stored `rich_rule` string, exactly
/// as firewalld normalised it, *is* the identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum RuleHandle {
    Firewalld { zone: String, rich_rule: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendHealth {
    /// The backend's tooling is installed.
    pub available: bool,
    /// The firewall is actually running and enforcing rules.
    pub active: bool,
    pub version: Option<String>,
    /// A sentence fit to show the user.
    pub detail: String,
}

pub trait FirewallBackend {
    fn id(&self) -> BackendId;
    fn open(&self, req: &OpenRequest) -> Result<RuleHandle>;
    fn close(&self, handle: &RuleHandle) -> Result<()>;
    /// Rules this backend can see that porthole may have created. Used by the
    /// reconciliation pass (milestone 3).
    fn list_managed(&self) -> Result<Vec<RuleHandle>>;
    fn health(&self) -> Result<BackendHealth>;

    /// Where this backend keeps porthole's rules — the firewalld zone, the ufw
    /// chain. Shown by `porthole status`; `None` when the concept does not
    /// apply.
    fn location(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Pick a backend: firewalld, then ufw, then nftables.
///
/// Milestone 1 only implements firewalld. A backend that is installed but
/// stopped is still returned: reporting "installed but not running" is more
/// useful than reporting "absent", and it is the caller's job to refuse to open
/// anything in that state.
pub fn detect<'a>(runner: &'a dyn CommandRunner) -> Result<Box<dyn FirewallBackend + 'a>> {
    let firewalld = firewalld::Firewalld::new(runner);
    if firewalld.health()?.available {
        return Ok(Box::new(firewalld));
    }
    Err(Error::BackendUnavailable(format!(
        "firewalld is not installed. porthole {} manages firewalld only; \
         support for ufw and nftables is planned. If you use one of those, \
         porthole cannot see your rules and cannot tell you whether this port \
         is reachable.",
        env!("CARGO_PKG_VERSION")
    )))
}
