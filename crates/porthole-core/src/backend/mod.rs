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
pub mod nftables;
pub mod ufw;

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
/// Note on markers: ufw and nftables rules carry a `porthole:<uuid>` comment
/// (the `marker` field below). firewalld rich rules cannot — the rich
/// language has no comment element — so for firewalld the stored `rich_rule`
/// string, exactly as firewalld normalised it, *is* the identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum RuleHandle {
    Firewalld {
        zone: String,
        rich_rule: String,
    },
    /// ufw deletes by re-stating the rule, not by number: numbers shift
    /// whenever any other rule is removed, so a stored number is a
    /// use-after-free waiting to happen. `spec` is the argument list after
    /// `allow`, e.g. `from 10.10.10.0/24 to any port 5173 proto tcp`.
    Ufw {
        spec: String,
        marker: String,
    },
    /// nftables rules live in the user's own enforcing chain — see
    /// `nftables.rs` for why a table of porthole's own does not work. The
    /// kernel-assigned handle is deliberately **not** stored: handles are not
    /// stable across a ruleset flush, so it is re-read from the marker at
    /// close time.
    Nftables {
        family: String,
        table: String,
        chain: String,
        marker: String,
    },
}

/// Whether a backend can prove which rules porthole created.
///
/// This is not a detail. Reconciliation removes rules the firewall has and
/// porthole's state does not. On a backend that cannot tell its own rules from
/// the user's, that sweep deletes the user's firewall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// Every rule carries `porthole:<uuid>`. A rule either is porthole's or it
    /// plainly is not.
    Marked,
    /// The backend has nowhere to put a marker. firewalld's rich language has
    /// no comment element, so a rule porthole wrote is textually identical to
    /// one the user wrote by hand.
    Unprovable,
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

    /// Create the rule.
    ///
    /// `marker` is `porthole:<uuid>`, built from the `ManagedRule::id` the
    /// engine mints before calling in, so a backend never invents identity and
    /// the marker in the firewall always matches the one in the state file.
    /// firewalld ignores it — its rich language has nowhere to put it — and
    /// that asymmetry is exactly what `Ownership` records.
    fn open(&self, req: &OpenRequest, marker: &str) -> Result<RuleHandle>;
    fn close(&self, handle: &RuleHandle) -> Result<()>;

    /// Every rule visible in the place porthole writes to.
    ///
    /// **This is diagnostic information, not evidence of ownership.** On
    /// firewalld it is every rich rule in the zone, the user's included. Use
    /// [`FirewallBackend::owned_rules`] when the answer must be "porthole's
    /// rules".
    fn list_rules(&self) -> Result<Vec<RuleHandle>>;

    /// The rules porthole can *prove* it created, or `None` when this backend
    /// cannot prove it.
    ///
    /// Returns `None` if and only if [`FirewallBackend::ownership`] is
    /// [`Ownership::Unprovable`]. Reconciliation's orphan sweep consumes this,
    /// so on such a backend there is no way to obtain a list to sweep — the
    /// mistake is unavailable rather than merely discouraged.
    fn owned_rules(&self) -> Result<Option<Vec<RuleHandle>>>;

    /// The static answer to "can this backend identify its own rules?", for
    /// messaging that should not pay for a firewall call.
    fn ownership(&self) -> Ownership;

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

#[cfg(test)]
mod tests {
    use super::firewalld;
    use super::firewalld::tests::{ROUTE_JSON, SUBNET_RULE, ZONE};
    use super::nftables;
    use super::ufw;
    use super::{FirewallBackend, Ownership};
    use crate::command::{Output, RecordingRunner};

    #[test]
    fn firewalld_cannot_prove_ownership_and_says_so() {
        // The rich language has no comment element. If this ever changes, the
        // reconciliation sweep in reconcile.rs becomes available on firewalld —
        // and that is a deliberate decision, not something to discover by
        // accident, so it must break a test first.
        let runner = RecordingRunner::new();
        assert_eq!(
            firewalld::Firewalld::new(&runner).ownership(),
            Ownership::Unprovable
        );
    }

    #[test]
    fn a_backend_that_cannot_prove_ownership_returns_no_owned_rules() {
        // The two must agree, always. `ownership()` is the cheap static answer
        // used for messaging; `owned_rules()` is what reconciliation consumes.
        // If they could drift, a caller could get Some(rules) from a backend that
        // does not actually know which rules are porthole's — which is precisely
        // the bug this seam exists to prevent.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(SUBNET_RULE),
        ]);
        let backend = firewalld::Firewalld::new(&runner);
        assert_eq!(backend.ownership(), Ownership::Unprovable);
        assert!(backend.owned_rules().unwrap().is_none());
    }

    #[test]
    fn list_rules_on_firewalld_returns_the_users_rules_too() {
        // Documents the hazard in an executable place: this list is diagnostic,
        // not evidence. A user rule porthole never created appears here.
        //
        // family="ipv6" is the load-bearing part of this fixture, not the
        // source/port/protocol. `Firewalld::rich_rule` hardcodes
        // `family="ipv4"` in both of its match arms (porthole v1 does not
        // manage IPv6 — see the module doc), so no `OpenRequest` porthole
        // builds can ever produce an ipv6 rich rule. A rule that only varies
        // the CIDR or port from `rich_rule`'s own template would not prove
        // anything: porthole could have written that one too.
        const USER_RULE: &str = r#"rule family="ipv6" source address="2001:db8::/32" port port="22" protocol="tcp" accept"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(&format!("{SUBNET_RULE}\n{USER_RULE}")),
        ]);
        let rules = firewalld::Firewalld::new(&runner).list_rules().unwrap();
        assert_eq!(rules.len(), 2, "the user's own rule is in this list");
    }

    #[test]
    fn ownership_and_owned_rules_agree_for_every_backend() {
        // `owned_rules` returns None if and only if `ownership()` is
        // Unprovable. They are two hand-written answers to one question, so
        // this asserts they are the same answer — for every backend, not
        // just the one whose author remembered to check.
        //
        // The match on BackendId is exhaustive on purpose: adding a backend
        // without adding it here does not compile, which is the only version
        // of this test that stays true.
        fn check(backend: &dyn FirewallBackend) {
            let expected_none = backend.ownership() == Ownership::Unprovable;
            assert_eq!(
                backend.owned_rules().unwrap().is_none(),
                expected_none,
                "{:?} disagrees with itself about whether it can prove ownership",
                backend.id()
            );
        }

        for id in [
            super::BackendId::Firewalld,
            super::BackendId::Ufw,
            super::BackendId::Nftables,
        ] {
            match id {
                super::BackendId::Firewalld => {
                    check(&firewalld::Firewalld::new(&RecordingRunner::new()));
                }
                super::BackendId::Ufw => {
                    check(&ufw::Ufw::new(&RecordingRunner::new()));
                }
                super::BackendId::Nftables => {
                    // A bare `RecordingRunner::new()` answers every read with
                    // empty stdout, and empty stdout is not valid `nft -j`
                    // output -- unlike ufw's and firewalld's parsers, this one
                    // would then error rather than report zero rules. So this
                    // scripts the smallest *valid* answer instead: an envelope
                    // with no chain at the input hook, which is a legitimate
                    // (if unenforced) nftables state, not a parse failure.
                    const NO_INPUT_CHAIN: &str = r#"{"nftables":[
                        {"metainfo":{"version":"1.1.3","json_schema_version":1}}
                    ]}"#;
                    check(&nftables::Nftables::new(&RecordingRunner::with_responses(
                        vec![Output::stdout(NO_INPUT_CHAIN)],
                    )));
                }
            }
        }
    }
}
