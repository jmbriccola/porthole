//! What crosses the bus.
//!
//! The wire types are deliberately not the domain types. [`ManagedRule`]
//! carries a [`RuleHandle`] — the exact specification needed to remove a rule
//! from the firewall — and a client that held one could ask the helper to
//! remove rules it never created. It stays on the privileged side, exactly as
//! it stays out of `--json`.
//!
//! D-Bus has no optional types, so `expires_at == 0` means "until reboot".
//! Epoch 0 is 1970 and can never be a real expiry.

use crate::engine::Status;
use crate::model::Target;
use crate::state::ManagedRule;
use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;

/// The well-known name the helper owns on the system bus.
pub const SERVICE: &str = "com.jacopobriccola.Porthole";
/// The object the helper serves.
pub const PATH: &str = "/com/jacopobriccola/Porthole";
/// The interface clients talk to.
pub const INTERFACE: &str = "com.jacopobriccola.Porthole1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct WireRule {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    /// A CIDR, or the literal `anywhere`.
    pub target: String,
    /// `network` or `anywhere`.
    pub scope: String,
    pub backend: String,
    pub opened_at: u64,
    /// Seconds since the epoch, or **0 for until-reboot**.
    pub expires_at: u64,
    pub uid: u32,
}

impl WireRule {
    pub fn from_rule(rule: &ManagedRule) -> Self {
        WireRule {
            id: rule.id.clone(),
            port: rule.port,
            protocol: rule.protocol.to_string(),
            target: rule.target.to_string(),
            scope: match rule.target {
                Target::Network { .. } => "network",
                Target::Anywhere => "anywhere",
            }
            .to_string(),
            backend: rule.backend.to_string(),
            opened_at: rule.opened_at,
            expires_at: rule.expires_at.unwrap_or(0),
            uid: rule.uid,
        }
    }
}

/// One failure from `close_all`, carried structurally rather than as a bare
/// rendered string.
///
/// A single failed `close`, `close_by_id` or `open` reports itself as a typed
/// D-Bus error name, which the client maps back to the exact `kind` slug and
/// exit code the CLI would have produced locally. `close_all` cannot use that
/// mechanism for its *per-rule* failures — the call as a whole still
/// succeeds — so without this shape those failures had nothing but a
/// `.to_string()`, and a client reporting `--json` had no `kind` or `code` to
/// put in each error, only `"unexpected"`. This carries the same three things
/// a single failure would have sent as a typed error, so `close --all --json`
/// cannot tell a bus-backed failure apart from a local one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct WireError {
    pub message: String,
    /// The same stable slug `Error::kind()` produces locally.
    pub kind: String,
    /// The same `ExitCode` a local failure of this kind would carry, as i32.
    pub code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct WireStatus {
    pub backend: String,
    pub firewall_available: bool,
    pub firewall_active: bool,
    /// Empty when unknown.
    pub firewall_version: String,
    /// The firewalld zone, or empty.
    pub location: String,
    /// Empty when not on a usable network.
    pub interface: String,
    /// This machine's own address on that interface. `docs/json-schema.md`
    /// already publishes it in the local `--json` status, so a D-Bus-backed
    /// view has to be able to show the same thing.
    pub address: String,
    pub cidr: String,
    pub rules: Vec<WireRule>,
}

impl WireStatus {
    pub fn from_status(status: &Status) -> Self {
        WireStatus {
            backend: status.backend.to_string(),
            firewall_available: status.health.available,
            firewall_active: status.health.active,
            firewall_version: status.health.version.clone().unwrap_or_default(),
            location: status.location.clone().unwrap_or_default(),
            interface: status
                .network
                .as_ref()
                .map(|n| n.interface.clone())
                .unwrap_or_default(),
            address: status
                .network
                .as_ref()
                .map(|n| n.address.to_string())
                .unwrap_or_default(),
            cidr: status
                .network
                .as_ref()
                .map(|n| n.cidr.to_string())
                .unwrap_or_default(),
            rules: status.rules.iter().map(WireRule::from_rule).collect(),
        }
    }
}

/// The client side of the helper's interface.
///
/// `scope` is passed as the user typed it — `subnet`, `any`, a CIDR, an IP —
/// and the **helper** parses and validates it. The client never sends a rule
/// string, and never sends anything the helper does not re-check.
///
/// `seconds` is 0 for until-reboot.
#[zbus::proxy(
    interface = "com.jacopobriccola.Porthole1",
    default_service = "com.jacopobriccola.Porthole",
    default_path = "/com/jacopobriccola/Porthole"
)]
pub trait Porthole {
    async fn open(
        &self,
        port: u16,
        protocol: &str,
        scope: &str,
        seconds: u32,
    ) -> zbus::Result<WireRule>;

    async fn close(&self, port: u16, protocol: &str) -> zbus::Result<WireRule>;

    /// `from_timer` is the expiry timer's own claim about itself, forwarded
    /// from `--from-timer` — see `porthole_helper::service::Porthole::close_by_id`
    /// for why the helper accepts it from the client rather than verifying it
    /// independently.
    async fn close_by_id(&self, id: &str, from_timer: bool) -> zbus::Result<WireRule>;

    /// Returns what closed and, separately, the failures — so one stuck rule
    /// cannot hide the others, exactly as `close --all` behaves locally.
    async fn close_all(&self) -> zbus::Result<(Vec<WireRule>, Vec<WireError>)>;

    async fn list(&self) -> zbus::Result<Vec<WireRule>>;

    async fn status(&self) -> zbus::Result<WireStatus>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendHealth, BackendId, RuleHandle};
    use crate::model::{Protocol, Target};
    use crate::net::LocalNetwork;
    use crate::state::ManagedRule;

    fn rule(expires_at: Option<u64>) -> ManagedRule {
        ManagedRule {
            id: "abc".to_string(),
            port: 5173,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            backend: BackendId::Firewalld,
            opened_at: 1_757_000_000,
            expires_at,
            uid: 1000,
            handle: RuleHandle::Firewalld {
                zone: "FedoraWorkstation".to_string(),
                rich_rule: "the exact spec needed to remove this".to_string(),
            },
        }
    }

    #[test]
    fn the_wire_form_carries_what_a_client_needs() {
        let wire = WireRule::from_rule(&rule(Some(1_757_003_600)));
        assert_eq!(wire.id, "abc");
        assert_eq!(wire.port, 5173);
        assert_eq!(wire.protocol, "tcp");
        assert_eq!(wire.target, "10.10.10.0/24");
        assert_eq!(wire.scope, "network");
        assert_eq!(wire.backend, "firewalld");
        assert_eq!(wire.opened_at, 1_757_000_000);
        assert_eq!(wire.expires_at, 1_757_003_600);
        assert_eq!(wire.uid, 1000);
    }

    #[test]
    fn the_removal_spec_never_crosses_the_bus() {
        // The handle is what removes a rule from the firewall. A client that
        // had it could ask the helper to remove rules it did not create, so it
        // must not be reachable from the wire form at all.
        let wire = WireRule::from_rule(&rule(None));
        let encoded = format!("{wire:?}");
        assert!(
            !encoded.contains("the exact spec needed to remove this"),
            "the rule handle leaked onto the wire: {encoded}"
        );
        assert!(!encoded.contains("rich_rule"), "got: {encoded}");
    }

    #[test]
    fn until_reboot_is_expires_at_zero() {
        // D-Bus has no optional types. Epoch 0 is 1970 and can never be a real
        // expiry, so it is the sentinel — one field rather than two that can
        // disagree with each other.
        assert_eq!(WireRule::from_rule(&rule(None)).expires_at, 0);
    }

    #[test]
    fn anywhere_is_reported_as_its_own_scope() {
        let mut r = rule(None);
        r.target = Target::Anywhere;
        let wire = WireRule::from_rule(&r);
        assert_eq!(wire.scope, "anywhere");
        assert_eq!(wire.target, "anywhere");
    }

    #[test]
    fn status_carries_the_network_a_client_needs_to_show() {
        // interface, address and cidr all come from the same LocalNetwork,
        // so a regression that drops one silently is easy to miss unless all
        // three are checked together.
        let status = Status {
            backend: BackendId::Firewalld,
            health: BackendHealth {
                available: true,
                active: true,
                version: Some("1.3.2".to_string()),
                detail: "running".to_string(),
                caveat: None,
            },
            network: Some(LocalNetwork {
                interface: "wlo1".to_string(),
                address: "10.10.10.119".parse().unwrap(),
                cidr: "10.10.10.0/24".parse().unwrap(),
            }),
            location: Some("FedoraWorkstation".to_string()),
            rules: vec![],
        };

        let wire = WireStatus::from_status(&status);
        assert_eq!(wire.interface, "wlo1");
        assert_eq!(wire.address, "10.10.10.119");
        assert_eq!(wire.cidr, "10.10.10.0/24");
    }

    #[test]
    fn wire_error_carries_the_same_three_things_a_typed_dbus_error_would() {
        // close_all cannot report a per-rule failure as a typed D-Bus error
        // name -- the call as a whole still succeeds -- so this is what lets
        // its failures carry the same kind slug and exit code a single failed
        // close would have sent, instead of a bare rendered string.
        let error = WireError {
            message: "command `firewall-cmd ...` exited with status 1: boom".to_string(),
            kind: "command_failed".to_string(),
            code: crate::error::ExitCode::Failure as i32,
        };
        let json = serde_json::to_value(&error).unwrap();
        assert_eq!(json["kind"], "command_failed");
        assert_eq!(json["code"], 1);
        assert!(json["message"].as_str().unwrap().contains("firewall-cmd"));
    }
}
