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

/// The well-known name the helper owns -- the system bus in production, or
/// the session bus when the helper is started with `--session` (tests only;
/// see `porthole_helper::main`'s own module doc). The name itself is
/// identical either way.
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

/// Why a rule stopped being open, as it crosses the bus in `RuleClosed`.
///
/// A single undifferentiated "closed" would force every subscriber to guess:
/// a rule that ran out its own clock, one a person asked to close, one the
/// helper closed because the machine left the network it was scoped to, and
/// one that was already gone from the firewall by the time porthole looked
/// are four different things to tell a user about. The wire form is the slug
/// [`CloseReason::as_str`] returns — one source of truth for the string,
/// which the journal line and the signal both derive from, so neither can
/// drift from the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[zvariant(signature = "s")]
#[serde(rename_all = "kebab-case")]
pub enum CloseReason {
    /// The rule's own lifetime ran out and the expiry timer closed it.
    Expired,
    /// Somebody asked: `close`, `close --id`, or `close --all`.
    Requested,
    /// The rule was scoped to a subnet the machine is no longer on -- see
    /// `porthole_core::engine::Engine::close_rules_outside`.
    NetworkChanged,
    /// Reconciliation found porthole's record of a rule the firewall no
    /// longer has, and dropped the record. Nothing was removed from any
    /// firewall for this one: the port had already stopped being open, and
    /// this is porthole noticing.
    ///
    /// Not only at helper start-up. A `firewall-cmd --reload` (or a `ufw
    /// reload`) while the helper is running produces this on the next
    /// operation whose sweep both finds the record and saves without it --
    /// including one that then fails because the rule it was about to act on
    /// is the one that had gone. A read produces none: `list` and `status`
    /// never save, so the record is still in the state file and the next
    /// operation that does write is where it is dropped for real.
    Reconciled,
}

impl CloseReason {
    /// The exact slug that crosses the bus. Kept next to the enum rather
    /// than spelled out at each call site so the journal and the signal
    /// cannot disagree about what a close was.
    pub fn as_str(self) -> &'static str {
        match self {
            CloseReason::Expired => "expired",
            CloseReason::Requested => "requested",
            CloseReason::NetworkChanged => "network-changed",
            CloseReason::Reconciled => "reconciled",
        }
    }
}

impl std::fmt::Display for CloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
    /// `true` when `firewall_active: false` means "porthole could not
    /// confirm activity," never "porthole confirmed there is none" — the
    /// same distinction `status --json`'s own `firewall_active_unknown`
    /// carries (see `docs/json-schema.md`), reproduced here so a client on
    /// this surface is not left with the one undistinguished bit the local
    /// `--json` path already stopped carrying. The production helper always
    /// runs as root, which rules out the *permission-denied* case ufw and
    /// nftables both have -- but not every case: an installed `nft` whose
    /// ruleset porthole cannot parse sets this `true` for a root caller just
    /// as it does for an unprivileged one (`Nftables::health`'s own
    /// catch-all `Err` arm), and firewalld's resource-level `--state`
    /// spawn failure can too. A `--session` helper run by an ordinary user
    /// -- which this milestone's own e2e suite does -- can additionally hit
    /// the permission-denied case a system helper never would.
    pub firewall_active_unknown: bool,
    /// Empty when unknown.
    pub firewall_version: String,
    /// `BackendHealth::detail`, verbatim -- the same text `porthole-cli`'s
    /// own `print_status` (plain `porthole status`, not `--json`, which
    /// deliberately does not carry this field -- see `docs/json-schema.md`'s
    /// own paragraph on the collapse that leaves unnamed) already shows a
    /// person. Never empty in practice today (every `BackendHealth` this
    /// codebase constructs sets it), but a client must not assume it always
    /// will be: this is what lets a GUI render *this* crate's own account of
    /// why a firewall is unavailable or inactive, verbatim, instead of a
    /// client-authored guess resting on an invariant ("the only way `detect`
    /// can fail is 'no firewall installed'") held entirely in this crate,
    /// with nothing in the wire type connecting the two. See
    /// `porthole-gui/src/status_bar.rs`'s own module doc for the client that
    /// needed exactly this.
    pub detail: String,
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
            firewall_active_unknown: status.health.active_unknown,
            firewall_version: status.health.version.clone().unwrap_or_default(),
            detail: status.health.detail.clone(),
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

/// One port Docker has published, as [`crate::docker::Published`] crosses
/// the bus. D-Bus has no optional types (the same reason [`WireRule`]'s
/// `expires_at` uses `0` as a sentinel): `host_addr` is empty for "no `-d`",
/// i.e. published on every interface, and otherwise the address itself,
/// which can never be the empty string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct WireDockerPort {
    /// Empty means every interface (no `-d` on the rule).
    pub host_addr: String,
    pub host_port: u16,
    pub protocol: String,
    pub container_addr: String,
    pub container_port: u16,
}

impl WireDockerPort {
    pub fn from_published(p: &crate::docker::Published) -> Self {
        WireDockerPort {
            host_addr: p.host_addr.map(|a| a.to_string()).unwrap_or_default(),
            host_port: p.host_port,
            protocol: p.protocol.to_string(),
            container_addr: p.container_addr.to_string(),
            container_port: p.container_port,
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
    ///
    /// `forget` is `--forget`: drop the state record without touching any
    /// firewall, the only way out of the trap a state entry recorded under a
    /// backend this machine no longer has would otherwise be — see
    /// `porthole_core::engine::Engine::forget_rule`. The helper re-checks
    /// that the entry is actually such an orphan before honouring it; a
    /// client claiming `forget: true` for anything else is refused.
    async fn close_by_id(&self, id: &str, from_timer: bool, forget: bool)
        -> zbus::Result<WireRule>;

    /// Returns what closed and, separately, the failures — so one stuck rule
    /// cannot hide the others, exactly as `close --all` behaves locally.
    async fn close_all(&self) -> zbus::Result<(Vec<WireRule>, Vec<WireError>)>;

    async fn list(&self) -> zbus::Result<Vec<WireRule>>;

    async fn status(&self) -> zbus::Result<WireStatus>;

    /// Every port Docker currently has published, read from the `DOCKER`
    /// chain in the `nat` table — see `crate::docker`'s own module doc for
    /// why this needs root, and never asks Docker itself anything. Gated on
    /// the same `list` polkit action as `list`/`status`: it is exactly as
    /// unprivileged a read as either.
    async fn docker_ports(&self) -> zbus::Result<Vec<WireDockerPort>>;

    /// A rule the helper just created. **The rule, not the request**: the id,
    /// the resolved target and the expiry are all decided by the helper, so a
    /// subscriber that reconstructed them from what a client asked for would
    /// be showing something else.
    #[zbus(signal)]
    fn rule_opened(&self, rule: WireRule) -> zbus::Result<()>;

    /// A rule that has stopped being open, and why -- see [`CloseReason`].
    ///
    /// **`list` is the authority; these signals are notifications.** Three
    /// things a subscriber that keeps its whole view from `RuleOpened` and
    /// `RuleClosed` alone would get wrong:
    ///
    /// - A rule can leave `list` with no `RuleClosed` behind it.
    ///   `close --id <id> --forget` drops porthole's record of a rule
    ///   recorded under a backend this machine no longer has, without
    ///   touching any firewall — so none of the four reasons is true of it
    ///   and none is sent. A client that only listens goes on showing that
    ///   rule as open.
    /// - Signals are emitted after the state lock is released, so two
    ///   clients acting at once can put a `RuleClosed` on the bus ahead of
    ///   the `RuleOpened` for a different rule. Per-message ordering from one
    ///   sender is preserved; the order two *operations* completed in is not.
    /// - A signal sent before a client subscribed is simply gone. The
    ///   helper's start-up sweep announces what it dropped as soon as it owns
    ///   the bus name: a client whose match rule is already installed by then
    ///   receives those, and a client that subscribes to a helper already
    ///   running has missed them. The helper is D-Bus activated, so a client
    ///   that subscribes and only then calls it is in the first case.
    ///
    /// So: subscribe, and also call `list` — at start-up, and whenever the
    /// view has to be right rather than merely current.
    #[zbus(signal)]
    fn rule_closed(&self, rule: WireRule, reason: CloseReason) -> zbus::Result<()>;

    /// The machine's own subnet, as porthole last resolved it, changed.
    ///
    /// Both arguments are CIDRs, or **empty for "no usable network"** --
    /// D-Bus has no optional types, the same reason [`WireRule::expires_at`]
    /// uses `0` as its sentinel, and the empty string can never be a CIDR.
    /// `old_cidr` is what the previous check saw, not necessarily what was
    /// true an instant before this one: the helper only looks when it wakes
    /// up (see `porthole_helper::netmon`), so the two values are porthole's
    /// last two observations and nothing finer.
    #[zbus(signal)]
    fn network_changed(&self, old_cidr: &str, new_cidr: &str) -> zbus::Result<()>;
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
                active_unknown: false,
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
    fn wire_status_does_not_collapse_the_activity_distinction_status_json_already_carries() {
        // `--json` stopped carrying only `firewall_active` once a
        // permission-denied read stopped being distinguishable from a
        // confirmed absence of enforcement; this D-Bus surface must not be
        // the one place that regresses back to it. `firewall_active_unknown`
        // is `false` in every case that existed before this field, so a
        // client reading only `firewall_active` is unaffected either way.
        let status = Status {
            backend: BackendId::Ufw,
            health: BackendHealth {
                available: true,
                active: false,
                active_unknown: true,
                version: Some("0.36.2".to_string()),
                detail: "ufw is installed, but reading its status needs more privilege than \
                         this process has"
                    .to_string(),
                caveat: None,
            },
            network: None,
            location: Some("ufw".to_string()),
            rules: vec![],
        };

        let wire = WireStatus::from_status(&status);
        assert!(!wire.firewall_active);
        assert!(wire.firewall_active_unknown);
    }

    #[test]
    fn wire_status_carries_the_health_detail_verbatim() {
        // A D-Bus client (the GUI today) must be able to show the same
        // sentence `porthole-cli`'s own `print_status` already does (not
        // `--json`, which deliberately omits this field -- see
        // `docs/json-schema.md`), rather than resting a claim -- "no
        // firewall means already reachable" -- on an invariant held only in
        // this crate, with nothing in the wire type connecting the two if
        // it ever changed.
        let status = Status {
            backend: BackendId::Firewalld,
            health: BackendHealth {
                available: false,
                active: false,
                active_unknown: false,
                version: None,
                detail: "no firewall found: none of firewalld, ufw or nftables is installed. \
                         Without a firewall this port is already reachable from your network."
                    .to_string(),
                caveat: None,
            },
            network: None,
            location: None,
            rules: vec![],
        };

        let wire = WireStatus::from_status(&status);
        assert_eq!(wire.detail, status.health.detail);
        assert!(wire.detail.contains("already reachable"));
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

    #[test]
    fn a_docker_port_published_everywhere_crosses_the_wire_with_an_empty_host_addr() {
        // No `-d` on the rule means every interface -- see this module's own
        // `WireDockerPort::from_published`. Empty, not the address `"0.0.0.0"`
        // itself, since porthole never actually parses that literal out of
        // the rule -- it only ever infers "no restriction" from `-d`'s
        // absence.
        let p = crate::docker::Published {
            host_addr: None,
            host_port: 8080,
            protocol: Protocol::Tcp,
            container_addr: "172.17.0.2".parse().unwrap(),
            container_port: 80,
        };
        let wire = WireDockerPort::from_published(&p);
        assert_eq!(wire.host_addr, "");
        assert_eq!(wire.host_port, 8080);
        assert_eq!(wire.container_addr, "172.17.0.2");
        assert_eq!(wire.container_port, 80);
    }

    #[test]
    fn every_close_carries_why() {
        // "expired", "requested", "network-changed", "reconciled". The
        // notification says something different for each, and a single
        // undifferentiated ClosedSignal would force the agent to guess.
        //
        // Both halves are checked for every variant: the slug `as_str`
        // returns (what the journal line is built from) and the string that
        // actually crosses the bus (what a subscriber matches on). They are
        // produced by different machinery -- a `match` and serde's
        // `rename_all` -- so a test that checked only one would let the two
        // drift apart silently, which is exactly the failure a reason code
        // exists to prevent.
        use zbus::zvariant::{serialized::Context, to_bytes, LE};

        for (reason, expected) in [
            (CloseReason::Expired, "expired"),
            (CloseReason::Requested, "requested"),
            (CloseReason::NetworkChanged, "network-changed"),
            (CloseReason::Reconciled, "reconciled"),
        ] {
            assert_eq!(reason.as_str(), expected);
            assert_eq!(reason.to_string(), expected);

            let encoded = to_bytes(Context::new_dbus(LE, 0), &reason).unwrap();
            let on_the_wire: String = encoded.deserialize().unwrap().0;
            assert_eq!(
                on_the_wire, expected,
                "{reason:?} crosses the bus as {on_the_wire:?}, not as its own slug"
            );

            let back: CloseReason = encoded.deserialize().unwrap().0;
            assert_eq!(back, reason, "a subscriber must be able to read it back");
        }
    }

    #[test]
    fn the_close_reason_is_a_plain_string_on_the_wire() {
        // A subscriber written against the published signature -- and the
        // `dbus-monitor` output the container suite greps -- both depend on
        // this being `s` and not the `u` a bare unit enum would default to.
        assert_eq!(CloseReason::SIGNATURE, "s");
    }

    #[test]
    fn a_docker_port_published_on_loopback_carries_that_address_on_the_wire() {
        let p = crate::docker::Published {
            host_addr: Some("127.0.0.1".parse().unwrap()),
            host_port: 5432,
            protocol: Protocol::Tcp,
            container_addr: "172.17.0.3".parse().unwrap(),
            container_port: 80,
        };
        let wire = WireDockerPort::from_published(&p);
        assert_eq!(wire.host_addr, "127.0.0.1");
    }
}
