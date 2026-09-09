//! What crosses the bus.
//!
//! The wire types are deliberately not the domain types. [`ManagedRule`]
//! carries a [`RuleHandle`] — the exact specification needed to remove a rule
//! from the firewall — and a client that held one could ask the helper to
//! remove rules it never created. It stays on the privileged side, exactly as
//! it stays out of `--json`.
//!
//! D-Bus has no optional types, so `expires_at == 0` means "until reboot".
//! Epoch 0 is 1970 and can never be a real expiry. An empty `container_addr`
//! is the same device for the other absent thing: a rule that redirects
//! rather than merely permits.

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

/// What this build speaks, and the one thing on the wire that says which of
/// two porthole binaries is the older half.
///
/// **Raise it whenever [`SIGNATURE`] changes.** The two constants are
/// hand-written and nothing but a test can hold them together: see
/// [`SIGNATURE`] for the two guards that fail when a member's signature
/// moves and this number does not.
///
/// Every component ships in one package, so two porthole binaries speaking
/// different versions is always an upgrade that left one of them behind --
/// there is no supported configuration in which they differ. What the
/// number buys is not compatibility, which nothing here attempts, but the
/// answer to *which one to restart*: a `zbus::Error::Variant` names two
/// signatures and does not order them (see [`is_undecodable`]), so before
/// this existed a component that met one could only name both remedies and
/// stop.
///
/// **0 is not a value any helper reports.** It is what [`read_protocol_version`]
/// reads an absent member as -- every helper built before this constant
/// existed, which is every helper deployed today. See that function.
pub const PROTOCOL_VERSION: u32 = 1;

/// What an absent version member is read as: a helper from before
/// [`PROTOCOL_VERSION`] existed.
///
/// Lower than any version a helper can report, so [`alignment`] answers
/// [`Alignment::HelperIsOlder`] for it without a case of its own.
pub const PROTOCOL_VERSION_ABSENT: u32 = 0;

/// Every method and every signal of [`INTERFACE`], normalised: one line
/// each, sorted, with argument names and documentation stripped.
///
/// **This is the guard on [`PROTOCOL_VERSION`], which is a hand-kept
/// number and would otherwise be exactly the kind this project already has
/// an open item about** -- a number somebody has to remember to raise is a
/// number that eventually is not raised, and then the check says "we are
/// level" while the signatures have diverged. That is worse than no check
/// at all: a silence with a green tick on it.
///
/// Two tests hold it. `the_wire_types_are_the_ones_this_digest_names` needs
/// no bus: it rebuilds the lines that carry a wire type from that type's
/// own `Type::SIGNATURE`, so adding a field to [`WireRule`] -- the exact
/// change that produced the defect this whole contract exists for -- fails
/// in `cargo test` with nothing running. `the_served_interface_is_the_one
/// _this_digest_names`, in `porthole-helper/tests/interface_contract.rs`,
/// introspects the real object on a private bus and compares
/// [`signature_digest`] of what it serves against this constant, which
/// catches what the types cannot: an argument list, a member added or
/// removed, a member renamed, and the interface itself being renamed --
/// every line names it.
///
/// **Not the introspection XML itself**, which was the obvious thing to
/// pin and is the wrong one. Measured
/// (`.superpowers/sdd/2026-09-07-docker-forward/spike-protocol-version.md`):
/// it is deterministic to the byte across processes, rebuilds, profiles and
/// libcs -- and it embeds every rustdoc comment and every Rust parameter
/// name, so four words added to a doc comment change it and renaming
/// `_seconds` to `_secs` changes it. A contract that breaks when prose
/// improves, in a project that spends half its time improving prose, is a
/// test that gets re-blessed unread. (It is also not well-formed XML today:
/// five of those doc comments contain `--`.)
pub const SIGNATURE: &str = "\
method com.jacopobriccola.Porthole1.Close(qs) -> ((sqssssttusqq))
method com.jacopobriccola.Porthole1.CloseAll() -> (a(sqssssttusqq)a(ssi))
method com.jacopobriccola.Porthole1.CloseById(sbb) -> ((sqssssttusqq))
method com.jacopobriccola.Porthole1.DockerPorts() -> (a(sqssq))
method com.jacopobriccola.Porthole1.Forward(qssuq) -> ((sqssssttusqq))
method com.jacopobriccola.Porthole1.List() -> (a(sqssssttusqq))
method com.jacopobriccola.Porthole1.Open(qssu) -> ((sqssssttusqq))
method com.jacopobriccola.Porthole1.ProtocolVersion() -> (u)
method com.jacopobriccola.Porthole1.Status() -> ((sbbbssssssa(sqssssttusqq)))
signal com.jacopobriccola.Porthole1.NetworkChanged(ss)
signal com.jacopobriccola.Porthole1.RuleClosed((sqssssttusqq)s)
signal com.jacopobriccola.Porthole1.RuleOpened((sqssssttusqq))
";

/// Which of the two binaries is the older half, as a client that has just
/// read the helper's [`PROTOCOL_VERSION`] sees it.
///
/// The distinction is the whole point of the number: the remedy for one is
/// something a session process can do by itself, and the remedy for the
/// other needs a person with privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    /// The two speak the same contract.
    Same,
    /// The helper is the older half. The remedy is `systemctl restart
    /// porthole-helper.service`, which needs privilege and therefore a
    /// person. Includes the helper that reports no version at all -- see
    /// [`PROTOCOL_VERSION_ABSENT`].
    HelperIsOlder,
    /// **This** binary is the older half: the helper speaks a later
    /// contract than this build was compiled against. The remedy is to
    /// replace this process, which `porthole-agent` can do by itself
    /// because its binary on disk is already the new one.
    ThisOneIsOlder,
}

/// Which half is behind, given what the helper just answered.
pub fn alignment(helper_version: u32) -> Alignment {
    match helper_version.cmp(&PROTOCOL_VERSION) {
        std::cmp::Ordering::Equal => Alignment::Same,
        std::cmp::Ordering::Less => Alignment::HelperIsOlder,
        std::cmp::Ordering::Greater => Alignment::ThisOneIsOlder,
    }
}

/// Read the helper's [`PROTOCOL_VERSION`] over `conn`, freshly.
///
/// **A method call, and a proxy built for this one read.** Measured: a
/// long-lived proxy's *cached property* answers with the version of the
/// helper that has just died, at exactly the moment a re-check is called
/// for -- `cached=2` while `uncached=3` across a helper restart, because
/// zbus fills the cache with `GetAll` when the proxy is built and
/// invalidates it on `PropertiesChanged`, which a brand-new helper process
/// never sends. A version check that reads the old value precisely when the
/// new one matters is worse than no check. A method cannot be cached, and a
/// proxy that lives for one call cannot hold a stale anything.
///
/// **An absent member is an answer, not a failure.** A helper built before
/// this contract has no such member and says so:
/// `org.freedesktop.DBus.Error.UnknownMethod`, or `...UnknownProperty` for
/// a caller that asks for it as a property -- verified read-only against
/// the live helper on the author's own machine. That is read as
/// [`PROTOCOL_VERSION_ABSENT`], because a helper without the member is by
/// construction older than a build that expects one: the member is only
/// ever added, and [`SIGNATURE`]'s guards are what make removing it break
/// the suite.
///
/// Everything else stays an error. A helper that is simply **absent**
/// answers `ServiceUnknown`, and reading that as a version would turn
/// "porthole is not installed" into "porthole is out of date".
pub async fn read_protocol_version(conn: &zbus::Connection) -> zbus::Result<u32> {
    let proxy = PortholeProxy::new(conn).await?;
    match proxy.protocol_version().await {
        Ok(version) => Ok(version),
        Err(e) if names_an_absent_member(&e) => Ok(PROTOCOL_VERSION_ABSENT),
        Err(e) => Err(e),
    }
}

/// Whether this error is the bus's own way of saying the member does not
/// exist -- see [`read_protocol_version`], which is the only caller and
/// where the reasoning lives.
fn names_an_absent_member(e: &zbus::Error) -> bool {
    matches!(
        e,
        zbus::Error::MethodError(name, ..)
            if name.as_str() == "org.freedesktop.DBus.Error.UnknownMethod"
                || name.as_str() == "org.freedesktop.DBus.Error.UnknownProperty"
    )
}

/// [`SIGNATURE`]'s own normal form, computed from an interface's
/// introspection XML.
///
/// One line per method and per signal, sorted, naming the interface, the
/// member, the argument signature and -- for a method -- the reply body's.
/// Argument *names* and documentation are deliberately absent: they are
/// what makes the raw XML churn on prose edits (see [`SIGNATURE`]), and
/// nothing on the wire depends on them.
///
/// Comments are removed before anything is parsed, which is also what makes
/// this work at all on porthole's own XML: rustdoc prose containing `--`
/// lands inside an XML comment, `xmllint` refuses the document with five
/// "double hyphen within comment" errors, and a guard that parsed it
/// properly would have failed before this feature started.
///
/// `Err` when the document has no such interface, rather than an empty
/// digest: a guard that compares nothing against nothing passes.
pub fn signature_digest(xml: &str, interface: &str) -> Result<String, String> {
    let without_comments = strip_comments(xml);
    let block = interface_block(&without_comments, interface).ok_or_else(|| {
        format!("the introspection XML declares no interface named `{interface}`")
    })?;

    let mut lines: Vec<String> = Vec::new();
    let mut member: Option<(&str, String)> = None;
    let mut ins = String::new();
    let mut outs = String::new();
    for tag in tags(block) {
        match tag.name {
            "method" | "signal" => {
                let name = attribute(tag.attributes, "name")
                    .ok_or_else(|| format!("a <{}> with no name attribute", tag.name))?;
                member = Some((tag.name, name.to_string()));
                ins.clear();
                outs.clear();
                // zbus never emits one, but a member with no arguments at
                // all is `<method name="Ping"/>` in the specification's own
                // grammar, and it must not swallow the next member's args.
                if tag.self_closing {
                    lines.push(rendered(tag.name, interface, name, "", ""));
                    member = None;
                }
            }
            "arg" => {
                let (kind, _) = member
                    .as_ref()
                    .ok_or_else(|| "an <arg> outside any member".to_string())?;
                let signature = attribute(tag.attributes, "type")
                    .ok_or_else(|| "an <arg> with no type attribute".to_string())?;
                // The specification's own default is `in`; zbus spells it
                // out for methods and omits it for signals, whose arguments
                // are the whole body.
                let direction = attribute(tag.attributes, "direction").unwrap_or("in");
                if *kind == "signal" || direction == "in" {
                    ins.push_str(signature);
                } else {
                    outs.push_str(signature);
                }
            }
            "/method" | "/signal" => {
                let (kind, name) = member
                    .take()
                    .ok_or_else(|| format!("a <{}> closing nothing", tag.name))?;
                lines.push(rendered(kind, interface, &name, &ins, &outs));
            }
            _ => {}
        }
    }
    if lines.is_empty() {
        return Err(format!(
            "interface `{interface}` declares no members at all"
        ));
    }
    lines.sort();
    Ok(lines.join("\n") + "\n")
}

/// One line of [`SIGNATURE`]. A method's reply body is a struct of its out
/// arguments, which is why it is wrapped even when there is one of them.
fn rendered(kind: &str, interface: &str, name: &str, ins: &str, outs: &str) -> String {
    match kind {
        "signal" => format!("signal {interface}.{name}({ins})"),
        _ => format!("method {interface}.{name}({ins}) -> ({outs})"),
    }
}

/// Everything outside `<!-- ... -->`.
fn strip_comments(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        match rest[start..].find("-->") {
            Some(end) => rest = &rest[start + end + 3..],
            // An unterminated comment: everything after it is comment.
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// The text between `<interface name="...">` and its `</interface>`.
fn interface_block<'a>(xml: &'a str, interface: &str) -> Option<&'a str> {
    let opening = format!("<interface name=\"{interface}\">");
    let start = xml.find(&opening)? + opening.len();
    let end = xml[start..].find("</interface>")? + start;
    Some(&xml[start..end])
}

/// One `<tag attr="value" ...>` as this parser needs it.
struct Tag<'a> {
    /// The element name, with a leading `/` for a closing tag.
    name: &'a str,
    attributes: &'a str,
    self_closing: bool,
}

/// Every tag in `s`, in order. Not an XML parser: it reads `<`...`>` runs
/// and nothing else, which is all a digest of members and types needs and
/// which is why the document not being well-formed does not matter here.
fn tags(s: &str) -> impl Iterator<Item = Tag<'_>> {
    let mut rest = s;
    std::iter::from_fn(move || loop {
        let start = rest.find('<')?;
        let end = rest[start..].find('>')? + start;
        let inner = &rest[start + 1..end];
        rest = &rest[end + 1..];
        if inner.starts_with('?') || inner.starts_with('!') {
            continue;
        }
        let self_closing = inner.ends_with('/');
        let inner = inner.trim_end_matches('/');
        let (name, attributes) = match inner.find(char::is_whitespace) {
            Some(i) => (&inner[..i], &inner[i..]),
            None => (inner, ""),
        };
        return Some(Tag {
            name,
            attributes,
            self_closing,
        });
    })
}

/// The value of `key="..."` in an attribute run.
fn attribute<'a>(attributes: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=\"");
    let start = attributes.find(&needle)? + needle.len();
    let end = attributes[start..].find('"')? + start;
    Some(&attributes[start..end])
}

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
    /// The address a forward redirects to, or **empty for a rule that only
    /// permits**. An address can never be the empty string, so this is the
    /// field that tells the two apart — the ports below cannot, since `0` is
    /// also what a forward to a container port nobody could have published
    /// would carry.
    ///
    /// Without it a forward reaches a subscriber as an open with the same
    /// port and the same target, and gets rendered as one: nothing in the
    /// remaining fields says that what answers on that port is a container
    /// rather than something on this machine. It discloses no more than the
    /// bus already carries — `docker_ports` returns the same addresses to
    /// every caller `list` is open to.
    pub container_addr: String,
    /// The port inside the container. `0` when `container_addr` is empty.
    pub container_port: u16,
    /// The port Docker published on this machine, which is the port the
    /// person named. Not `port`: that is what the local network connects to,
    /// and the whole point of a forward is that the two may differ. `0` when
    /// `container_addr` is empty.
    pub published_port: u16,
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
            container_addr: rule
                .forward
                .as_ref()
                .map(|f| f.container_addr.to_string())
                .unwrap_or_default(),
            container_port: rule.forward.as_ref().map(|f| f.container_port).unwrap_or(0),
            published_port: rule.forward.as_ref().map(|f| f.published_port).unwrap_or(0),
        }
    }

    /// Whether this rule redirects rather than only permits.
    ///
    /// The sentinel is [`WireRule::container_addr`]'s, defined and documented
    /// on the field itself: an address can never be the empty string, and the
    /// two ports cannot say it, since `0` is also what a forward to a
    /// container port nobody could have published would carry.
    ///
    /// **One method, on the type that owns the sentinel.** There were three
    /// copies of this line — `porthole-agent`'s `notify::redirects`,
    /// `porthole-gui`'s `open_now::is_forward`, and an inline
    /// `container_addr.is_empty()` in `porthole-cli`'s `client.rs` — in three
    /// crates, each deriving a rule this module defines. Two copies of a
    /// one-line predicate is how a rule ends up *described* as one act and
    /// *re-sent* as the other, which is a bug this branch has already fixed
    /// once, in the agent's `Reopen`. Three copies is the same bug waiting.
    /// Every crate that needs the answer already depends on this one.
    pub fn redirects(&self) -> bool {
        !self.container_addr.is_empty()
    }
}

/// Why a rule stopped being open, as it crosses the bus in `RuleClosed`.
///
/// A single undifferentiated "closed" would force every subscriber to guess:
/// a rule that ran out its own clock, one a person asked to close, one the
/// helper closed because the machine left the network it was scoped to, one
/// that was already gone from the firewall by the time porthole looked, and
/// one whose container is no longer the one it was created against are five
/// different things to tell a user about. The slug is spelled twice:
/// the wire form comes from serde's `rename_all` below, the journal form from
/// the `match` in [`CloseReason::as_str`]. Nothing in the type system makes
/// those agree — `every_close_carries_why` checks both halves for every
/// variant, which is the only reason they cannot drift.
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
    /// A forward whose container is no longer the one it was created
    /// against: the mapping the rule stored is absent from Docker's own
    /// table now -- see `porthole_core::forward::stale_forwards`.
    ///
    /// The forward closes rather than being re-aimed. Docker assigns
    /// container addresses at start, so the address a restarted container
    /// gives up can be taken by a different one; a rule re-aimed at whatever
    /// now holds that address would carry traffic from the local network to
    /// a service nobody authorised. This is the same principle as a rule
    /// scoped to a subnet the machine has left.
    ///
    /// Never sent because Docker could not be read. Not knowing is not
    /// knowing it changed -- see
    /// `porthole_core::engine::Engine::close_stale_forwards`.
    TargetGone,
}

impl CloseReason {
    /// The slug the journal line is built from. It is not what serde puts on
    /// the wire -- `rename_all` above derives that from the variant name
    /// independently -- so the two are held equal by `every_close_carries_why`
    /// rather than by construction. Kept next to the enum all the same, so
    /// that every spelling is in one place rather than at each call site.
    pub fn as_str(self) -> &'static str {
        match self {
            CloseReason::Expired => "expired",
            CloseReason::Requested => "requested",
            CloseReason::NetworkChanged => "network-changed",
            CloseReason::Reconciled => "reconciled",
            CloseReason::TargetGone => "target-gone",
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

/// Whether this error is porthole failing to **read** what the helper sent,
/// rather than anything the helper decided or any way it could not be
/// reached.
///
/// The case it exists for is measured, in
/// `.superpowers/sdd/2026-09-07-docker-forward/spike-protocol-version.md`:
/// the forward feature added three members to [`WireRule`], so `RuleClosed`'s
/// body went from `((sqssssttu)s)` to `((sqssssttusqq)s)` and `list`'s return
/// from `a(sqssssttu)` to `a(sqssssttusqq)`. A client built against one and
/// talking to a helper built against the other gets
/// `zbus::Error::Variant(SignatureMismatch)` — from a method's return, and
/// from a signal's own `args()`. zbus delivers the signal either way and the
/// stream survives it; only the decode refuses.
///
/// **Every `Variant` error, not only `SignatureMismatch`**, and that is
/// deliberate: a value this build has no name for fails the same way with a
/// serde error instead (a `CloseReason` a newer helper added, say — the
/// signature would still be `s`), and it is the same fact about the same two
/// binaries. What this cannot tell apart is the *direction*: zvariant reports
/// a value porthole failed to **encode** the same way. So this is only asked
/// about an error that came back from a call or from `args()`, where nothing
/// porthole sent is what failed.
///
/// It says nothing about which of the two is older. Nothing on the wire does
/// today; that is what a protocol version would be for, and it is not this.
pub fn is_undecodable(e: &zbus::Error) -> bool {
    matches!(e, zbus::Error::Variant(_))
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

    /// Redirect `port` to the container that publishes `published_port` on
    /// this machine, for `seconds` (0 for until-reboot). `scope` is what the
    /// user typed and the helper parses, exactly as in `open` — named the
    /// same thing here because it is the same thing.
    ///
    /// Authorized every time. `open` towards the local subnet can reuse an
    /// authentication given minutes earlier; this never does, and the action
    /// it asks for does not depend on `scope`.
    ///
    /// Refusals all come from the helper, in the fixed order
    /// [`crate::error::FORWARD_REFUSALS`] lists them in — plus the one a
    /// forward shares with `open`, a firewall that is installed but not
    /// enforcing rules. Enumerated there rather than here: this doc comment
    /// was one of two copies that had gone a refusal out of date while
    /// promising "a fixed order" for a list with a hole in the middle of it.
    async fn forward(
        &self,
        port: u16,
        protocol: &str,
        scope: &str,
        seconds: u32,
        published_port: u16,
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

    /// The contract the helper speaks: [`PROTOCOL_VERSION`], as the helper
    /// was compiled with it.
    ///
    /// A method rather than a property, and the difference is measured
    /// rather than stylistic -- see [`read_protocol_version`], which is what
    /// every component here calls instead of this, and which is where the
    /// cached-property trap and the absent-member answer are both handled.
    ///
    /// `(u)` and nothing else: it must stay readable by a client that
    /// disagrees with the helper about every other type on this interface,
    /// which is the one situation it exists for.
    async fn protocol_version(&self) -> zbus::Result<u32>;

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
    ///   touching any firewall — so none of the reasons is true of it and
    ///   none is sent. A client that only listens goes on showing that
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
            forward: None,
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
    fn a_forward_reaches_a_subscriber_as_something_it_can_tell_from_an_open() {
        // Same port, same protocol, same target, same everything an `open`
        // has: a client with only those fields renders a redirect to a
        // container as a permission granted to whatever is on this machine.
        // The three fields below are what it takes to say otherwise, and to
        // say where the traffic actually goes.
        let mut r = rule(None);
        r.forward = Some(crate::forward::ForwardTo {
            container_addr: "172.18.0.2".parse().unwrap(),
            container_port: 80,
            published_port: 3000,
            protocol: Protocol::Tcp,
        });
        let wire = WireRule::from_rule(&r);
        assert_eq!(wire.container_addr, "172.18.0.2");
        assert_eq!(wire.container_port, 80);
        assert_eq!(
            wire.published_port, 3000,
            "the published port is the one the person named, and is not `port`"
        );
        assert_eq!(wire.port, 5173, "`port` stays what the network connects to");
        assert!(
            wire.redirects(),
            "the one predicate three crates ask, on the type that defines the \
             sentinel it reads"
        );
    }

    #[test]
    fn an_ordinary_open_carries_the_empty_address_that_means_not_a_forward() {
        // D-Bus has no optional types. The address is the sentinel rather
        // than either port, because `0` is a value a port field can hold for
        // other reasons and the empty string is not an address.
        let wire = WireRule::from_rule(&rule(None));
        assert_eq!(wire.container_addr, "");
        assert_eq!(wire.container_port, 0);
        assert_eq!(wire.published_port, 0);
        assert!(
            !wire.redirects(),
            "and the other direction: a rule that only permits says so"
        );
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
        // "expired", "requested", "network-changed", "reconciled",
        // "target-gone". The notification says something different for each,
        // and a single undifferentiated ClosedSignal would force the agent to
        // guess.
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
            (CloseReason::TargetGone, "target-gone"),
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
    fn the_reasons_that_predate_forwarding_keep_their_slugs() {
        // These four crossed the bus before `target-gone` existed, and
        // subscribers match on the slug: a rename would be a silent break for
        // anything already deployed, not a compile error anywhere. The test
        // above covers every reason including the new one; this one exists to
        // say that these particular strings are not free to move.
        //
        // Spelled as literals rather than derived from the enum, which is
        // the point -- a test that asked `as_str` what the slug is would
        // agree with any rename.
        assert_eq!(CloseReason::Expired.as_str(), "expired");
        assert_eq!(CloseReason::Requested.as_str(), "requested");
        assert_eq!(CloseReason::NetworkChanged.as_str(), "network-changed");
        assert_eq!(CloseReason::Reconciled.as_str(), "reconciled");
    }

    #[test]
    fn a_new_reason_has_to_be_written_into_the_slug_test_by_hand() {
        // Not a behavioural check: an exhaustive match that stops compiling
        // when a variant is added, so the next reason cannot reach the bus
        // with nobody having decided what it is called. It is deliberately
        // not `as_str` -- reading the answer out of the code under test
        // would agree with whatever that code says.
        fn slug(reason: CloseReason) -> &'static str {
            match reason {
                CloseReason::Expired => "expired",
                CloseReason::Requested => "requested",
                CloseReason::NetworkChanged => "network-changed",
                CloseReason::Reconciled => "reconciled",
                CloseReason::TargetGone => "target-gone",
            }
        }
        assert_eq!(
            slug(CloseReason::TargetGone),
            CloseReason::TargetGone.as_str()
        );
    }

    #[test]
    fn the_close_reason_is_a_plain_string_on_the_wire() {
        // A subscriber written against the published signature -- and the
        // `dbus-monitor` output the container suite greps -- both depend on
        // this being `s` and not the `u` a bare unit enum would default to.
        assert_eq!(CloseReason::SIGNATURE, "s");
    }

    /// [`WireRule`] as it was before the forward feature added
    /// `container_addr`, `container_port` and `published_port` — the exact
    /// shape a component from before that upgrade still reads with. Written
    /// out rather than derived from `WireRule`, because deriving it from the
    /// type under test would change with it and stop being the old shape.
    #[derive(Debug, Clone, Serialize, Deserialize, Type)]
    struct RuleBeforeForward {
        id: String,
        port: u16,
        protocol: String,
        target: String,
        scope: String,
        backend: String,
        opened_at: u64,
        expires_at: u64,
        uid: u32,
    }

    /// One real `RuleClosed` body, encoded from `T` and read back as `U` —
    /// the error zbus itself produces, not one built by hand here.
    fn read_back<T, U>(sent: &T) -> zbus::Result<U>
    where
        T: serde::Serialize + Type,
        U: serde::de::DeserializeOwned + Type,
    {
        zbus::message::Message::signal(PATH, INTERFACE, "RuleClosed")
            .expect("a well-formed signal header")
            .build(sent)
            .expect("a body")
            .body()
            .deserialize::<U>()
    }

    #[test]
    fn a_rule_from_before_the_forward_feature_cannot_be_read_and_says_so() {
        // The defect this predicate exists for, reproduced end to end
        // through zbus's own encoder and decoder: the two signatures really
        // do not match, the error really is `Variant`, and a component that
        // asks `is_undecodable` about it really does get `true`.
        let old = RuleBeforeForward {
            id: "abc".to_string(),
            port: 5173,
            protocol: "tcp".to_string(),
            target: "10.10.10.0/24".to_string(),
            scope: "network".to_string(),
            backend: "firewalld".to_string(),
            opened_at: 1_757_000_000,
            expires_at: 1_757_003_600,
            uid: 1000,
        };
        let sent = (old.clone(), CloseReason::Expired);
        let e = read_back::<_, (WireRule, CloseReason)>(&sent)
            .expect_err("the two bodies have different signatures");
        assert!(
            is_undecodable(&e),
            "a body porthole cannot decode must be readable as exactly that: {e}"
        );
        assert!(
            e.to_string().contains("ignature"),
            "and zbus's own text is what says which signatures disagreed: {e}"
        );

        // The other direction is the same fact: a helper from before the
        // upgrade, a client from after it.
        let e = read_back::<_, (RuleBeforeForward, CloseReason)>(&(
            WireRule::from_rule(&rule(Some(1_757_003_600))),
            CloseReason::Expired,
        ))
        .expect_err("still two different signatures");
        assert!(is_undecodable(&e), "{e}");

        // And the negative control the whole predicate rests on: a body of
        // the *matching* shape decodes, so "could not decode" is a real
        // failure and not something this test would report about anything.
        let sent = (
            WireRule::from_rule(&rule(Some(1_757_003_600))),
            CloseReason::Expired,
        );
        let (back, reason) =
            read_back::<_, (WireRule, CloseReason)>(&sent).expect("the matching shape reads back");
        assert_eq!(back.port, 5173);
        assert_eq!(reason, CloseReason::Expired);
    }

    #[test]
    fn a_helper_that_answered_and_a_helper_that_was_not_there_are_not_decode_failures() {
        // The distinction the agent's own start-up turns on: an absent
        // helper is ordinary and recoverable, and must not be mistaken for
        // the one failure that means the two binaries cannot speak.
        let answered = zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from("com.jacopobriccola.Porthole.NotAuthorized")
                .unwrap(),
            Some("not authorized: com.jacopobriccola.Porthole.List".to_string()),
            zbus::message::Message::method_call("/", "Noop")
                .unwrap()
                .build(&())
                .unwrap(),
        );
        assert!(!is_undecodable(&answered));
        assert!(!is_undecodable(&zbus::Error::Failure(
            "the connection was lost".to_string()
        )));
        assert!(!is_undecodable(&zbus::Error::InvalidReply));
    }

    /// One D-Bus **message body**, from the Rust tuple zvariant encodes it
    /// from: the arguments concatenated, with no outer parentheses.
    ///
    /// zvariant renders a Rust tuple as a struct, so
    /// `(WireRule, CloseReason)` signs as `((sqssssttusqq)s)` while the
    /// signal's body on the wire -- what `dbus-monitor` prints and what an
    /// introspection `<arg>` list adds up to -- is `(sqssssttusqq)s`.
    fn body(tuple: impl std::fmt::Display) -> String {
        let rendered = tuple.to_string();
        rendered
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .expect("a tuple's signature is parenthesised")
            .to_string()
    }

    fn method_error(name: &str, detail: &str) -> zbus::Error {
        zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(name.to_string()).unwrap(),
            Some(detail.to_string()),
            zbus::message::Message::method_call("/", "Noop")
                .unwrap()
                .build(&())
                .unwrap(),
        )
    }

    /// The guard on the hand-kept number, in the half that needs no bus.
    ///
    /// Every line of [`SIGNATURE`] that carries a wire type is rebuilt here
    /// from that type's own `Type::SIGNATURE` -- the very strings zvariant
    /// puts on the wire -- so the change that produced this whole contract
    /// (three members added to [`WireRule`], `a(sqssssttu)` becoming
    /// `a(sqssssttusqq)`) fails here, in `cargo test`, with nothing running.
    ///
    /// What it cannot see is an argument list, a renamed member or a member
    /// added or removed: nothing in Rust's type system carries "Open takes
    /// `qssu`". That is the live guard's half --
    /// `porthole-helper/tests/interface_contract.rs`.
    #[test]
    fn the_wire_types_are_the_ones_this_digest_names() {
        let rule = WireRule::SIGNATURE;
        let expected = [
            // `rule` already renders parenthesised -- zvariant signs a
            // struct that way -- and the reply body is a struct of the one
            // out argument, which is what the second pair would have been.
            format!("method {INTERFACE}.Open(qssu) -> ({rule})"),
            format!("method {INTERFACE}.Forward(qssuq) -> ({rule})"),
            format!("method {INTERFACE}.Close(qs) -> ({rule})"),
            format!("method {INTERFACE}.CloseById(sbb) -> ({rule})"),
            format!(
                "method {INTERFACE}.CloseAll() -> ({}{})",
                <Vec<WireRule>>::SIGNATURE,
                <Vec<WireError>>::SIGNATURE
            ),
            format!(
                "method {INTERFACE}.List() -> ({})",
                <Vec<WireRule>>::SIGNATURE
            ),
            format!("method {INTERFACE}.Status() -> ({})", WireStatus::SIGNATURE),
            format!(
                "method {INTERFACE}.DockerPorts() -> ({})",
                <Vec<WireDockerPort>>::SIGNATURE
            ),
            format!(
                "method {INTERFACE}.ProtocolVersion() -> ({})",
                u32::SIGNATURE
            ),
            format!("signal {INTERFACE}.RuleOpened({rule})"),
            format!(
                "signal {INTERFACE}.RuleClosed({})",
                body(<(WireRule, CloseReason)>::SIGNATURE)
            ),
            format!(
                "signal {INTERFACE}.NetworkChanged({})",
                body(<(&str, &str)>::SIGNATURE)
            ),
        ];
        for line in &expected {
            assert!(
                SIGNATURE.lines().any(|declared| declared == line),
                "`SIGNATURE` has no line\n  {line}\nwhich is what the types this build \
                 encodes actually produce. If you changed a wire type on purpose, write \
                 the new line into `SIGNATURE` **and raise `PROTOCOL_VERSION`** -- a \
                 changed contract with the same version number is the one failure this \
                 pair of constants exists to prevent.\n`SIGNATURE` is:\n{SIGNATURE}"
            );
        }
        // The other direction: a line here that no type produces is a line
        // left behind, and a digest with a stale line in it would go on
        // matching a live interface that no longer serves it -- so this
        // count is what says the two lists are the same list.
        assert_eq!(
            SIGNATURE.lines().count(),
            expected.len(),
            "`SIGNATURE` names {} members and this check accounts for {}. Every member \
             belongs in both, or the digest and the interface can drift in the direction \
             neither guard looks.",
            SIGNATURE.lines().count(),
            expected.len()
        );
    }

    #[test]
    fn the_digest_is_read_out_of_an_interfaces_own_introspection() {
        // The parser the live guard runs on, driven by the XML zbus really
        // emits -- comments with `--` inside them (which is why this is not
        // an XML parser at all), argument names, and a signal whose args
        // carry no direction.
        let xml = "\
<node>
  <interface name=\"com.example.Other\">
    <method name=\"Ignored\"><arg type=\"s\" direction=\"in\"/></method>
  </interface>
  <interface name=\"com.jacopobriccola.Porthole1\">
    <!-- a doc comment with a `--` in it, which is not well-formed XML -->
    <method name=\"Open\">
      <arg name=\"port\" type=\"q\" direction=\"in\"/>
      <arg name=\"scope\" type=\"s\" direction=\"in\"/>
      <arg type=\"(sq)\" direction=\"out\"/>
    </method>
    <method name=\"List\">
      <arg type=\"a(sq)\" direction=\"out\"/>
    </method>
    <signal name=\"RuleClosed\">
      <arg name=\"rule\" type=\"(sq)\"/>
      <arg name=\"reason\" type=\"s\"/>
    </signal>
  </interface>
</node>";
        assert_eq!(
            signature_digest(xml, INTERFACE).expect("the interface is in there"),
            "method com.jacopobriccola.Porthole1.List() -> (a(sq))\n\
             method com.jacopobriccola.Porthole1.Open(qs) -> ((sq))\n\
             signal com.jacopobriccola.Porthole1.RuleClosed((sq)s)\n"
        );

        // An interface that is not there is an error and never an empty
        // digest: a guard comparing nothing to nothing is one of the ways a
        // check reports success while executing nothing.
        let missing = signature_digest(xml, "com.jacopobriccola.Porthole2")
            .expect_err("nothing serves Porthole2");
        assert!(missing.contains("Porthole2"), "{missing}");
    }

    #[test]
    fn an_absent_version_member_is_a_helper_from_before_this_contract() {
        // Measured, read-only, against the live helper on the author's own
        // machine: `busctl --system get-property ... ProtocolVersion` ->
        // `Unknown property 'ProtocolVersion'`. That answer is information,
        // and reading it as a failure would leave every helper in the field
        // indistinguishable from a broken one.
        assert!(names_an_absent_member(&method_error(
            "org.freedesktop.DBus.Error.UnknownMethod",
            "Unknown method 'ProtocolVersion'"
        )));
        assert!(names_an_absent_member(&method_error(
            "org.freedesktop.DBus.Error.UnknownProperty",
            "Unknown property 'ProtocolVersion'"
        )));

        // And the boundary that matters most: a helper that is not there at
        // all is not an old helper. Reading `ServiceUnknown` as version 0
        // would turn "porthole is not installed" into "porthole is out of
        // date", and every component here acts differently on the two.
        assert!(!names_an_absent_member(&method_error(
            "org.freedesktop.DBus.Error.ServiceUnknown",
            "The name is not activatable"
        )));
        assert!(!names_an_absent_member(&method_error(
            "com.jacopobriccola.Porthole.NotAuthorized",
            "not authorized"
        )));
        assert!(!names_an_absent_member(&zbus::Error::InvalidReply));
    }

    #[test]
    fn the_version_says_which_half_is_old_and_never_merely_that_they_differ() {
        // The whole reason the number exists: one of the two remedies needs
        // a person with privilege and the other does not, and a component
        // that only knew "these disagree" had to offer both.
        assert_eq!(alignment(PROTOCOL_VERSION), Alignment::Same);
        assert_eq!(
            alignment(PROTOCOL_VERSION_ABSENT),
            Alignment::HelperIsOlder,
            "a helper with no version member is older than one that has it: the member \
             is only ever added, and `SIGNATURE`'s guards are what keep it from being \
             removed"
        );
        assert_eq!(
            alignment(PROTOCOL_VERSION + 1),
            Alignment::ThisOneIsOlder,
            "a helper ahead of this build makes *this* the half to replace"
        );
        // 0 must stay below every version a helper can report, or an absent
        // member would read as a helper from the future -- and the agent's
        // answer to that is to replace *itself*, which would be the wrong
        // half every time. A compile-time assertion rather than a runtime
        // one, since both sides are constants: this way the impossible
        // arrangement does not build.
        const _: () = assert!(PROTOCOL_VERSION > PROTOCOL_VERSION_ABSENT);
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
