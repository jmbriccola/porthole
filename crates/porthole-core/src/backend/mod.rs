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
use crate::forward::ForwardTo;
use crate::model::{OpenRequest, Protocol};
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
    ///
    /// `false` means one of two different things, and `active` alone cannot
    /// tell a caller which: either porthole read the ruleset and confirmed
    /// nothing is enforcing, or it could not read the ruleset at all (see
    /// [`BackendHealth::active_unknown`]). Collapsing those two into one bit
    /// is exactly what let a permission-denied read on ufw or nftables come
    /// out the other end as "porthole confirmed this port is already
    /// reachable" — false in the dangerous direction. A caller that needs to
    /// tell them apart must check `active_unknown` too, not read `!active`
    /// as a confirmed absence on its own.
    pub active: bool,
    /// `true` when `active` is `false` only because porthole could not
    /// confirm activity, never because it confirmed an absence of it.
    ///
    /// The most common cause is a read refused for want of privilege: `ufw
    /// status` and `nft -j list chains` need root to read at all, firewalld
    /// refuses an unprivileged `firewall-cmd --state` on some machines (exit
    /// 253, its own NOT_AUTHORIZED), and `porthole status`/`doctor` run
    /// without root. But it is not the *only* one: an `nft -j
    /// list chains` that returns something porthole cannot parse sets it
    /// too, since an installed `nft` porthole cannot make sense of is still
    /// installed, not absent, and porthole did not confirm anything either
    /// way. Read this as "could not confirm," not as a synonym for
    /// "permission denied" specifically -- a caller that needs to say *why*
    /// reads `detail`, which always names the actual reason.
    ///
    /// Always `false` when `active` is `true`: there is nothing left unknown
    /// once enforcement has actually been confirmed. `porthole doctor` reads
    /// this to choose between "here is how to enable it" (genuinely
    /// inactive) and "porthole cannot tell, one way or the other" (unknown)
    /// -- the two need different remedies, and conflating them risks the
    /// same "feeling safe when you are not" failure reconciliation's own
    /// ownership rules exist to prevent, just one layer up in diagnostics
    /// instead of in the firewall itself.
    pub active_unknown: bool,
    pub version: Option<String>,
    /// A sentence fit to show the user.
    pub detail: String,
    /// A standing caveat about this backend's enforcement that is true
    /// regardless of `active`/`available` and worth a user knowing on every
    /// run, not only when something has gone wrong — e.g. nftables' "this
    /// chain's policy is accept and nothing here drops, but a chain it jumps
    /// to might still" warning. `None` when there is nothing beyond `detail`
    /// to add. `porthole status` and `porthole doctor` both surface this, so
    /// it must never depend on `active` to decide whether to exist.
    pub caveat: Option<String>,
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

    /// Redirect `req.port` to `to`.
    ///
    /// `req.port` is the external port — what the local network connects to.
    /// `to` says where that traffic goes: a container's own address and port
    /// on Docker's network, never loopback.
    ///
    /// One rule, and an ordinary handle for it. A permit for `req.port`
    /// alongside it was measured to carry none of the redirected traffic and
    /// to be a working accept for something else — see `firewalld.rs`'s
    /// `forward`.
    ///
    /// The refusal comes from [`FirewallBackend::forward_capability`], so a
    /// backend that cannot redirect says so in one place and a caller cannot
    /// be given two different sentences for one fact.
    fn forward(&self, _req: &OpenRequest, _to: &ForwardTo, _marker: &str) -> Result<RuleHandle> {
        self.forward_capability()?;
        // Only a backend whose capability answer is `Ok` reaches here, and
        // such a backend is expected to have overridden this method.
        Err(Error::Unexpected(format!(
            "{} reports a redirect it does not implement",
            self.id()
        )))
    }

    /// Whether this backend can express a redirect at all: `Ok(())` if it
    /// can, and otherwise the refusal to hand back.
    ///
    /// It runs nothing and reads nothing, which is what lets a caller ask it
    /// before anything else — on a machine whose firewall cannot redirect,
    /// no fact about Docker, the state file or `/proc` changes the answer,
    /// and reporting one of those instead sends a user looking in the wrong
    /// place.
    ///
    /// This says nothing about whether a particular redirect would succeed.
    ///
    /// The default refuses, and says only that. Any backend can inherit it,
    /// including one whose reason for having no forward is not the reason
    /// ufw has none — so the message states the absence and stops there. A
    /// backend with something more specific to tell a user overrides this
    /// and says it itself.
    ///
    /// ufw inherits the default; `ufw.rs`'s module docs carry why. nftables
    /// overrides it with a refusal of its own, for a different reason its
    /// module docs carry.
    fn forward_capability(&self) -> Result<()> {
        Err(Error::ForwardUnsupported(format!(
            "{} cannot redirect a port: porthole has no forward for this backend",
            self.id()
        )))
    }

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
    ///
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

/// The one protocol a forward is written for.
///
/// `OpenRequest` and `ForwardTo` each carry a protocol, and they are built
/// from different sources — the request from what the user asked for, the
/// mapping from what Docker published. A redirect is a single rule whose one
/// protocol governs both the match on `req.port` and the destination `to`
/// names, so a disagreement between the two has no spelling: it can only be
/// resolved by picking one and discarding the other. Refuse instead.
pub(crate) fn forward_protocol(req: &OpenRequest, to: &ForwardTo) -> Result<Protocol> {
    if req.protocol != to.protocol {
        return Err(Error::InvalidArgument(format!(
            "a forward cannot be {} on the outside and {} on the inside",
            req.protocol, to.protocol
        )));
    }
    Ok(req.protocol)
}

/// The exact message [`detect`] fails with when no firewall is installed at
/// all -- `pub` (not `pub(crate)`) so a client that needs this same text for
/// a test fixture can import it rather than retyping it. It reaches every
/// caller through `Error::BackendUnavailable`'s own `Display`, and reaches
/// the wire verbatim as `BackendHealth::detail` and then `WireStatus::detail`
/// (`porthole-helper/src/service.rs`'s `status_for_undetected_backend`,
/// `porthole-core/src/ipc.rs`'s `WireStatus::from_status`) -- which is what
/// `porthole-gui`'s own `StatusBar` shows a user.
///
/// It is a constant because a GUI test once retyped a shortened copy of this
/// text and documented itself as holding the real thing, so nothing ever
/// rendered the sentence a user would actually see. Tests import this; they do
/// not restate it. That is the whole point of the constant, and it is why the
/// sentence above names no test: this comment's own predecessor named a
/// fixture that the commit introducing it had already deleted.
pub const NO_FIREWALL_MESSAGE: &str = "no firewall found: none of firewalld, ufw or nftables is \
     installed. Without a firewall this port is already reachable from your network — \
     porthole cannot change that, and will not pretend it has. Setting up \
     a firewall is outside what porthole does.";

/// Pick a backend: firewalld, then ufw, then nftables.
///
/// All three are chosen on being **available** (installed), never on being
/// **active** -- every check below reads `BackendHealth::available` and none
/// of them reads `active` to decide. What differs is only the *order*:
/// nftables is checked last and only as a fallback, never a contender ahead
/// of the other two. Installing firewalld or ufw is a
/// decision about how this machine's firewall is managed, while `nft` exists
/// on almost every modern Linux and its mere presence says nothing about
/// whether anyone uses it as one.
///
/// A backend that is installed but stopped is still returned. "firewalld is
/// installed but not running" is a more useful thing to tell someone than "no
/// firewall found", and refusing to open anything in that state is the
/// caller's job, not this function's.
pub fn detect<'a>(runner: &'a dyn CommandRunner) -> Result<Box<dyn FirewallBackend + 'a>> {
    let firewalld = firewalld::Firewalld::new(runner);
    if firewalld.health()?.available {
        return Ok(Box::new(firewalld));
    }
    let ufw = ufw::Ufw::new(runner);
    if ufw.health()?.available {
        return Ok(Box::new(ufw));
    }
    let nft = nftables::Nftables::new(runner);
    if nft.health()?.available {
        return Ok(Box::new(nft));
    }
    Err(Error::BackendUnavailable(NO_FIREWALL_MESSAGE.to_string()))
}

#[cfg(test)]
mod tests {
    use super::firewalld;
    use super::firewalld::tests::{FORWARD_REDIRECT, ROUTE_JSON, SUBNET_RULE, ZONE};
    use super::nftables;
    use super::ufw;
    use super::{detect, BackendId, FirewallBackend, Ownership, RuleHandle};
    use crate::command::{Command, CommandRunner, Output, RecordingRunner};
    use crate::error::{Error, ExitCode};
    use crate::forward::ForwardTo;
    use crate::model::{Lifetime, OpenRequest, Target};

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
        // manage IPv6 — `Target` in `model.rs`'s module doc is defined as
        // always an already-resolved IPv4 network, and `net::current_network`
        // in net.rs only ever resolves an IPv4 address), so no `OpenRequest`
        // porthole builds can ever produce an ipv6 rich rule. A rule that only
        // varies the CIDR or port from `rich_rule`'s own template would not
        // prove anything: porthole could have written that one too.
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
                    // Two responses, because `owned_rules` reads twice: it
                    // discovers the single input base chain, then lists that
                    // chain's rules. A bare `RecordingRunner::new()` will not
                    // do -- empty stdout is not valid `nft -j` output, and
                    // unlike ufw's and firewalld's text parsers this one errors
                    // rather than reporting zero rules.
                    //
                    // The fixture deliberately carries one marked rule of the
                    // shape porthole writes and one unmarked rule -- a
                    // realistic ruleset, not an empty one -- so this arm
                    // proves `owned_rules` actually succeeds and returns
                    // `Some` for a `Marked` backend, rather than agreeing
                    // vacuously by erroring or returning an empty list for a
                    // trivial reason. `check()` only compares
                    // `owned_rules().is_none()` against `ownership() ==
                    // Unprovable`; it never inspects the returned Vec, so the
                    // shape filter itself (a `porthole:` comment alone is not
                    // enough) is exercised by the dedicated tests in
                    // `nftables.rs`, not here.
                    const ONE_INPUT_CHAIN: &str = r#"{"nftables":[
                        {"metainfo":{"version":"1.1.3","json_schema_version":1}},
                        {"chain":{"family":"inet","table":"filter","name":"input","handle":1,
                                  "type":"filter","hook":"input","prio":0,"policy":"drop"}}
                    ]}"#;
                    const ITS_RULES: &str = r#"{"nftables":[
                        {"metainfo":{"version":"1.1.3","json_schema_version":1}},
                        {"rule":{"family":"inet","table":"filter","chain":"input","handle":4,
                                 "comment":"porthole:a1",
                                 "expr":[
                                   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5173}},
                                   {"accept":null}
                                 ]}},
                        {"rule":{"family":"inet","table":"filter","chain":"input","handle":5,
                                 "expr":[{"drop":null}]}}
                    ]}"#;
                    check(&nftables::Nftables::new(&RecordingRunner::with_responses(
                        vec![Output::stdout(ONE_INPUT_CHAIN), Output::stdout(ITS_RULES)],
                    )));
                }
            }
        }
    }

    #[test]
    fn of_the_backends_detect_returns_only_firewalld_has_a_forward() {
        // Which of the three backends `detect` can hand back implements a
        // forward, pinned so that a change to the set is a change to this
        // test rather than a surprise at a call site. Two of the three
        // refuse, for different reasons their own module docs carry.
        //
        // The match on BackendId is exhaustive on purpose: adding a variant
        // there breaks the build here. That covers a new backend that also
        // adds an id, which is how all three arrived; it does not cover a
        // second backend reusing an existing id, which is what `fake.rs`
        // does -- FakeBackend reports `BackendId::Firewalld` and inherits
        // the refusing default, and no match on ids can see it.
        fn refuses(backend: &dyn FirewallBackend, runner: &RecordingRunner) {
            let err = backend
                .forward(&forward_req(), &forward_to(), "porthole:abc")
                .expect_err("this backend is expected to have no forward");
            assert_eq!(err.exit_code(), ExitCode::ForwardUnsupported);
            assert!(
                err.to_string().contains(&backend.id().to_string()),
                "the refusal must name the backend: {err}"
            );
            assert!(
                runner.recorded().is_empty(),
                "refusing must not run any command"
            );
        }

        for id in [BackendId::Firewalld, BackendId::Ufw, BackendId::Nftables] {
            match id {
                // The one that implements `forward`, so it never reaches the
                // default. Called with an empty script it fails somewhere in
                // its own implementation -- what matters here is only that
                // the failure is not a refusal.
                BackendId::Firewalld => {
                    let runner = RecordingRunner::new();
                    let err = firewalld::Firewalld::new(&runner)
                        .forward(&forward_req(), &forward_to(), "porthole:abc")
                        .expect_err("an empty script cannot complete a forward");
                    assert_ne!(err.exit_code(), ExitCode::ForwardUnsupported);
                }
                // nftables refuses with a message of its own rather than the
                // default's, so `refuses` is not what checks it -- see
                // `nftables.rs`'s own test, which pins the sentence.
                BackendId::Nftables => {
                    let runner = RecordingRunner::new();
                    let err = nftables::Nftables::new(&runner)
                        .forward(&forward_req(), &forward_to(), "porthole:abc")
                        .expect_err("this backend is expected to have no forward");
                    assert_eq!(err.exit_code(), ExitCode::ForwardUnsupported);
                    assert!(
                        runner.recorded().is_empty(),
                        "refusing must not run any command"
                    );
                }
                BackendId::Ufw => {
                    let runner = RecordingRunner::new();
                    refuses(&ufw::Ufw::new(&runner), &runner);
                }
            }
        }
    }

    #[test]
    fn a_backends_capability_answer_and_its_refusal_are_the_same_sentence() {
        // Two ways to learn one fact: the engine asks the capability before
        // it reads anything, and a caller that goes straight to `forward`
        // gets the refusal. Nothing but this would notice the two drifting
        // into saying different things, and then which one a user saw would
        // depend on which path reached them.
        fn one_sentence(backend: &dyn FirewallBackend, runner: &RecordingRunner) {
            let asked = backend
                .forward_capability()
                .expect_err("this backend is expected to have no forward");
            let attempted = backend
                .forward(&forward_req(), &forward_to(), "porthole:abc")
                .expect_err("and to refuse an attempt at one");
            assert_eq!(asked.to_string(), attempted.to_string());
            assert_eq!(asked.exit_code(), ExitCode::ForwardUnsupported);
            assert_eq!(attempted.exit_code(), ExitCode::ForwardUnsupported);
            assert!(
                runner.recorded().is_empty(),
                "neither way of asking may run a command"
            );
        }

        let runner = RecordingRunner::new();
        one_sentence(&ufw::Ufw::new(&runner), &runner);
        one_sentence(&nftables::Nftables::new(&runner), &runner);

        // The one that can. A refusal here would stop the engine before it
        // ever called the implementation below it.
        assert!(firewalld::Firewalld::new(&runner)
            .forward_capability()
            .is_ok());
    }

    fn forward_req() -> OpenRequest {
        OpenRequest {
            port: 3000,
            protocol: crate::model::Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            lifetime: Lifetime::For(std::time::Duration::from_secs(300)),
        }
    }

    fn forward_to() -> ForwardTo {
        ForwardTo {
            container_addr: std::net::Ipv4Addr::new(172, 18, 0, 2),
            container_port: 8080,
            published_port: 3000,
            protocol: crate::model::Protocol::Tcp,
        }
    }

    #[test]
    fn a_forward_handle_survives_the_state_file_round_trip() {
        // `RuleHandle` is serialised into /run/porthole/state.json, and a
        // handle that cannot be read back is a rule nothing can ever remove.
        // A forward's handle is an ordinary one -- the firewalld variant,
        // holding the redirect rich rule as firewalld normalised it -- so
        // what is asserted here is that a rule string full of quotes
        // survives the round trip, not that a shape of its own does.
        let handle = RuleHandle::Firewalld {
            zone: ZONE.to_string(),
            rich_rule: FORWARD_REDIRECT.to_string(),
        };
        let json = serde_json::to_string(&handle).unwrap();
        assert_eq!(
            serde_json::from_str::<RuleHandle>(&json).unwrap(),
            handle,
            "serialised as: {json}"
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["backend"], "firewalld");
        assert_eq!(v["rich_rule"], FORWARD_REDIRECT);
    }

    /// Delegates every call to an inner [`RecordingRunner`], except for named
    /// programs, which fail exactly as [`RealRunner`](crate::command::RealRunner)
    /// would if the binary were not installed at all: a spawn error, not a
    /// scripted [`Output`].
    ///
    /// Every backend's `health()` treats "not installed" as specifically that
    /// -- see e.g. `Firewalld::health`'s `Err(Error::CommandSpawn { .. })` arm
    /// -- and a bare `RecordingRunner` can never produce one; it always
    /// returns `Ok`, even for a scripted [`Output::failure`]. Feeding
    /// `Output::failure` where a genuine absence is needed is read as
    /// "installed, but this call failed", which is a different state
    /// entirely: `Firewalld::health` still reports `available: true` for it,
    /// because only the `CommandSpawn` early return ever sets `available:
    /// false`. So simulating "not installed" in a cascade test needs this
    /// instead.
    struct AbsentPrograms<'a> {
        absent: &'a [&'a str],
        inner: RecordingRunner,
    }

    impl<'a> AbsentPrograms<'a> {
        fn new(absent: &'a [&'a str], responses: Vec<Output>) -> Self {
            Self {
                absent,
                inner: RecordingRunner::with_responses(responses),
            }
        }
    }

    impl CommandRunner for AbsentPrograms<'_> {
        fn run(&self, cmd: &Command) -> crate::error::Result<Output> {
            if self.absent.contains(&cmd.program.as_str()) {
                return Err(Error::CommandSpawn {
                    command: cmd.display(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no such file or directory",
                    ),
                });
            }
            self.inner.run(cmd)
        }
    }

    #[test]
    fn detect_prefers_firewalld_when_it_is_running() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("2.4.4"),
            Output::stdout("running"),
        ]);
        assert_eq!(detect(&runner).unwrap().id(), BackendId::Firewalld);
    }

    #[test]
    fn detect_prefers_ufw_next_when_firewalld_is_absent() {
        // `firewall-cmd` is genuinely unreachable, so `Firewalld::health`
        // takes its `CommandSpawn` early return and never calls the runner
        // again -- nothing is scripted for it, because nothing is read. That
        // leaves exactly two responses for ufw's own two-call health check:
        // its version, then its status.
        let runner = AbsentPrograms::new(
            &["firewall-cmd"],
            vec![
                Output::stdout("ufw 0.36.2"),
                Output::stdout("Status: active"),
            ],
        );
        assert_eq!(detect(&runner).unwrap().id(), BackendId::Ufw);
    }

    #[test]
    fn detect_picks_nftables_last_and_on_presence_not_activity() {
        // firewalld and ufw are policy managers: installing one is a choice.
        // nft ships on nearly every modern Linux, so its presence says
        // nothing -- which is exactly why it is the fallback and not a
        // contender.
        //
        // firewalld and ufw are both genuinely absent, so neither one ever
        // touches the queue below. nftables' health check makes exactly two
        // calls of its own: its version, then `nft -j list chains`. The
        // chain listing is scripted empty on purpose -- no chain at the
        // input hook means nothing is enforcing, so `active` comes back
        // false -- and nftables is still chosen, because `detect` reads
        // `available`, never `active`, for this backend. That is the whole
        // point of this test.
        let runner = AbsentPrograms::new(
            &["firewall-cmd", "ufw"],
            vec![
                Output::stdout("nftables v1.1.6"),
                Output::stdout(
                    r#"{"nftables":[{"metainfo":{"version":"1.1.3","json_schema_version":1}}]}"#,
                ),
            ],
        );
        assert_eq!(detect(&runner).unwrap().id(), BackendId::Nftables);
    }

    #[test]
    fn detect_does_not_report_no_firewall_when_nftables_output_is_unparseable() {
        // The seventh instance of one class on this branch, and the first
        // time it was in a comment written to fix that very class:
        // `Nftables::health` used to let a JSON parse failure propagate as
        // `Err` on the theory that `porthole doctor` needed it to, to tell
        // the failure apart from "needs root". Doctor cannot -- it gets its
        // backend from `detect`, which propagates any `health()` error with
        // `?` (below), so the parse failure never reached `firewall_check`
        // at all. A unit test constructing `Nftables` directly (as
        // `doctor.rs`'s own test does) cannot catch that, because it never
        // goes through `detect` -- this one does, on purpose, to prove the
        // path production actually takes.
        let runner = AbsentPrograms::new(
            &["firewall-cmd", "ufw"],
            vec![
                Output::stdout("nftables v1.1.6"),
                Output::stdout("not valid nft -j output"),
            ],
        );
        let backend = detect(&runner)
            .expect("an installed nft with unparseable output must still be detected");
        assert_eq!(backend.id(), BackendId::Nftables);
    }

    #[test]
    fn detect_does_not_report_no_firewall_when_firewalld_state_spawn_fails() {
        // On the one backend the earlier ufw and nftables permission-denied
        // fix did not cover: `firewall-cmd --version` succeeding already
        // proves firewalld is installed; a resource-level failure
        // to even run `--state` afterwards used to propagate with `?` out
        // of `Firewalld::health`, and `detect` propagates any `health()`
        // error the same way -- so this reported "no firewall found" on a
        // machine running firewalld. Verified through `detect` itself, the
        // same reasoning as the nftables production-path test above.
        struct VersionOkThenSpawnFails;
        impl CommandRunner for VersionOkThenSpawnFails {
            fn run(&self, cmd: &Command) -> crate::error::Result<Output> {
                if cmd.args.iter().any(|a| a == "--version") {
                    Ok(Output::stdout("2.4.4"))
                } else {
                    Err(Error::CommandSpawn {
                        command: cmd.display(),
                        source: std::io::Error::other("resource busy"),
                    })
                }
            }
        }
        let backend = detect(&VersionOkThenSpawnFails)
            .expect("an installed firewalld must still be detected");
        assert_eq!(backend.id(), BackendId::Firewalld);
    }

    #[test]
    fn detect_still_prefers_an_installed_but_stopped_firewalld_over_ufw() {
        // Reporting "firewalld is installed but not running" is more useful
        // than silently managing a different firewall than the one the
        // machine chose.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("2.4.4"),
            // 252, firewalld's own NOT_RUNNING: what a stopped firewalld
            // actually answers, and the only exit `health()` reads as stopped.
            Output {
                status: 252,
                stdout: "not running".into(),
                stderr: String::new(),
            },
        ]);
        let backend = detect(&runner).unwrap();
        assert_eq!(backend.id(), BackendId::Firewalld);
    }

    #[test]
    fn detect_names_all_three_and_refuses_to_pretend_when_none_found() {
        // All three are genuinely absent, so each health check takes its own
        // early `CommandSpawn` return before ever calling the runner a
        // second time. Nothing is scripted, because nothing is ever read.
        let runner = AbsentPrograms::new(&["firewall-cmd", "ufw", "nft"], vec![]);
        // `unwrap_err` needs `T: Debug`, and `Box<dyn FirewallBackend>` isn't
        // one -- the trait has no reason to require it. `.err().unwrap()`
        // gets the same error without that bound.
        let err = detect(&runner).err().unwrap();
        assert_eq!(err.exit_code(), ExitCode::BackendUnavailable);
        let text = err.to_string();
        for name in ["firewalld", "ufw", "nftables"] {
            assert!(text.contains(name), "must name {name}: {text}");
        }
        // The spec forbids porthole installing or enabling a firewall, so the
        // message has to say the port is already reachable and that setting
        // one up is not porthole's job. Assert the positive statement rather
        // than the absence of the word "install" -- the message legitimately
        // contains it ("is installed"), and a negative assertion on a common
        // word breaks on the next honest rewording.
        assert!(text.contains("already reachable"), "{text}");
        assert!(text.contains("outside what porthole does"), "{text}");
    }
}
