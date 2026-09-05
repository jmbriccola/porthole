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
/// firewalld and ufw are chosen when **active**; nftables when merely
/// **present**. That asymmetry is deliberate: installing firewalld or ufw is a
/// decision about how this machine's firewall is managed, while `nft` exists
/// on almost every modern Linux and its presence says nothing at all. So nft
/// is the fallback, never a contender.
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
    Err(Error::BackendUnavailable(
        "no firewall found: none of firewalld, ufw or nftables is installed. \
         Without a firewall this port is already reachable from your network — \
         porthole cannot change that, and will not pretend it has. Setting up \
         a firewall is outside what porthole does."
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::firewalld;
    use super::firewalld::tests::{ROUTE_JSON, SUBNET_RULE, ZONE};
    use super::nftables;
    use super::ufw;
    use super::{detect, BackendId, FirewallBackend, Ownership};
    use crate::command::{Command, CommandRunner, Output, RecordingRunner};
    use crate::error::{Error, ExitCode};

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
                    // Two responses, because `owned_rules` reads twice: it
                    // discovers the single input base chain, then lists that
                    // chain's rules. A bare `RecordingRunner::new()` will not
                    // do -- empty stdout is not valid `nft -j` output, and
                    // unlike ufw's and firewalld's text parsers this one errors
                    // rather than reporting zero rules.
                    //
                    // The fixture deliberately carries one marked rule of the
                    // shape porthole writes and one unmarked rule, so this arm
                    // exercises the ownership filter rather than agreeing
                    // vacuously over an empty list.
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
    fn firewalld_wins_when_it_is_running() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("2.4.4"),
            Output::stdout("running"),
        ]);
        assert_eq!(detect(&runner).unwrap().id(), BackendId::Firewalld);
    }

    #[test]
    fn ufw_is_next_when_firewalld_is_absent() {
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
    fn nftables_is_last_and_is_chosen_on_presence_not_on_activity() {
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
    fn an_installed_but_stopped_firewalld_still_wins_over_ufw() {
        // Reporting "firewalld is installed but not running" is more useful
        // than silently managing a different firewall than the one the
        // machine chose.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("2.4.4"),
            Output::failure("not running"),
        ]);
        let backend = detect(&runner).unwrap();
        assert_eq!(backend.id(), BackendId::Firewalld);
    }

    #[test]
    fn no_firewall_at_all_names_all_three_and_refuses_to_pretend() {
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
