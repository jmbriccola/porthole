//! The order of operations.
//!
//! Everything the engine calls is independently testable; this module is the
//! only place that knows the sequence. One ordering decision matters more than
//! the rest: the state is written **before** the expiry timer is scheduled, and
//! if scheduling fails the rule is closed again and the state rolled back. An
//! open rule with no timer is exactly the failure porthole exists to prevent,
//! so it must not be reachable.
//!
//! When milestone 2 introduces the D-Bus helper, this module moves behind it
//! very nearly unchanged, and the CLI becomes a client.

use crate::backend::{BackendHealth, BackendId, FirewallBackend};
use crate::clock::Clock;
use crate::command::CommandRunner;
use crate::error::{Error, Result};
use crate::expiry;
use crate::model::{Lifetime, OpenRequest, Protocol, ScopeSpec, Target};
use crate::net::{self, LocalNetwork};
use crate::state::{ManagedRule, StateStore};
use crate::validate;
use std::path::PathBuf;
use uuid::Uuid;

/// Turn what the caller asked for into the network a backend can use.
///
/// A free function because the privileged helper needs to resolve a scope —
/// and decide which polkit action applies — *before* it takes the state lock.
/// A polkit check can block for as long as a human takes to type a password,
/// and holding an advisory lock across that would stall every other writer.
pub fn resolve_scope(runner: &dyn CommandRunner, spec: &ScopeSpec) -> Result<Target> {
    Ok(match spec {
        ScopeSpec::CurrentSubnet => Target::Network {
            cidr: net::current_network(runner)?.cidr,
        },
        ScopeSpec::Anywhere => Target::Anywhere,
        ScopeSpec::Network(cidr) => {
            // A /0 is everyone, however it was spelled.
            if cidr.prefix_len() == 0 {
                Target::Anywhere
            } else {
                Target::Network { cidr: *cidr }
            }
        }
        ScopeSpec::Host(addr) => Target::Network {
            cidr: validate::host_to_network(*addr),
        },
    })
}

/// Whether `target` amounts to the same exposure as `Target::Anywhere`.
///
/// `Target::Anywhere` always does. A `Target::Network` does too unless it
/// sits entirely inside the machine's own local subnet: a `/32` for a device
/// on that subnet stays the weaker case, but a network broader than the local
/// subnet, or one the machine is not even on, is not "the network you are on"
/// no matter how it was spelled — `--to 0.0.0.0/1` plus `--to 128.0.0.0/1`
/// between them cover the entire address space while neither is literally
/// `/0`, and both must still be treated as maximum exposure.
///
/// `local` is `None` when the local network could not be resolved. That is
/// the safe direction: nothing can be verified to be contained in a network
/// that is not known, so a resolution failure must not buy the weaker check.
pub fn is_open_any(target: &Target, local: Option<&LocalNetwork>) -> bool {
    match target {
        Target::Anywhere => true,
        Target::Network { cidr } => match local {
            None => true,
            Some(local) => !local.cidr.contains(cidr),
        },
    }
}

#[derive(Debug, Clone)]
pub struct Status {
    pub backend: BackendId,
    pub health: BackendHealth,
    /// `None` when the machine is not on a usable network.
    pub network: Option<LocalNetwork>,
    /// The firewalld zone, or whatever the backend calls its location.
    pub location: Option<String>,
    pub rules: Vec<ManagedRule>,
}

pub struct Engine<'a> {
    backend: &'a dyn FirewallBackend,
    runner: &'a dyn CommandRunner,
    clock: &'a dyn Clock,
    state: StateStore,
    /// The porthole binary the expiry timer will invoke.
    executable: PathBuf,
}

impl<'a> Engine<'a> {
    pub fn new(
        backend: &'a dyn FirewallBackend,
        runner: &'a dyn CommandRunner,
        clock: &'a dyn Clock,
        state: StateStore,
        executable: PathBuf,
    ) -> Self {
        Engine {
            backend,
            runner,
            clock,
            state,
            executable,
        }
    }

    pub fn rules(&self) -> &[ManagedRule] {
        self.state.rules()
    }

    /// Turn what the user asked for into the network a backend can use.
    pub fn resolve(&self, spec: &ScopeSpec) -> Result<Target> {
        resolve_scope(self.runner, spec)
    }

    pub fn open(
        &mut self,
        port: u16,
        protocol: Protocol,
        spec: &ScopeSpec,
        lifetime: Lifetime,
        uid: u32,
    ) -> Result<ManagedRule> {
        let health = self.backend.health()?;
        if !health.active {
            return Err(Error::BackendUnavailable(format!(
                "{}. porthole will not open anything while the firewall is not enforcing \
                 rules: the port is either already reachable or blocked by something \
                 porthole does not manage",
                health.detail
            )));
        }

        if let Some(existing) = self.state.find_by_port(port, protocol) {
            return Err(Error::AlreadyOpen {
                port,
                protocol,
                detail: format!(
                    "open towards {}; close it first if you want a different scope",
                    existing.target
                ),
            });
        }

        let target = self.resolve(spec)?;
        let request = OpenRequest {
            port,
            protocol,
            target,
            lifetime,
        };
        // Minted before the backend call, not after: the marker written into
        // the firewall and the id written into the state file must be the
        // same identity, or reconciliation has nothing to match them by.
        let id = Uuid::new_v4().to_string();
        let handle = self.backend.open(&request, &format!("porthole:{id}"))?;

        let now = self.clock.now();
        let rule = ManagedRule {
            id,
            port,
            protocol,
            target,
            backend: self.backend.id(),
            opened_at: now,
            expires_at: match lifetime {
                Lifetime::For(d) => Some(now + d.as_secs()),
                Lifetime::UntilReboot => None,
            },
            uid,
            handle,
        };

        if !self.runner.is_dry_run() {
            self.state.insert(rule.clone());
            if let Err(e) = self.state.save() {
                // The backend already has the rule. If recording it failed,
                // nothing would ever close it — no state entry to find it by,
                // and the scheduling below is never reached. Undo the opening
                // rather than return leaving a hole in the firewall that
                // porthole has no memory of.
                self.roll_back(&rule);
                return Err(e);
            }
        }

        if let Lifetime::For(duration) = lifetime {
            if let Err(e) =
                expiry::schedule_close(self.runner, &self.executable, &rule, duration.as_secs())
            {
                self.roll_back(&rule);
                return Err(e);
            }
        }

        Ok(rule)
    }

    /// Undo an opening that could not be completed.
    ///
    /// Best effort, but not blind: if the compensating close fails, the rule is
    /// still in the firewall, so the state entry must survive. A stale entry is
    /// recoverable — `porthole list` shows it and `close --all` retries it — and
    /// an open port with no record is not.
    fn roll_back(&mut self, rule: &ManagedRule) {
        let closed = self.backend.close(&rule.handle);
        if closed.is_ok() && !self.runner.is_dry_run() {
            self.state.remove(&rule.id);
            let _ = self.state.save();
        }
    }

    pub fn close_by_id(&mut self, id: &str, from_timer: bool) -> Result<ManagedRule> {
        let rule = self
            .state
            .find_by_id(id)
            .cloned()
            .ok_or_else(|| Error::RuleNotFound(id.to_string()))?;
        self.close_rule(rule, from_timer)
    }

    pub fn close_by_port(
        &mut self,
        port: u16,
        protocol: Protocol,
        from_timer: bool,
    ) -> Result<ManagedRule> {
        let rule = self
            .state
            .find_by_port(port, protocol)
            .cloned()
            .ok_or_else(|| Error::RuleNotFound(format!("{port}/{protocol}")))?;
        self.close_rule(rule, from_timer)
    }

    /// Close everything. Keeps going after a failure: one rule that will not
    /// close must not leave the others open.
    pub fn close_all(&mut self, from_timer: bool) -> (Vec<ManagedRule>, Vec<Error>) {
        let ids: Vec<String> = self.state.rules().iter().map(|r| r.id.clone()).collect();
        let mut closed = Vec::new();
        let mut errors = Vec::new();
        for id in ids {
            match self.close_by_id(&id, from_timer) {
                Ok(rule) => closed.push(rule),
                Err(e) => errors.push(e),
            }
        }
        (closed, errors)
    }

    fn close_rule(&mut self, rule: ManagedRule, from_timer: bool) -> Result<ManagedRule> {
        self.backend.close(&rule.handle)?;

        // The rule is gone from the firewall, so the state must stop claiming it
        // is open — and it must do so before anything else that could fail. A
        // state file that disagrees with the firewall is worse than a stray
        // timer: it points at a handle that no longer removes anything.
        if !self.runner.is_dry_run() {
            self.state.remove(&rule.id);
            self.state.save()?;
        }

        // Cancelling is secondary and deliberately cannot fail the close. A
        // close invoked *by* the expiry timer must not stop that timer, and a
        // rule that never had one has nothing to cancel. If the cancel itself
        // fails, the timer simply fires later, finds no such rule and exits —
        // harmless, and not a reason to report a successful close as an error.
        if !from_timer && rule.expires_at.is_some() {
            let _ = expiry::cancel_close(self.runner, &rule.id);
        }

        Ok(rule)
    }

    pub fn status(&self) -> Result<Status> {
        Ok(Status {
            backend: self.backend.id(),
            health: self.backend.health()?,
            // Not being on a network is a fact to report, not a failure.
            network: net::current_network(self.runner).ok(),
            location: self.backend.location().unwrap_or(None),
            rules: self.state.rules().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::fake::FakeBackend;
    use crate::backend::RuleHandle;
    use crate::clock::FixedClock;
    use crate::command::{Command, DryRunRunner, Output, RecordingRunner};
    use crate::model::Protocol;
    use std::time::Duration;
    use tempfile::TempDir;

    const NOW: u64 = 1_757_000_000;
    const ROUTE_JSON: &str = r#"[{"dst":"default","dev":"wlo1","metric":600}]"#;
    const ADDR_JSON: &str = r#"[{"ifindex":2,"ifname":"wlo1","addr_info":[{"family":"inet","local":"10.10.10.119","prefixlen":24,"scope":"global"}]}]"#;

    /// Responses for one `--to subnet` open: two `ip` reads, then systemd-run.
    fn subnet_open_script() -> Vec<Output> {
        vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
            Output::stdout("Running timer as unit: porthole-close-x.timer"),
        ]
    }

    struct Harness {
        _dir: TempDir,
        path: std::path::PathBuf,
    }

    impl Harness {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("state.json");
            Harness { _dir: dir, path }
        }

        fn store(&self) -> StateStore {
            StateStore::open(&self.path).unwrap()
        }
    }

    fn make_engine<'a>(
        backend: &'a dyn FirewallBackend,
        runner: &'a dyn CommandRunner,
        clock: &'a FixedClock,
        store: StateStore,
    ) -> Engine<'a> {
        Engine::new(
            backend,
            runner,
            clock,
            store,
            std::path::PathBuf::from("/usr/bin/porthole"),
        )
    }

    #[test]
    fn open_resolves_the_current_subnet_and_records_the_rule() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(subnet_open_script());
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let rule = engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(3600)),
                1000,
            )
            .unwrap();

        assert_eq!(rule.port, 5173);
        assert_eq!(
            rule.target,
            Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap()
            }
        );
        assert_eq!(rule.opened_at, NOW);
        assert_eq!(rule.expires_at, Some(NOW + 3600));
        assert_eq!(rule.uid, 1000);
        assert_eq!(backend.opened().len(), 1);

        // Persisted, and readable by a fresh reader.
        let reloaded = StateStore::open(&harness.path).unwrap();
        assert_eq!(reloaded.rules().len(), 1);
        assert_eq!(reloaded.rules()[0].id, rule.id);
    }

    #[test]
    fn open_schedules_a_close_timer() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(subnet_open_script());
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let rule = engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(900)),
                1000,
            )
            .unwrap();

        let last = runner.recorded().pop().unwrap();
        assert_eq!(last.program, "systemd-run");
        assert!(last.args.contains(&"--on-active=900s".to_string()));
        assert!(last.args.contains(&rule.id));
    }

    #[test]
    fn until_reboot_schedules_no_timer() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let rule = engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        assert_eq!(rule.expires_at, None);
        assert!(
            !runner.recorded().iter().any(|c| c.program == "systemd-run"),
            "an until-reboot rule needs no timer: the reboot removes it"
        );
    }

    #[test]
    fn open_rolls_back_when_the_timer_cannot_be_scheduled() {
        // A rule with no timer would never close. Better no rule at all.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
            Output {
                status: 1,
                stdout: String::new(),
                stderr: "Failed to start transient timer unit".into(),
            },
        ]);
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(3600)),
                1000,
            )
            .unwrap_err();
        assert!(err.to_string().contains("transient timer"), "got: {err}");

        assert!(
            backend.handles().is_empty(),
            "the rule must be closed again"
        );
        assert!(engine.rules().is_empty(), "the state must be rolled back");
        let reloaded = StateStore::open(&harness.path).unwrap();
        assert!(reloaded.rules().is_empty());
    }

    #[test]
    fn open_refuses_while_the_firewall_is_not_running() {
        let harness = Harness::new();
        let backend = FakeBackend::inactive();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(3600)),
                1000,
            )
            .unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::BackendUnavailable);
        assert!(backend.opened().is_empty());
    }

    #[test]
    fn open_refuses_a_port_that_is_already_open() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(
            subnet_open_script()
                .into_iter()
                .chain(subnet_open_script())
                .collect(),
        );
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();
        let err = engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::Anywhere,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap_err();

        assert_eq!(err.exit_code(), crate::error::ExitCode::AlreadyOpen);
        assert_eq!(backend.opened().len(), 1);

        // Same port, other protocol, is a different rule.
        assert!(engine
            .open(
                5173,
                Protocol::Udp,
                &ScopeSpec::Anywhere,
                Lifetime::UntilReboot,
                1000
            )
            .is_ok());
    }

    #[test]
    fn close_by_port_removes_the_rule_and_cancels_the_timer() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(subnet_open_script());
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(3600)),
                1000,
            )
            .unwrap();
        let closed = engine.close_by_port(5173, Protocol::Tcp, false).unwrap();

        assert_eq!(closed.port, 5173);
        assert!(backend.handles().is_empty());
        assert!(engine.rules().is_empty());
        // On disk too, not just in memory.
        assert!(StateStore::open(&harness.path).unwrap().rules().is_empty());

        let last = runner.recorded().pop().unwrap();
        assert_eq!(last.program, "systemctl");
        assert_eq!(
            last.args,
            vec![
                "stop".to_string(),
                format!("porthole-close-{}.timer", closed.id)
            ]
        );
    }

    #[test]
    fn a_close_from_the_timer_does_not_stop_its_own_timer() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(subnet_open_script());
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let rule = engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(3600)),
                1000,
            )
            .unwrap();
        engine.close_by_id(&rule.id, true).unwrap();

        assert!(
            !runner.recorded().iter().any(|c| c.program == "systemctl"),
            "the timer's own service must not try to stop the timer"
        );
    }

    #[test]
    fn closing_something_that_is_not_open_is_rule_not_found() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .close_by_port(5173, Protocol::Tcp, false)
            .unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::RuleNotFound);
        assert!(err.to_string().contains("5173/tcp"), "got: {err}");
    }

    #[test]
    fn close_all_closes_everything_and_reports_what_it_closed() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();
        engine
            .open(
                5432,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        let (closed, errors) = engine.close_all(false);
        assert_eq!(closed.len(), 2);
        assert!(errors.is_empty());
        assert!(engine.rules().is_empty());
        assert!(backend.handles().is_empty());
    }

    /// Answers `ip` normally but makes every `systemctl` invocation fail to
    /// spawn, so a close meets a cancellation failure on a real code path.
    struct SystemctlMissing {
        inner: RecordingRunner,
    }

    impl CommandRunner for SystemctlMissing {
        fn run(&self, cmd: &Command) -> Result<Output> {
            if cmd.program == "systemctl" {
                return Err(Error::CommandSpawn {
                    command: cmd.display(),
                    source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
                });
            }
            self.inner.run(cmd)
        }

        fn recorded(&self) -> Vec<Command> {
            self.inner.recorded()
        }
    }

    #[test]
    fn open_rolls_back_when_the_state_cannot_be_written() {
        // A hole in the firewall that nothing has recorded is worse than no
        // hole: no state entry means no way to find the rule again, and the
        // scheduling branch is never reached, so nothing would ever close it.
        //
        // The seam: `save` writes `<path>.json.tmp` before renaming it into
        // place. Pre-creating that path as a *directory* makes the write fail
        // while `open` still sees an ordinary missing state file.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        std::fs::create_dir(dir.path().join("state.json.tmp")).unwrap();
        let store = StateStore::open(&path).unwrap();

        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, store);

        let err = engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(3600)),
                1000,
            )
            .unwrap_err();
        assert!(err.to_string().contains("state.json"), "got: {err}");

        assert!(
            backend.handles().is_empty(),
            "a rule that could not be recorded must be closed again"
        );
        assert!(
            !runner.recorded().iter().any(|c| c.program == "systemd-run"),
            "a rolled-back rule must not leave a timer behind"
        );
    }

    #[test]
    fn a_close_succeeds_even_when_its_timer_cannot_be_cancelled() {
        // By the time cancellation runs, the rule is already gone from the
        // firewall. Failing here would report an open port that is in fact
        // closed, and would leave the state file claiming so too. A stray timer
        // that later fires and finds nothing is the harmless outcome.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = SystemctlMissing {
            inner: RecordingRunner::with_responses(vec![
                Output::stdout(ROUTE_JSON),
                Output::stdout(ADDR_JSON),
                Output::stdout("Running timer as unit: porthole-close-x.timer"),
            ]),
        };
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(3600)),
                1000,
            )
            .unwrap();

        let closed = engine
            .close_by_port(5173, Protocol::Tcp, false)
            .expect("the port is closed, so the close must not report failure");

        assert_eq!(closed.port, 5173);
        assert!(backend.handles().is_empty());
        assert!(engine.rules().is_empty());
        assert!(
            StateStore::open(&harness.path).unwrap().rules().is_empty(),
            "the state file must not outlive a close that really happened"
        );
    }

    #[test]
    fn close_all_keeps_going_when_one_rule_will_not_close() {
        // This is the entire reason close_all returns two lists instead of a
        // Result: one rule that refuses to close must not leave the others open.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let clock = FixedClock(NOW);

        // A rule the backend has never issued a handle for: closing it fails.
        // It is inserted first, so close_all meets the failure before the
        // healthy rule and has to keep going to reach it.
        let mut store = harness.store();
        store.insert(ManagedRule {
            id: "stale".to_string(),
            port: 9999,
            protocol: Protocol::Tcp,
            target: Target::Anywhere,
            backend: BackendId::Firewalld,
            opened_at: NOW,
            expires_at: None,
            uid: 1000,
            handle: RuleHandle::Firewalld {
                zone: "TestZone".to_string(),
                rich_rule: "a rule the fake backend never issued".to_string(),
            },
        });

        let mut engine = make_engine(&backend, &runner, &clock, store);
        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        let (closed, errors) = engine.close_all(false);

        assert_eq!(errors.len(), 1, "the stale rule must fail to close");
        assert_eq!(closed.len(), 1, "the healthy rule must close regardless");
        assert_eq!(closed[0].port, 5173);
        assert!(
            backend.handles().is_empty(),
            "the healthy rule must be gone from the firewall"
        );
        // The stale rule stays recorded: porthole could not close it, so it must
        // not pretend it did.
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(engine.rules()[0].id, "stale");
    }

    #[test]
    fn dry_run_changes_nothing_and_writes_no_state() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let inner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let runner = DryRunRunner::new(Box::new(inner));
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let rule = engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(3600)),
                1000,
            )
            .unwrap();

        // The subnet was really read, so a dry run tells the truth about scope.
        assert_eq!(
            rule.target,
            Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap()
            }
        );
        assert!(
            !harness.path.exists(),
            "dry-run must not write the state file"
        );
        assert_eq!(
            runner.recorded().len(),
            1,
            "one withheld mutation: the systemd-run"
        );
    }

    #[test]
    fn resolve_widens_a_single_host_to_a_slash_32() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let engine = make_engine(&backend, &runner, &clock, harness.store());

        assert_eq!(
            engine
                .resolve(&ScopeSpec::Host("10.10.10.42".parse().unwrap()))
                .unwrap(),
            Target::Network {
                cidr: "10.10.10.42/32".parse().unwrap()
            }
        );
        assert_eq!(
            engine.resolve(&ScopeSpec::Anywhere).unwrap(),
            Target::Anywhere
        );
    }

    #[test]
    fn a_slash_zero_network_resolves_to_anywhere() {
        // 0.0.0.0/0 is everyone, however it was spelled, and milestone 2 gives
        // "anywhere" a stronger polkit action than a subnet. A /0 must not take
        // the weaker path by being classified as an ordinary network.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let engine = make_engine(&backend, &runner, &clock, harness.store());

        assert_eq!(
            engine
                .resolve(&ScopeSpec::Network("0.0.0.0/0".parse().unwrap()))
                .unwrap(),
            Target::Anywhere
        );
        assert_eq!(
            engine
                .resolve(&ScopeSpec::Network("10.10.10.0/24".parse().unwrap()))
                .unwrap(),
            Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap()
            }
        );
    }

    fn local_net() -> LocalNetwork {
        LocalNetwork {
            interface: "wlo1".to_string(),
            address: "10.10.10.119".parse().unwrap(),
            cidr: "10.10.10.0/24".parse().unwrap(),
        }
    }

    #[test]
    fn anywhere_is_always_open_any() {
        assert!(is_open_any(&Target::Anywhere, Some(&local_net())));
        assert!(is_open_any(&Target::Anywhere, None));
    }

    #[test]
    fn a_slash_32_inside_the_local_subnet_stays_open_subnet() {
        let target = Target::Network {
            cidr: "10.10.10.42/32".parse().unwrap(),
        };
        assert!(
            !is_open_any(&target, Some(&local_net())),
            "a single device on the local subnet must keep the weaker action"
        );
    }

    #[test]
    fn a_network_that_is_not_the_local_subnet_is_open_any() {
        // Same prefix length as the local subnet, but a different network —
        // "the network you are on" this is not.
        let target = Target::Network {
            cidr: "192.168.1.0/24".parse().unwrap(),
        };
        assert!(is_open_any(&target, Some(&local_net())));
    }

    #[test]
    fn a_slash_zero_is_open_any() {
        let target = Target::Network {
            cidr: "0.0.0.0/0".parse().unwrap(),
        };
        assert!(is_open_any(&target, Some(&local_net())));
    }

    #[test]
    fn splitting_the_whole_address_space_in_half_does_not_hide_it_from_open_any() {
        // 0.0.0.0/1 and 128.0.0.0/1 together are total exposure, and neither
        // one is literally 0.0.0.0/0. A classifier that only caught prefix
        // length zero would let this through at the weaker action.
        for cidr in ["0.0.0.0/1", "128.0.0.0/1"] {
            let target = Target::Network {
                cidr: cidr.parse().unwrap(),
            };
            assert!(
                is_open_any(&target, Some(&local_net())),
                "{cidr} must be classified open-any"
            );
        }
    }

    #[test]
    fn no_local_network_is_the_safe_direction_open_any() {
        let target = Target::Network {
            cidr: "10.10.10.42/32".parse().unwrap(),
        };
        assert!(
            is_open_any(&target, None),
            "an unresolved local network must not buy the weaker check"
        );
    }

    #[test]
    fn status_reports_the_backend_the_zone_and_the_network() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let clock = FixedClock(NOW);
        let engine = make_engine(&backend, &runner, &clock, harness.store());

        let status = engine.status().unwrap();
        assert!(status.health.active);
        assert_eq!(status.location.as_deref(), Some("TestZone"));
        assert_eq!(
            status.network.unwrap().cidr,
            "10.10.10.0/24".parse().unwrap()
        );
    }
}
