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
use crate::forward::ForwardTo;
use crate::listening::ProcFs;
use crate::model::{Lifetime, OpenRequest, Protocol, ScopeSpec, Target};
use crate::net::{self, LocalNetwork};
use crate::reconcile;
use crate::state::{ManagedRule, StateStore};
use crate::validate;
use ipnet::Ipv4Net;
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
    /// Records this engine's own reconciliation has dropped, waiting to be
    /// collected by [`Engine::take_reconciled`]. See that method for why they
    /// are accumulated rather than logged here.
    reconciled: Vec<ManagedRule>,
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
            reconciled: Vec::new(),
        }
    }

    /// Reconciles state against the firewall, read-only, then returns the
    /// (now accurate) rules.
    ///
    /// Read-only and not [`Engine::reconcile`]'s full sweep, deliberately:
    /// this is a read accessor, and the orphan direction mutates the
    /// firewall. See [`crate::reconcile::SweepMode::ReadOnly`].
    pub fn rules(&mut self) -> &[ManagedRule] {
        self.reconcile_read_only();
        self.state.rules()
    }

    /// Take the records this engine's reconciliation has dropped from state
    /// so far, leaving none behind.
    ///
    /// A dropped record is a rule the firewall no longer has: the port had
    /// already stopped being open, and reconciliation is porthole noticing.
    /// It is the same event the helper's start-up sweep already announces as
    /// `CloseReason::Reconciled`, and it happens for the same reasons at any
    /// other moment -- a `firewall-cmd --reload`, a `ufw reload` -- while the
    /// helper is running. Left uncollected it is invisible: nothing else in
    /// this crate logs it, and a client that learns what is open from the
    /// helper's signals alone would go on showing that port as open.
    ///
    /// Accumulated here rather than reported by [`Engine::run_sweep`] because
    /// the two callers that can act on it are outside this crate (the
    /// privileged helper's interface methods and its network monitor), and
    /// because a caller must be able to collect them **whether or not the
    /// operation it asked for succeeded** -- a `close` whose rule the sweep
    /// had just dropped fails with `RuleNotFound`, and that is exactly the
    /// case where the drop most needs announcing.
    ///
    /// Only [`crate::reconcile::SweepMode::Apply`] sweeps that actually
    /// persist contribute. A read path's sweep
    /// ([`crate::reconcile::SweepMode::ReadOnly`], what `status` and `rules`
    /// use) reflects the drop in memory and never saves it, so the record is
    /// still in the state file and the next writing operation will drop it
    /// for real; announcing from a read would announce the same close on
    /// every `list`. A dry run does not contribute either: nothing was
    /// written, so nothing was dropped.
    pub fn take_reconciled(&mut self) -> Vec<ManagedRule> {
        std::mem::take(&mut self.reconciled)
    }

    /// Turn what the user asked for into the network a backend can use.
    pub fn resolve(&self, spec: &ScopeSpec) -> Result<Target> {
        resolve_scope(self.runner, spec)
    }

    /// Bring the firewall and the state file back into agreement before
    /// doing anything else that reads or writes state.
    ///
    /// Runs before every operation, not only once at helper start-up: see
    /// `reconcile`'s module docs for why. Full [`crate::reconcile::SweepMode::Apply`]:
    /// both directions, persisted (unless the caller itself is a dry run, in
    /// which case the safe direction is computed and reflected in memory but
    /// never written -- see `SweepMode::Apply`'s own doc comment). Used by
    /// every operation that can mutate the firewall or the state file:
    /// `open`, `close_by_id`, `close_by_port`, `close_all`. `status` and
    /// `rules` use [`Engine::reconcile_read_only`] instead -- see there for
    /// why the split exists at all.
    fn reconcile(&mut self) {
        let mode = reconcile::SweepMode::Apply {
            dry_run: self.runner.is_dry_run(),
        };
        self.run_sweep(mode);
    }

    /// [`Engine::reconcile`], but for a read path.
    ///
    /// `status` is gated by the `List` polkit action, not `Close`, so a
    /// caller authorised only to look must never be able to cause a close --
    /// and the orphan direction is the only direction that mutates the
    /// firewall. [`crate::reconcile::SweepMode::ReadOnly`] never reaches it:
    /// it computes the safe (state-firewall) direction only, reflects it in
    /// `self.state`'s in-memory view so the caller's answer is accurate, and
    /// never saves -- a read path must not write either, and both `status`
    /// and `rules` are commonly reached without the exclusive state lock
    /// held at all.
    fn reconcile_read_only(&mut self) {
        self.run_sweep(reconcile::SweepMode::ReadOnly);
    }

    /// Run one sweep and log whatever it found wrong, without ever letting it
    /// fail the operation the caller actually asked for: the caller asked to
    /// open a port, close one, or read the truth about what is open, not to
    /// tidy up, and refusing that because an unrelated stale rule would not
    /// delete is a worse outcome than a rule left behind.
    ///
    /// What the sweep *dropped from state* is not a "went wrong" and is not
    /// logged here: it is collected for [`Engine::take_reconciled`], whose
    /// caller announces it. See that method.
    ///
    /// Several distinct kinds of "went wrong", all logged: `sweep` itself
    /// returning `Err` (a failure to list rules, or to save); a successful
    /// sweep whose `Report::failures` is non-empty (an individual orphan
    /// that would not close); `Report::orphan_sweep_error` (`owned_rules`
    /// itself failing -- see `reconcile.rs` for why that is a different fact
    /// from `failures`, not folded into it); and `Report::foreign_backend`
    /// (I1: a state entry recorded under a backend that is no longer the one
    /// just detected, which neither sweep direction may touch -- see that
    /// field's own doc comment). None of these abort `sweep` with `?`
    /// internally, so silently dropping any of them here would turn a real,
    /// reportable problem into one nothing ever prints.
    fn run_sweep(&mut self, mode: reconcile::SweepMode) {
        match reconcile::sweep(self.backend, &mut self.state, mode) {
            Ok(report) => {
                // Not logged here: [`Engine::take_reconciled`]'s caller
                // writes the journal line and emits the signal together, so
                // logging it here as well would say it twice in the one
                // process that does both.
                if matches!(mode, reconcile::SweepMode::Apply { dry_run: false }) {
                    self.reconciled
                        .extend(report.dropped_from_state.iter().cloned());
                }
                for failure in &report.failures {
                    eprintln!(
                        "porthole: reconciliation could not remove one orphaned rule, \
                         continuing: {failure}"
                    );
                }
                if let Some(e) = &report.orphan_sweep_error {
                    eprintln!(
                        "porthole: reconciliation could not check for orphaned rules, \
                         continuing: {e}"
                    );
                }
                for rule in &report.foreign_backend {
                    eprintln!(
                        "porthole: reconciliation found {}/{} recorded under backend {}, but \
                         {} is what this machine has now -- porthole cannot tell whether that \
                         rule is still open in the old firewall, so it is left in state \
                         unclosed rather than guessed away; close it by hand, or switch back \
                         to {} and let the next command reconcile it",
                        rule.port,
                        rule.protocol,
                        rule.backend,
                        self.backend.id(),
                        rule.backend,
                    );
                }
            }
            Err(e) => {
                eprintln!("porthole: reconciliation failed, continuing anyway: {e}");
            }
        }
    }

    /// Refuse unless the firewall is confirmed to be enforcing rules.
    ///
    /// One copy, called by every operation that would write a rule: a rule
    /// written where nothing enforces it is a promise porthole cannot keep,
    /// and two copies of the sentence saying so would drift apart.
    fn require_enforcing_firewall(&self) -> Result<()> {
        let health = self.backend.health()?;
        if health.active {
            return Ok(());
        }
        // `active: false` is two different facts (see
        // `BackendHealth::active_unknown`'s own doc comment), and only one of
        // them supports "the firewall is not enforcing rules" as a stated
        // premise. Saying that outright when porthole could not read the
        // ruleset at all would assert something it does not know, right where
        // a hedge already exists for the other half of the same claim
        // (reachable vs. blocked) -- so the unknown case gets its own honest
        // lead-in instead of reusing this one.
        let why = if health.active_unknown {
            "porthole cannot open anything here until it can confirm the firewall is \
             actually enforcing rules -- it could not read enough of the ruleset to tell"
        } else {
            "porthole will not open anything while the firewall is not enforcing \
             rules: the port is either already reachable or blocked by something \
             porthole does not manage"
        };
        Err(Error::BackendUnavailable(format!(
            "{}. {why}",
            health.detail
        )))
    }

    pub fn open(
        &mut self,
        port: u16,
        protocol: Protocol,
        spec: &ScopeSpec,
        lifetime: Lifetime,
        uid: u32,
    ) -> Result<ManagedRule> {
        self.reconcile();
        self.require_enforcing_firewall()?;

        if let Some(existing) = self.state.find_by_port(port, protocol) {
            // A foreign-backend entry (see `close_rule`'s own doc comment)
            // cannot be closed through this backend, so "close it first"
            // would send someone in a circle: an ordinary `close` on this
            // port hits the same guard `close_rule` does. Name the actual
            // way out.
            let detail = if existing.backend != self.backend.id() {
                format!(
                    "open towards {} (recorded under the {} backend, but this machine now \
                     has {}); an ordinary close cannot remove that record -- \
                     `porthole close --id {} --forget` does, if you want this port back",
                    existing.target,
                    existing.backend,
                    self.backend.id(),
                    existing.id
                )
            } else {
                format!(
                    "open towards {}; close it first if you want a different scope",
                    existing.target
                )
            };
            return Err(Error::AlreadyOpen {
                port,
                protocol,
                detail,
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
            forward: None,
        };

        self.record_and_schedule(rule, lifetime)
    }

    /// Write a rule the backend has just created into the state file and
    /// arrange for it to close, undoing the firewall change if either fails.
    ///
    /// One copy, called by every operation that creates a rule. The rule is
    /// in the firewall by the time this runs, so each failure here has to
    /// remove it again rather than return and leave it behind.
    fn record_and_schedule(
        &mut self,
        rule: ManagedRule,
        lifetime: Lifetime,
    ) -> Result<ManagedRule> {
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

    /// Redirect the external port `req.port` to the container that publishes
    /// `published_port`.
    ///
    /// `req.port` is what the local network connects to; `published_port` is
    /// the port Docker published on this host, which is what the user named.
    /// The two are separate arguments because they are separate ports: the
    /// whole point of a forward is that they may differ.
    ///
    /// Five situations make a forward wrong, and the order they are found in
    /// is part of what this method promises.
    ///
    /// **Docker is read first.** Until that read returns, nothing about the
    /// request has been decided. A failed read yields
    /// [`Error::DockerUnreadable`] and a successful read with no match yields
    /// [`Error::NotPublishedByContainer`] -- two variants because they are
    /// two facts, and reporting the first as the second would tell a user a
    /// port is not published when porthole never found out. They share an
    /// exit code; the variant and [`Error::kind`] are what carry the
    /// difference.
    ///
    /// **That same read settles one more thing**, before anything else is
    /// consulted: a published mapping that is not restricted to a loopback
    /// address is already reachable from the network, so a forward would add
    /// a second way in rather than the only one, and expiring would close
    /// only the one porthole made. That is [`Error::AlreadyReachable`]. It is
    /// a refusal and not a warning because there is nowhere a warning could
    /// arrive in time: `porthole-helper`'s `service.rs` builds the polkit
    /// details before it authorizes, which is before Docker is read at all,
    /// so anything said here reaches the user only after they have already
    /// authenticated for a forward they would not have asked for.
    ///
    /// **The external port is checked next**, against porthole's own state
    /// and then against this machine's listening sockets. Either refuses with
    /// [`Error::ExternalPortInUse`], whose `detail` says which. Both exist
    /// because a redirect claims the port: what arrives on it reaches the
    /// container. The listening check does not look at what a socket is bound
    /// to -- any listener on that port and protocol refuses, loopback ones
    /// included.
    ///
    /// Ahead of all of it, reading nothing: whether the detected firewall can
    /// express a redirect at all, and whether porthole can check what this
    /// request needs checking. A firewall that cannot redirect makes every
    /// later question moot, and a UDP request meets a listening check that
    /// has no UDP counterpart yet.
    ///
    /// A firewall that is not confirmed to be enforcing rules is refused
    /// where `open` refuses it, in the same words.
    ///
    /// `procfs` is a parameter rather than an `Engine` field because this is
    /// the only operation on this type that reads `/proc` at all.
    pub fn forward(
        &mut self,
        req: &OpenRequest,
        published_port: u16,
        uid: u32,
        procfs: &dyn ProcFs,
    ) -> Result<ManagedRule> {
        let external = req.port;

        // First of all, and it reads nothing: on a firewall that cannot
        // redirect at all, no fact about Docker, the state file or /proc
        // changes the answer. Reporting one of those instead would send a
        // user looking for a container on a machine that could not have
        // forwarded to it either way.
        self.backend.forward_capability()?;

        // Then this, because it is a property of the request rather than of
        // this machine. The check further down that looks for a local
        // listener on the external port reads TCP only; for UDP it would find
        // nothing however much was there, and a check that cannot fail is not
        // one.
        if req.protocol == Protocol::Udp {
            return Err(Error::ForwardCheckUnavailable(format!(
                "porthole will not create a UDP forward yet: before redirecting a port it \
                 checks whether something on this machine is already listening on it, and \
                 that check reads TCP only -- for {external}/udp it would compare against \
                 nothing"
            )));
        }

        let published = crate::docker::published(self.runner).map_err(|e| {
            Error::DockerUnreadable(format!(
                "porthole could not read Docker's published ports, so it cannot say \
                 whether {published_port}/{} is one of them: {e}",
                req.protocol
            ))
        })?;

        // A host port can carry more than one DNAT rule --
        // `-p 127.0.0.1:5432:80 -p 0.0.0.0:5432:80` is two. The first match
        // wins; the chain is not searched for a best one.
        let mapping = published
            .iter()
            .copied()
            .find(|p| p.host_port == published_port && p.protocol == req.protocol)
            .ok_or_else(|| {
                Error::NotPublishedByContainer(format!(
                    "{published_port}/{} is not published by any container",
                    req.protocol
                ))
            })?;

        // Decided from Docker's answer and nothing else, which is why it
        // sits here: right after the read that produced it, beside the
        // refusal for a port no container publishes, and before this
        // machine's firewall or state file is consulted at all. A user whose
        // container is already exposed is told so whether or not their
        // firewall happens to be running.
        //
        // Asked of the whole read rather than of `mapping`: the `find` above
        // takes the first rule on the port, and a port can carry two
        // (`-p 127.0.0.1:3000:80 -p 0.0.0.0:3000:80`) with the loopback one
        // first. Asking `mapping` alone would then forward onto a port the
        // network already reaches and report it as a bounded exposure --
        // `docker::already_reachable` orders by exposure instead.
        //
        // What is read to decide it: one DNAT rule's own `-d` flag. No `-d`
        // at all is every interface; a `-d` naming an address outside
        // 127.0.0.0/8 is that one address. porthole has not looked at which
        // interface carries that address, so a container published on an
        // address no network of this machine's actually holds is refused
        // too. That is the conservative direction, and it is the reading
        // `open`'s own warning already gives that same rule.
        if let Some(reachable) =
            crate::docker::already_reachable(published_port, req.protocol, &published)
        {
            return Err(Error::AlreadyReachable(format!(
                "{reachable} A forward would not change that: it would add a second way in \
                 on {external}/{proto} and, when it expired, close only the one porthole \
                 made -- {published_port}/{proto} would still be open. To forward this \
                 container, publish it on loopback instead (`-p 127.0.0.1:{published_port}:...` \
                 in your docker-compose.yml or `docker run -p`), so that the local network \
                 reaches it only through the forward.",
                proto = req.protocol
            )));
        }

        let to = ForwardTo::from_published(&mapping);

        // After the Docker read, so that a Docker failure is reported before
        // this sweep can close anything; before the state check below, so a
        // record the firewall no longer has is not read as a conflict -- the
        // same reason `open` reconciles ahead of its own already-open check.
        self.reconcile();
        self.require_enforcing_firewall()?;

        if let Some(existing) = self.state.find_by_port(external, req.protocol) {
            return Err(Error::ExternalPortInUse {
                port: external,
                detail: format!(
                    "porthole has a rule on it, towards {} (id {})",
                    existing.target, existing.id
                ),
            });
        }

        // TCP only: `listening::scan` reads `/proc/net/tcp` and
        // `/proc/net/tcp6`, not their `udp` counterparts, so a UDP external
        // port passes this check having been compared against nothing.
        let listeners = crate::listening::scan(procfs).map_err(|e| {
            Error::Unexpected(format!(
                "porthole could not read this machine's listening sockets, so it cannot \
                 say whether anything already answers on {external}: {e}"
            ))
        })?;
        if let Some(service) = listeners
            .iter()
            .find(|s| s.port == external && s.protocol == req.protocol)
        {
            let detail = match &service.process {
                Some(name) => format!("`{name}` is listening on it"),
                None => "something on this machine is listening on it".to_string(),
            };
            return Err(Error::ExternalPortInUse {
                port: external,
                detail,
            });
        }

        // Minted before the backend call for the reason `open` gives: the
        // marker in the firewall and the id in the state file are one
        // identity.
        let id = Uuid::new_v4().to_string();
        let handle = self.backend.forward(req, &to, &format!("porthole:{id}"))?;

        let now = self.clock.now();
        let rule = ManagedRule {
            id,
            port: external,
            protocol: req.protocol,
            target: req.target,
            backend: self.backend.id(),
            opened_at: now,
            expires_at: match req.lifetime {
                Lifetime::For(d) => Some(now + d.as_secs()),
                Lifetime::UntilReboot => None,
            },
            uid,
            handle,
            forward: Some(to),
        };

        self.record_and_schedule(rule, req.lifetime)
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

    /// `forget`: see [`Engine::forget_rule`]. Only ever `true` from the CLI's
    /// `close --id <id> --forget` — `close_by_port` and `close_all` never
    /// pass it, so a foreign-backend entry is never forgotten by anything
    /// less specific than a human naming its id on purpose.
    pub fn close_by_id(&mut self, id: &str, from_timer: bool, forget: bool) -> Result<ManagedRule> {
        self.reconcile();
        self.close_by_id_unreconciled(id, from_timer, forget)
    }

    /// [`Engine::close_by_id`] without its own reconciliation pass. Used by
    /// [`Engine::close_all`], which already reconciled once for the whole
    /// batch: reconciling again per rule would run the same listing command
    /// once per rule instead of once per operation.
    fn close_by_id_unreconciled(
        &mut self,
        id: &str,
        from_timer: bool,
        forget: bool,
    ) -> Result<ManagedRule> {
        let rule = self
            .state
            .find_by_id(id)
            .cloned()
            .ok_or_else(|| Error::RuleNotFound(id.to_string()))?;
        if forget {
            self.forget_rule(rule, from_timer)
        } else {
            self.close_rule(rule, from_timer)
        }
    }

    pub fn close_by_port(
        &mut self,
        port: u16,
        protocol: Protocol,
        from_timer: bool,
    ) -> Result<ManagedRule> {
        self.reconcile();
        let rule = self
            .state
            .find_by_port(port, protocol)
            .cloned()
            .ok_or_else(|| Error::RuleNotFound(format!("{port}/{protocol}")))?;
        self.close_rule(rule, from_timer)
    }

    /// Close everything. Keeps going after a failure: one rule that will not
    /// close must not leave the others open.
    ///
    /// Never forgets: a foreign-backend entry among the rest still surfaces
    /// [`Engine::close_rule`]'s guard as one of the returned failures, rather
    /// than being silently dropped by a batch operation nobody named it to.
    /// Forgetting one is `close_by_id`'s job, on purpose, by id, alone.
    pub fn close_all(&mut self, from_timer: bool) -> (Vec<ManagedRule>, Vec<Error>) {
        self.reconcile();
        let ids: Vec<String> = self.state.rules().iter().map(|r| r.id.clone()).collect();
        let mut closed = Vec::new();
        let mut errors = Vec::new();
        for id in ids {
            match self.close_by_id_unreconciled(&id, from_timer, false) {
                Ok(rule) => closed.push(rule),
                Err(e) => errors.push(e),
            }
        }
        (closed, errors)
    }

    /// Close every rule whose stored CIDR is inside `lost` -- the subnet the
    /// caller last observed, now that it is observing a different one.
    ///
    /// `ManagedRule` records only the resolved `Target`, never the
    /// `ScopeSpec` that produced it, so there is no stored fact anywhere
    /// distinguishing "opened towards whatever subnet I'm on" from "opened
    /// towards this exact CIDR, deliberately, wherever I am". The predicate
    /// below is chosen so it does not need that distinction: a rule closes
    /// when its own CIDR sits inside `lost`, whichever `ScopeSpec` produced
    /// it. A rule whose CIDR is disjoint from `lost`, or broader than it (a
    /// deliberate `--to 10.0.0.0/8` on a `10.10.10.0/24` machine, say), was
    /// never a claim about `lost` specifically and survives -- closing it
    /// would be answering a question the machine leaving `lost` never
    /// raised. [`Target::Anywhere`] is checked against nothing and always
    /// survives.
    ///
    /// `lost` is a subnet the caller has stopped finding, not a subnet proven
    /// unreachable. What counts as stopping is the caller's judgement and is
    /// stated where that judgement is made; nothing here re-examines it, and
    /// nothing here reads the machine's interfaces at all.
    ///
    /// Reconciles first, exactly as [`Engine::close_all`] does: the same
    /// batch of rules is about to be inspected and possibly closed, so this
    /// should not cost a separate listing command per rule the way looping
    /// [`Engine::close_by_id`] naively would. Keeps going after a failure for
    /// the same reason `close_all` does -- one rule that will not close must
    /// not leave the others open on a network they no longer belong to.
    pub fn close_rules_outside(&mut self, lost: Ipv4Net) -> Vec<ManagedRule> {
        self.reconcile();
        let ids: Vec<String> = self
            .state
            .rules()
            .iter()
            .filter(|r| match r.target {
                Target::Anywhere => false,
                Target::Network { cidr } => lost.contains(&cidr),
            })
            .map(|r| r.id.clone())
            .collect();
        self.close_ids_unasked(ids, "a network change")
    }

    /// Close every subnet-scoped rule because the machine has no usable
    /// network at all right now.
    ///
    /// With no current subnet to compare a rule's stored CIDR against, there
    /// is no way to say any subnet-scoped rule is still honestly reachable,
    /// so every one of them closes. [`Target::Anywhere`] survives, for the
    /// same reason [`Engine::close_rules_outside`] leaves it alone.
    pub fn close_rules_on_network_loss(&mut self) -> Vec<ManagedRule> {
        self.reconcile();
        let ids: Vec<String> = self
            .state
            .rules()
            .iter()
            .filter(|r| matches!(r.target, Target::Network { .. }))
            .map(|r| r.id.clone())
            .collect();
        self.close_ids_unasked(ids, "a network change")
    }

    /// Shared by every close nobody asked for -- [`Engine::close_rules_outside`],
    /// [`Engine::close_rules_on_network_loss`] and
    /// [`Engine::close_stale_forwards`]: close each id, logging and skipping
    /// whatever will not close rather than letting one stuck rule stop the
    /// rest. No separate error list the way [`Engine::close_all`] keeps one,
    /// on purpose -- nothing downstream of these reads which rule failed and
    /// why, only that the ones that could close are gone.
    ///
    /// `why` is the journal line's own account of what made porthole close
    /// these without being asked, so a reader of a failure line knows which
    /// sweep was running.
    fn close_ids_unasked(&mut self, ids: Vec<String>, why: &str) -> Vec<ManagedRule> {
        let mut closed = Vec::new();
        for id in ids {
            match self.close_by_id_unreconciled(&id, false, false) {
                Ok(rule) => closed.push(rule),
                Err(e) => {
                    eprintln!("porthole: could not close rule {id} after {why}, continuing: {e}");
                }
            }
        }
        closed
    }

    /// Close every forward whose container is no longer the one it was
    /// created against, and return what closed.
    ///
    /// Docker assigns container addresses at start. A restarted container can
    /// take a different one, and the address it gave up can pass to a
    /// different container -- at which point a forward towards that address
    /// carries traffic from the local network to a service nobody authorised.
    /// The stored mapping is compared against Docker's own DNAT table (never
    /// Docker's socket, and never `docker` group membership) and all four
    /// fields must still match: see [`crate::forward::stale_forwards`], which
    /// is the whole decision. Everything here is the read around it.
    ///
    /// **A table that could not be read closes nothing.** Not knowing is not
    /// knowing it changed, and there is no way to spell "no answer" to
    /// `stale_forwards`: an empty slice is the answer "no container publishes
    /// anything", which would name every forward. So a read failure is logged
    /// and this returns empty, leaving the next wake-up to try again --
    /// rather than taking access away for a transient `iptables` fault. It is
    /// the shape [`crate::net::present_networks`]'s callers already keep for a
    /// resolution they could not make: only an answer closes anything.
    ///
    /// A stale forward closes. It is never re-aimed at whatever address the
    /// container holds now, for the same reason a rule scoped to a subnet the
    /// machine has left is not re-aimed at the subnet it is on: the request
    /// was for one service, and porthole cannot say the new one is it.
    ///
    /// No `Result`, matching [`Engine::close_rules_outside`]: the one read
    /// here answers "nothing closed" rather than failing, and a per-rule
    /// close failure is logged and skipped like every other unasked close.
    pub fn close_stale_forwards(&mut self) -> Vec<ManagedRule> {
        // Read Docker before the sweep, so a table that cannot be read costs
        // nothing at all -- the same order `forward` uses, for the same
        // reason.
        let published = match crate::docker::published(self.runner) {
            Ok(published) => published,
            Err(e) => {
                eprintln!(
                    "porthole: could not read Docker's published ports, so no forward was \
                     compared against them and none was closed: {e}"
                );
                return Vec::new();
            }
        };

        self.reconcile();
        let ids = crate::forward::stale_forwards(self.state.rules(), &published);
        self.close_ids_unasked(ids, "the container it forwards to moved")
    }

    /// Close a rule the currently detected backend actually created.
    ///
    /// I1 (a previous wave): a state entry recorded under a backend that is
    /// no longer the one `detect` finds survives reconciliation rather than
    /// being silently dropped -- correctly, since dropping it would lose the
    /// only record of a rule that may still be sitting in the old firewall.
    /// But that leaves this function needing a guard of its own: `rule.handle`
    /// is a `RuleHandle` variant belonging to a *different* backend than
    /// `self.backend`, and every backend's own `close` refuses a handle from
    /// another one (see e.g. `Firewalld::close`'s `other @ (RuleHandle::Ufw
    /// {..} | ...)` arm) -- correctly, but with a message meant for a
    /// programmer, not a user: `"the nftables backend was handed a Ufw
    /// {..}"`. Refuse here instead, before ever calling `close`, with a
    /// message that says what actually happened and what to do about it --
    /// including [`Engine::forget_rule`], the only way out of this specific
    /// trap.
    fn close_rule(&mut self, rule: ManagedRule, from_timer: bool) -> Result<ManagedRule> {
        if rule.backend != self.backend.id() {
            // I4: `--forget` is the same suggestion regardless of which
            // backend created the rule, but forgetting does not mean the
            // same thing for all three. ufw and nftables can prove a rule is
            // their own (`Ownership::Marked`), so reconciliation's orphan
            // sweep closes a forgotten one on its own the next time that
            // backend is current again -- forgetting there only drops
            // porthole's own record early. firewalld cannot
            // (`Ownership::Unprovable`), so that sweep never runs on it at
            // all: forgetting a firewalld-backed rule is permanent -- no
            // record, and nothing ever closes it automatically, even after
            // firewalld is current again.
            let recovery = match rule.backend {
                BackendId::Firewalld => {
                    "firewalld can never prove a rule is its own, so forgetting this one \
                     would be permanent: nothing closes it automatically, even after \
                     firewalld is current again"
                }
                BackendId::Ufw | BackendId::Nftables => {
                    "ufw and nftables can prove a rule is their own, so forgetting this one \
                     is not permanent: once that backend is current again, the next \
                     `open` or `close` sweeps it away as an orphan. `status` and `list` \
                     will not -- they never touch the firewall"
                }
            };
            return Err(Error::Unexpected(format!(
                "{}/{} towards {} was recorded under the {} backend, but this machine now has \
                 {} -- porthole cannot remove a rule through a different backend than the one \
                 that created it. Close it by hand with {}'s own tools, switch back to {} and \
                 let the next porthole command reconcile it, or run `porthole close --id {} \
                 --forget` to drop the record without touching any firewall ({recovery})",
                rule.port,
                rule.protocol,
                rule.target,
                rule.backend,
                self.backend.id(),
                rule.backend,
                rule.backend,
                rule.id
            )));
        }

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

    /// Drop a state entry without touching any firewall.
    ///
    /// The only way out of the trap [`Engine::close_rule`]'s own doc comment
    /// describes: a foreign-backend entry cannot be closed through the
    /// currently detected backend, and reconciliation deliberately never
    /// removes it either (`reconcile.rs`'s `Report::foreign_backend`), since
    /// the entry may still name a real rule sitting in whatever firewall
    /// created it. Without this, such an entry is permanent: `open` on the
    /// same port refuses forever (`AlreadyOpen`), and `close` refuses too.
    ///
    /// Refuses for anything else: forgetting a rule the current backend
    /// could actually close would silently leave it enforced with no record
    /// left to close it by, later -- a strictly worse outcome than the trap
    /// this exists to escape, and not what `--forget` is for. Reachable only
    /// through `close_by_id` (see its own doc comment): forgetting always
    /// names one rule, by id, on purpose -- never a side effect of `--all`
    /// or a port lookup that might resolve to the wrong rule.
    fn forget_rule(&mut self, rule: ManagedRule, from_timer: bool) -> Result<ManagedRule> {
        if rule.backend == self.backend.id() {
            return Err(Error::InvalidArgument(format!(
                "{}/{} towards {} was recorded under {}, the backend this machine still has -- \
                 porthole can close it normally. --forget exists only for a rule recorded \
                 under a backend this machine no longer has; refusing to drop the record of \
                 one it could actually still close",
                rule.port, rule.protocol, rule.target, rule.backend
            )));
        }

        if !self.runner.is_dry_run() {
            self.state.remove(&rule.id);
            self.state.save()?;
        }

        // Same reasoning as `close_rule`'s own cancel, `from_timer` guard
        // included even though nothing wires `--forget` and `--from-timer`
        // together today (the expiry timer only ever calls `close --id <id>
        // --from-timer`, never with `--forget`): a close invoked *by* the
        // expiry timer must not stop that timer, and this is the exact same
        // trap `from_timer` exists to prevent, one flag away, if it is ever
        // both. Secondary either way, and must not turn a successful forget
        // into a reported failure -- a stray timer that fires later finds no
        // such rule and exits, harmlessly.
        if !from_timer && rule.expires_at.is_some() {
            let _ = expiry::cancel_close(self.runner, &rule.id);
        }

        Ok(rule)
    }

    pub fn status(&mut self) -> Result<Status> {
        self.reconcile_read_only();
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
    use crate::command::{Command, DryRunRunner, Effect, Output, RecordingRunner};
    use crate::error::ExitCode;
    use crate::listening::FakeProcFs;
    use crate::model::Protocol;
    use std::sync::Mutex;
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

    /// A state entry the backend has never heard of: exactly what a
    /// `firewall-cmd --reload` leaves behind, since porthole's rules are
    /// runtime-only and its state file is not.
    fn orphaned_record(id: &str) -> ManagedRule {
        ManagedRule {
            id: id.to_string(),
            port: 5173,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            // FakeBackend reports itself as Firewalld, so this is *this*
            // backend's own record rather than a foreign-backend one, which
            // the sweep would skip instead of dropping.
            backend: BackendId::Firewalld,
            opened_at: NOW,
            expires_at: None,
            uid: 1000,
            handle: RuleHandle::Firewalld {
                zone: "FedoraWorkstation".to_string(),
                rich_rule: "a rule the firewall no longer has".to_string(),
            },
            forward: None,
        }
    }

    #[test]
    fn a_record_the_firewall_no_longer_has_is_collectable_even_when_the_operation_fails() {
        // The reload case, which needs no restart: the firewall forgets,
        // porthole's state file does not, and the very next operation's
        // sweep drops the record. Before `take_reconciled` that drop was
        // invisible -- nothing logged it and nothing announced it -- so a
        // client watching the helper's signals kept showing the port as
        // open. It has to survive a *failed* operation in particular,
        // because the operation that fails is most often the close of the
        // rule that just went.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);

        let mut store = harness.store();
        store.insert(orphaned_record("gone"));
        store.save().unwrap();

        let mut engine = make_engine(&backend, &runner, &clock, harness.store());
        let closed = engine.close_by_id("gone", false, false);
        assert!(
            closed.is_err(),
            "the sweep dropped it first, so the close has nothing to find"
        );

        let reconciled = engine.take_reconciled();
        assert_eq!(reconciled.len(), 1, "the drop must still be collectable");
        assert_eq!(reconciled[0].id, "gone");
        assert_eq!(reconciled[0].port, 5173);
        assert!(
            engine.take_reconciled().is_empty(),
            "taking must drain, or the next operation would announce it again"
        );
    }

    #[test]
    fn a_read_path_never_produces_a_record_to_announce() {
        // `rules` and `status` reconcile read-only: the drop is reflected in
        // memory and never saved, so the record is still in the state file
        // and a later writing operation will drop it for real. Collecting it
        // here would announce the same close on every `porthole list`.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);

        let mut store = harness.store();
        store.insert(orphaned_record("gone"));
        store.save().unwrap();

        let mut engine = make_engine(&backend, &runner, &clock, harness.store());
        assert!(engine.rules().is_empty(), "read-only still hides it");
        assert!(engine.take_reconciled().is_empty());

        let still_there = StateStore::open(&harness.path).unwrap();
        assert_eq!(
            still_there.rules().len(),
            1,
            "a read path must not have written the drop"
        );
    }

    #[test]
    fn a_dry_run_produces_no_record_to_announce_either() {
        // Nothing was written, so nothing was dropped -- announcing a close
        // from a dry run would be the plainest kind of false statement.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = DryRunRunner::new(Box::new(RecordingRunner::new()));
        let clock = FixedClock(NOW);

        let mut store = harness.store();
        store.insert(orphaned_record("gone"));
        store.save().unwrap();

        let mut engine = make_engine(&backend, &runner, &clock, harness.store());
        let _ = engine.close_by_id("gone", false, false);
        assert!(engine.take_reconciled().is_empty());
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
    fn open_writes_the_same_id_into_the_marker_and_the_state() {
        // The marker handed to the backend and the id written into the state
        // file must be one identity, or reconciliation has nothing to match
        // them by. Asserted against the returned rule's own id, not a
        // hardcoded uuid: a second `Uuid::new_v4()` reintroduced by a future
        // refactor would desync the two silently, and only comparing against
        // `rule.id` is guaranteed to catch that rather than pass by
        // coincidence.
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

        assert_eq!(backend.markers(), vec![format!("porthole:{}", rule.id)]);
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
    fn open_refuses_without_claiming_reachability_when_activity_is_unknown() {
        // Follow-up to C1: refusing to open is correct in both cases `!
        // health.active` covers, but the *reason* given must not overclaim.
        // "the firewall is not enforcing rules" is a fact only the confirmed
        // case (`FakeBackend::inactive`, covered above) can support; a
        // permission-denied read supports only "porthole could not tell."
        let harness = Harness::new();
        let backend = FakeBackend::active_unknown();
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
        let text = err.to_string();
        assert!(
            !text.to_lowercase().contains("reachable"),
            "must not claim the port is reachable, or that it is not, when porthole \
             could not read the ruleset at all: {text}"
        );
        assert!(
            text.contains("could not") || text.contains("privilege"),
            "must say porthole could not tell, not that the firewall is confirmed \
             inactive: {text}"
        );
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
    fn open_reconciles_before_deciding_the_port_is_already_open() {
        // What a `firewall-cmd --reload` between two porthole commands looks
        // like: state still claims 5173 is open, but the firewall dropped it.
        // Without reconciliation this would wrongly refuse an open that
        // should succeed.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::with_responses(subnet_open_script());
        let clock = FixedClock(NOW);

        let mut store = harness.store();
        store.insert(ManagedRule {
            id: "ghost".to_string(),
            port: 5173,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            backend: BackendId::Firewalld,
            opened_at: NOW,
            expires_at: None,
            uid: 1000,
            handle: RuleHandle::Firewalld {
                zone: "TestZone".to_string(),
                rich_rule: "a rule the reload already dropped".to_string(),
            },
            forward: None,
        });

        let mut engine = make_engine(&backend, &runner, &clock, store);
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
            engine.rules().len(),
            1,
            "the ghost entry is gone, replaced by the real one"
        );
        assert_eq!(engine.rules()[0].id, rule.id);
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
        engine.close_by_id(&rule.id, true, false).unwrap();

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

    /// A state entry recorded under a different backend than the one an
    /// engine in these tests detects (always `Ufw`, below) -- I1's
    /// surviving-but-permanent entry, exactly the shape `close_rule` and
    /// `forget_rule` exist to handle.
    fn foreign_backend_rule(id: &str, port: u16) -> ManagedRule {
        ManagedRule {
            id: id.to_string(),
            port,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            backend: BackendId::Nftables,
            opened_at: NOW,
            expires_at: None,
            uid: 1000,
            handle: RuleHandle::Nftables {
                family: "inet".to_string(),
                table: "filter".to_string(),
                chain: "input".to_string(),
                marker: "porthole:foreign".to_string(),
            },
            forward: None,
        }
    }

    /// `Ufw::list_rules`/`owned_rules` both read `ufw status numbered` once
    /// each -- `Engine::reconcile`'s Apply sweep calls both -- and neither
    /// finds a `[`-prefixed row in this text, so both come back empty
    /// without needing anything scripted beyond it.
    const UFW_STATUS_NO_ROWS: &str = "Status: active\n";

    #[test]
    fn closing_a_foreign_backend_entry_refuses_with_a_plain_message_naming_forget() {
        // I1 created this trap: a state entry recorded under a backend that
        // is no longer the one `detect` finds survives reconciliation,
        // correctly -- but every backend's own `close` refuses a handle from
        // another one with wording meant for a programmer, not a user (e.g.
        // `Ufw::close`'s "the ufw backend was handed a Nftables { .. }").
        // `close_rule` must catch this *before* ever calling `backend.close`,
        // name what actually happened in plain language, and point at the
        // only way out.
        use crate::backend::ufw::Ufw;

        let harness = Harness::new();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(UFW_STATUS_NO_ROWS),
            Output::stdout(UFW_STATUS_NO_ROWS),
        ]);
        let backend = Ufw::new(&runner);
        let clock = FixedClock(NOW);
        let mut store = harness.store();
        store.insert(foreign_backend_rule("foreign-1", 9999));
        let mut engine = make_engine(&backend, &runner, &clock, store);

        let err = engine.close_by_id("foreign-1", false, false).unwrap_err();
        let text = err.to_string();
        assert!(
            !text.contains("was handed a"),
            "must not leak the internal RuleHandle-mismatch wording: {text}"
        );
        assert!(
            text.contains("nftables"),
            "must name the backend that actually created it: {text}"
        );
        assert!(
            text.contains("ufw"),
            "must name the backend this machine has now: {text}"
        );
        assert!(
            text.contains("--forget"),
            "must point at the only way out: {text}"
        );
        // I4: the recovery advice must not be the same sentence for every
        // backend -- a forgotten nftables (or ufw) rule is not permanent,
        // since reconciliation's orphan sweep closes it once that backend
        // is current again.
        assert!(
            text.contains("not permanent"),
            "must say a forgotten nftables rule is recoverable: {text}"
        );
        assert_eq!(
            engine.rules().len(),
            1,
            "refusing to close it must not lose the only record of it either"
        );
    }

    #[test]
    fn closing_a_foreign_firewalld_entry_warns_that_forgetting_it_would_be_permanent() {
        // I4: the opposite half of the same guard's advice. firewalld's
        // ownership is `Unprovable`, so reconciliation's orphan sweep is
        // skipped for it outright (see `reconcile.rs`) -- a firewalld-backed
        // rule that gets forgotten is never swept up later the way a
        // forgotten ufw/nftables one is. The message must say so, not reuse
        // the other backends' "not permanent" reassurance.
        use crate::backend::ufw::Ufw;

        let harness = Harness::new();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(UFW_STATUS_NO_ROWS),
            Output::stdout(UFW_STATUS_NO_ROWS),
        ]);
        let backend = Ufw::new(&runner);
        let clock = FixedClock(NOW);
        let mut store = harness.store();
        store.insert(ManagedRule {
            backend: BackendId::Firewalld,
            handle: RuleHandle::Firewalld {
                zone: "FedoraWorkstation".to_string(),
                rich_rule: r#"rule family="ipv4" source address="10.10.10.0/24" port \
                              port="9999" protocol="tcp" accept"#
                    .to_string(),
            },
            ..foreign_backend_rule("foreign-firewalld", 9999)
        });
        let mut engine = make_engine(&backend, &runner, &clock, store);

        let err = engine
            .close_by_id("foreign-firewalld", false, false)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("permanent"),
            "must warn that forgetting a firewalld-backed rule never gets swept up: {text}"
        );
        assert!(
            !text.contains("not permanent"),
            "must not reuse the ufw/nftables reassurance for firewalld: {text}"
        );
    }

    #[test]
    fn forgetting_a_foreign_backend_entry_drops_it_without_touching_any_firewall() {
        use crate::backend::ufw::Ufw;

        let harness = Harness::new();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(UFW_STATUS_NO_ROWS),
            Output::stdout(UFW_STATUS_NO_ROWS),
        ]);
        let backend = Ufw::new(&runner);
        let clock = FixedClock(NOW);
        let mut store = harness.store();
        store.insert(foreign_backend_rule("foreign-1", 9999));
        let mut engine = make_engine(&backend, &runner, &clock, store);

        let forgotten = engine.close_by_id("foreign-1", false, true).unwrap();
        assert_eq!(forgotten.id, "foreign-1");
        assert!(engine.rules().is_empty(), "the record must be gone");
        assert!(
            runner.recorded().iter().all(|c| c.effect == Effect::Read),
            "forgetting must never mutate anything, only porthole's own state: {:?}",
            runner.recorded()
        );

        let reloaded = StateStore::open(&harness.path).unwrap();
        assert!(
            reloaded.rules().is_empty(),
            "the drop must reach disk too, not just the in-memory view"
        );
    }

    #[test]
    fn forget_refuses_a_rule_the_current_backend_could_actually_close() {
        // --forget exists only for the trap a foreign-backend entry is.
        // Honouring it for an ordinary rule the current backend still owns
        // would silently leave that rule enforced with no record left able
        // to close it later -- a strictly worse outcome than the trap it
        // exists to escape, so this must refuse rather than guess the user
        // meant it.
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

        let err = engine.close_by_id(&rule.id, false, true).unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::InvalidArguments);
        assert_eq!(
            engine.rules().len(),
            1,
            "a refused forget must not lose the record either"
        );
        assert_eq!(
            backend.handles().len(),
            1,
            "and the firewall was genuinely never touched"
        );
    }

    #[test]
    fn open_on_a_port_with_a_foreign_backend_entry_names_forget_as_the_way_out() {
        // Without `--forget`, `AlreadyOpen`'s original "close it first" advice
        // sends someone in a circle: an ordinary close on this port hits the
        // exact same guard `close_rule` has. Name the way that actually works.
        let harness = Harness::new();
        let backend = FakeBackend::new(); // id() is Firewalld -- foreign_backend_rule is Nftables.
                                          // `AlreadyOpen` fires before scope is ever resolved, so nothing here
                                          // should read anything at all; an empty script makes that explicit
                                          // rather than leaving unused responses that could mask a regression.
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let mut store = harness.store();
        store.insert(foreign_backend_rule("foreign-1", 9999));
        let mut engine = make_engine(&backend, &runner, &clock, store);

        let err = engine
            .open(
                9999,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::For(Duration::from_secs(3600)),
                1000,
            )
            .unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::AlreadyOpen);
        assert!(
            runner.recorded().is_empty(),
            "AlreadyOpen must be decided before anything is read"
        );
        assert!(
            err.to_string().contains("--forget"),
            "an ordinary close cannot free this port; the message must say what does: {err}"
        );
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

        // A rule the backend genuinely holds -- unlike a handle it never
        // issued, which reconciliation's own sweep (now run at the top of
        // close_all) would quietly clean up before this loop ever saw it --
        // but whose close is forced to fail, so close_all still has to keep
        // going to reach the healthy rule after it.
        let stuck = backend
            .open(
                &OpenRequest {
                    port: 9999,
                    protocol: Protocol::Tcp,
                    target: Target::Anywhere,
                    lifetime: Lifetime::UntilReboot,
                },
                "porthole:stuck",
            )
            .unwrap();
        backend.fail_close_for("porthole:stuck");

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
            handle: stuck.clone(),
            forward: None,
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

        assert_eq!(errors.len(), 1, "the stuck rule must fail to close");
        assert_eq!(closed.len(), 1, "the healthy rule must close regardless");
        assert_eq!(closed[0].port, 5173);
        assert_eq!(
            backend.handles(),
            vec![stuck],
            "the stuck rule is still in the firewall; only the healthy one closed"
        );
        // The stuck rule stays recorded: porthole could not close it, so it
        // must not pretend it did.
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(engine.rules()[0].id, "stale");
    }

    #[test]
    fn close_rules_outside_closes_a_rule_for_exactly_the_subnet_that_was_lost() {
        // The intent was "let my phone reach this, on this network". The
        // network changed, so the intent no longer holds: closed, not
        // re-aimed at the new network, not left listed as if still valid.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        let closed = engine.close_rules_outside("10.10.10.0/24".parse().unwrap());
        assert_eq!(closed.len(), 1);
        assert!(engine.rules().is_empty());
        assert!(
            backend.handles().is_empty(),
            "the firewall rule must really be gone, not just the state entry"
        );
    }

    #[test]
    fn close_rules_outside_closes_a_narrower_rule_still_inside_the_lost_subnet() {
        // A single device on the subnet that was lost is exactly as
        // unreachable as the subnet itself.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::Host("10.10.10.42".parse().unwrap()),
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        let closed = engine.close_rules_outside("10.10.10.0/24".parse().unwrap());
        assert_eq!(closed.len(), 1);
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn close_rules_outside_leaves_a_rule_towards_anywhere_alone() {
        // "Anyone" was never tied to a subnet, so nothing about it became
        // false when the network did.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::Anywhere,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        let closed = engine.close_rules_outside("10.10.10.0/24".parse().unwrap());
        assert!(closed.is_empty());
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn close_rules_outside_leaves_a_rule_for_a_disjoint_subnet_alone() {
        // A rule deliberately aimed at a different subnet than the one lost
        // never made any claim about the one that was lost.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::Network("192.168.5.0/24".parse().unwrap()),
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        assert!(engine
            .close_rules_outside("10.10.10.0/24".parse().unwrap())
            .is_empty());
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn close_rules_outside_leaves_a_rule_broader_than_the_lost_subnet_alone() {
        // C1: `porthole open 5173 --to 10.0.0.0/8` on a 10.10.10.0/24 machine
        // is a deliberate, wider peer-subnet rule, not a claim about
        // 10.10.10.0/24 specifically. `10.0.0.0/8` is not a subset of the
        // 10.10.10.0/24 that was lost -- `lost.contains(&cidr)` is false --
        // so it must survive. The predicate this replaced (`!current.
        // contains(&cidr)`, checked against the *new* subnet) closed this
        // rule on every poll tick even though nothing about it had changed.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::Network("10.0.0.0/8".parse().unwrap()),
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        let closed = engine.close_rules_outside("10.10.10.0/24".parse().unwrap());
        assert!(closed.is_empty(), "must survive, got closed: {closed:?}");
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn close_rules_on_network_loss_closes_every_subnet_rule_but_not_anywhere() {
        // No network at all means every subnet-scoped rule is meaningless --
        // there is nothing left to compare its CIDR against -- but a rule
        // towards Anywhere was never tied to a subnet in the first place.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let runner = RecordingRunner::new();
        let clock = FixedClock(NOW);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();
        engine
            .open(
                5432,
                Protocol::Tcp,
                &ScopeSpec::Anywhere,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        let closed = engine.close_rules_on_network_loss();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].port, 5173);
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(engine.rules()[0].port, 5432);
    }

    #[test]
    fn dry_run_changes_nothing_and_writes_no_state() {
        // C3: a store starting empty can never catch "dry-run's own
        // reconciliation sweep writes anyway" -- there is nothing for sweep
        // to find stale, so its `store.save()` (gated on `!dry_run`) never
        // even becomes reachable. A pre-existing ghost entry the backend does
        // not have is what makes this test able to fail.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let inner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let runner = DryRunRunner::new(Box::new(inner));
        let clock = FixedClock(NOW);

        let mut store = harness.store();
        store.insert(ManagedRule {
            id: "ghost".to_string(),
            port: 9999,
            protocol: Protocol::Tcp,
            target: Target::Anywhere,
            backend: BackendId::Firewalld,
            opened_at: NOW,
            expires_at: None,
            uid: 1000,
            handle: RuleHandle::Firewalld {
                zone: "TestZone".to_string(),
                rich_rule: "a rule nothing in this test actually has".to_string(),
            },
            forward: None,
        });
        store.save().unwrap();

        let mut engine = make_engine(&backend, &runner, &clock, store);

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
        let reloaded = StateStore::open(&harness.path).unwrap();
        assert_eq!(
            reloaded.rules().len(),
            1,
            "dry-run must not write the state file, including via its own \
             reconciliation sweep: got {:?}",
            reloaded.rules()
        );
        assert_eq!(
            reloaded.rules()[0].id,
            "ghost",
            "the file on disk must be exactly what it was before this dry run"
        );
        assert_eq!(
            runner.recorded().len(),
            1,
            "one withheld mutation: the systemd-run"
        );
    }

    #[test]
    fn open_succeeds_even_when_reconciliations_own_sweep_fails() {
        // I2: named explicitly by the brief, and previously untested --
        // FakeBackend could not fail list_rules or owned_rules, so changing
        // Engine::reconcile to propagate a sweep failure with `?` instead of
        // logging and continuing would have left every existing test green.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        backend.fail_list_rules();
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
            .expect("a sweep failure must not fail the operation the caller asked for");

        assert_eq!(rule.port, 5173);
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
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let status = engine.status().unwrap();
        assert!(status.health.active);
        assert_eq!(status.location.as_deref(), Some("TestZone"));
        assert_eq!(
            status.network.unwrap().cidr,
            "10.10.10.0/24".parse().unwrap()
        );
    }

    #[test]
    fn status_cannot_close_a_rule_even_though_it_looks_like_an_orphan() {
        // C2: `status` is gated by the List polkit action, not Close -- a
        // caller authorised only to look must never be able to cause a
        // close. A rule the backend holds but state does not know about
        // looks exactly like an orphan reconciliation's Apply mode would
        // remove; `status` must leave it alone regardless.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let orphan = backend
            .open(
                &OpenRequest {
                    port: 9999,
                    protocol: Protocol::Tcp,
                    target: Target::Anywhere,
                    lifetime: Lifetime::UntilReboot,
                },
                "porthole:orphan",
            )
            .unwrap();
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let clock = FixedClock(NOW);
        // Nothing in state claims this rule -- harness.store() starts empty.
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine.status().unwrap();

        assert_eq!(
            backend.handles(),
            vec![orphan],
            "a read command must never close a rule the firewall holds"
        );
    }

    // --- forward -------------------------------------------------------

    /// `iptables -t nat -S DOCKER` for one container published the way this
    /// feature exists for: on loopback only, where the local network cannot
    /// reach it. Shaped after `docker.rs`'s own `DOCKER_CHAIN`, which was
    /// captured from a real daemon.
    const DOCKER_CHAIN_LOOPBACK: &str = "\
-N DOCKER
-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 3000 -j DNAT --to-destination 172.18.0.2:8080
";

    /// The same container published on every interface instead: no `-d` at
    /// all, which is what a plain `-p 3000:8080` writes on a daemon that has
    /// not been told to bind loopback. The local network already reaches this
    /// one, and porthole cannot close it.
    const DOCKER_CHAIN_EVERY_INTERFACE: &str = "\
-N DOCKER
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 3000 -j DNAT --to-destination 172.18.0.2:8080
";

    /// One host port carrying both rules, the loopback one first -- what
    /// `-p 127.0.0.1:3000:8080 -p 0.0.0.0:3000:8080` writes. The order is the
    /// point: whichever a first-match search picks, the port is reachable.
    const DOCKER_CHAIN_BOTH: &str = "\
-N DOCKER
-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 3000 -j DNAT --to-destination 172.18.0.2:8080
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 3000 -j DNAT --to-destination 172.18.0.2:8080
";

    /// The container behind [`DOCKER_CHAIN_LOOPBACK`], spelled out once.
    const CONTAINER_ADDR: &str = "172.18.0.2";
    const CONTAINER_PORT: u16 = 8080;
    const PUBLISHED_PORT: u16 = 3000;
    /// The port the local network would connect to. Deliberately not
    /// `PUBLISHED_PORT`: a test where the two are equal cannot tell which of
    /// them a rule was built from.
    const EXTERNAL_PORT: u16 = 8443;

    /// `/proc/net/tcp`'s header, which is all a machine with nothing
    /// listening has.
    const PROC_NET_TCP_EMPTY: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
";

    /// The same, plus one `LISTEN` socket on 8443 (hex `20FB`) bound to
    /// `0.0.0.0` -- a service the local network can already reach.
    const PROC_NET_TCP_8443: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 67371 1 0000000000000000 100 0 0 10 0
";

    /// One `LISTEN` socket on 8443 bound to `127.0.0.1` (hex `0100007F`).
    const PROC_NET_TCP_8443_LOOPBACK: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 67371 1 0000000000000000 100 0 0 10 0
";

    fn nothing_listening() -> FakeProcFs {
        FakeProcFs::new(PROC_NET_TCP_EMPTY)
    }

    /// What `iptables -t nat -S DOCKER` answers.
    #[derive(Clone, Copy)]
    enum DockerChain {
        /// The chain, read successfully.
        Reads(&'static str),
        /// A read that did not happen. Exit 4 is `iptables(8)`'s "resource
        /// problem", one of the statuses `docker::published` refuses to read
        /// as an empty chain -- unlike exit 1, which it reads as exactly
        /// that, and which would therefore test the wrong thing here.
        Unreadable,
    }

    /// Answers the `DOCKER` chain read and passes everything else to an
    /// ordinary [`RecordingRunner`], the way `SystemctlMissing` does for
    /// `systemctl`. It keeps its own recording so the intercepted read is
    /// visible too: a test that never proves the read happened would pass
    /// just as well against an engine that skipped it.
    struct DockerRunner {
        /// Behind a lock so one runner can answer differently before and
        /// after: a container restarts, or `iptables` stops working, while
        /// the same engine keeps running. A test that could not change the
        /// answer would have to build the rule it is checking by hand, and a
        /// hand-built rule is one no backend holds -- reconciliation would
        /// drop it before anything under test looked at it.
        chain: Mutex<DockerChain>,
        inner: RecordingRunner,
        seen: Mutex<Vec<Command>>,
        /// Makes every `systemd-run` fail to spawn, the way
        /// `SystemctlMissing` does for `systemctl`.
        no_timer: bool,
    }

    impl DockerRunner {
        fn new(chain: DockerChain, responses: Vec<Output>) -> Self {
            DockerRunner {
                chain: Mutex::new(chain),
                inner: RecordingRunner::with_responses(responses),
                seen: Mutex::new(Vec::new()),
                no_timer: false,
            }
        }

        fn with_no_timer(mut self) -> Self {
            self.no_timer = true;
            self
        }

        /// What the next `iptables -t nat -S DOCKER` answers.
        fn answers(&self, chain: DockerChain) {
            *self.chain.lock().expect("not poisoned") = chain;
        }
    }

    impl CommandRunner for DockerRunner {
        fn run(&self, cmd: &Command) -> Result<Output> {
            self.seen.lock().expect("not poisoned").push(cmd.clone());
            if cmd.program == "iptables" {
                return Ok(match *self.chain.lock().expect("not poisoned") {
                    DockerChain::Reads(text) => Output::stdout(text),
                    DockerChain::Unreadable => Output {
                        status: 4,
                        stdout: String::new(),
                        stderr: "iptables: Resource temporarily unavailable.".to_string(),
                    },
                });
            }
            if self.no_timer && cmd.program == "systemd-run" {
                return Err(Error::CommandSpawn {
                    command: cmd.display(),
                    source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
                });
            }
            self.inner.run(cmd)
        }

        fn recorded(&self) -> Vec<Command> {
            self.seen.lock().expect("not poisoned").clone()
        }
    }

    fn forward_req(external: u16) -> OpenRequest {
        OpenRequest {
            port: external,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            lifetime: Lifetime::For(Duration::from_secs(3600)),
        }
    }

    #[test]
    fn forward_tells_a_port_no_container_publishes_apart_from_a_docker_it_could_not_read() {
        // Two different facts. "No container publishes 3000" is an answer;
        // "porthole could not read Docker's table" is the absence of one, and
        // reporting the second as the first would have a user believe porthole
        // checked. They share an exit code, so the variant and `kind` are
        // where the difference has to survive -- assert both.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);

        let runner = DockerRunner::new(DockerChain::Reads("-N DOCKER\n"), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());
        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::NotPublishedByContainer(_)),
            "an empty chain is an answer: {err}"
        );
        assert_eq!(err.kind(), "not_published_by_container");
        assert_eq!(err.exit_code(), ExitCode::NotForwardable);
        assert!(
            err.to_string().contains("3000/tcp"),
            "the message must name the port asked about: {err}"
        );

        let harness = Harness::new();
        let runner = DockerRunner::new(DockerChain::Unreadable, Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());
        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::DockerUnreadable(_)),
            "an unreadable Docker table must not be reported as 'no container': {err}"
        );
        assert_eq!(err.kind(), "docker_unreadable");
        assert_eq!(err.exit_code(), ExitCode::NotForwardable);
        let text = err.to_string();
        assert!(
            text.contains("cannot say"),
            "the message must not claim to know: {text}"
        );
        assert!(
            !text.contains("is not published"),
            "the message must not read like the answer it does not have: {text}"
        );
    }

    #[test]
    fn forward_reads_docker_before_it_looks_at_the_external_port() {
        // The order is the substance. Here every one of the four things that
        // makes a forward wrong is true at once: Docker cannot be read, the
        // external port already carries a porthole rule, and something is
        // listening on it. The Docker answer is the one that must come out --
        // until that read returns, nothing else has been decided.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Unreadable, subnet_open_script());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        engine
            .open(
                EXTERNAL_PORT,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &FakeProcFs::new(PROC_NET_TCP_8443),
            )
            .unwrap_err();

        assert!(
            matches!(err, Error::DockerUnreadable(_)),
            "the external port's own troubles must not answer a question about Docker: {err}"
        );
        assert!(
            runner
                .recorded()
                .iter()
                .any(|c| c.program == "iptables" && c.args.iter().any(|a| a == "DOCKER")),
            "the DOCKER chain read has to actually happen"
        );
    }

    #[test]
    fn forward_refuses_an_external_port_porthole_already_has_a_rule_on_and_names_it() {
        // Silently redirecting a port the user already opened towards
        // something else would send traffic somewhere they did not ask for
        // and would have no way to notice.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(
            DockerChain::Reads(DOCKER_CHAIN_LOOPBACK),
            subnet_open_script(),
        );
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let existing = engine
            .open(
                EXTERNAL_PORT,
                Protocol::Tcp,
                &ScopeSpec::CurrentSubnet,
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap_err();

        assert!(matches!(err, Error::ExternalPortInUse { .. }), "got {err}");
        assert_eq!(err.exit_code(), ExitCode::ExternalPortInUse);
        let text = err.to_string();
        assert!(
            text.contains("8443"),
            "the message must name the conflict: {text}"
        );
        assert!(
            text.contains(&existing.id),
            "and the rule it conflicts with: {text}"
        );
        assert!(
            backend.forwarded().is_empty(),
            "a refusal must not have reached the firewall"
        );
    }

    #[test]
    fn forward_refuses_an_external_port_something_on_this_machine_is_listening_on() {
        // A redirect claims the port: what arrives on it goes to the
        // container instead of to whatever answered before.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &FakeProcFs::new(PROC_NET_TCP_8443).with_socket(67371, 4242, "nginx"),
            )
            .unwrap_err();

        assert!(matches!(err, Error::ExternalPortInUse { .. }), "got {err}");
        let text = err.to_string();
        assert!(
            text.contains("8443") && text.contains("nginx"),
            "the message must name the port and what holds it: {text}"
        );
        assert!(
            backend.forwarded().is_empty(),
            "a refusal must not have reached the firewall"
        );
    }

    #[test]
    fn forward_asks_whether_the_firewall_can_redirect_before_it_reads_anything() {
        // On ufw or nftables the answer is unconditional, and every later
        // question is moot. Reaching "not published by any container" or
        // "that port is already in use" here would state a downstream fact
        // while a more fundamental one holds, and send a user hunting for a
        // container on a machine that could not have forwarded to it.
        //
        // Every one of those downstream refusals is armed below: Docker
        // cannot be read, and something is listening on the external port.
        let harness = Harness::new();
        let backend = FakeBackend::without_forward();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Unreadable, Vec::new());
        let procfs = FakeProcFs::new(PROC_NET_TCP_8443);
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(&forward_req(EXTERNAL_PORT), PUBLISHED_PORT, 1000, &procfs)
            .unwrap_err();

        assert!(matches!(err, Error::ForwardUnsupported(_)), "got {err}");
        assert_eq!(err.exit_code(), ExitCode::ForwardUnsupported);
        assert!(runner.recorded().is_empty(), "no command ran");
        assert_eq!(backend.touched(), 0, "the firewall was not asked anything");
        assert_eq!(procfs.reads(), 0, "/proc was not read");
    }

    #[test]
    fn forward_reads_docker_before_it_asks_whether_the_firewall_is_running() {
        // Both are true here: the firewall is stopped and Docker cannot be
        // read. Docker is the read that comes first, so its answer is the one
        // that comes out -- until it returns, nothing about the request has
        // been decided.
        let harness = Harness::new();
        let backend = FakeBackend::inactive();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Unreadable, Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap_err();

        assert!(
            matches!(err, Error::DockerUnreadable(_)),
            "a stopped firewall must not answer a question about Docker: {err}"
        );
    }

    #[test]
    fn forward_refuses_a_container_the_network_can_already_reach() {
        // Docker published 3000 on every interface, so it is open now,
        // permanently, and porthole never opened it. A forward onto 8443
        // would not be a no-op: it would add a second way in and then, on
        // expiry, report that the exposure had ended while 3000 stayed open.
        // The only honest answer is to refuse before writing anything.
        //
        // The loopback case -- the one this feature exists for -- is not
        // refused, and `forward_creates_the_rule_and_records_the_mapping_it_
        // was_built_from` is what holds that: it runs the same call against
        // `DOCKER_CHAIN_LOOPBACK` and expects a rule.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner =
            DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_EVERY_INTERFACE), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap_err();

        assert!(matches!(err, Error::AlreadyReachable(_)), "got {err}");
        assert_eq!(err.exit_code(), ExitCode::AlreadyReachable);
        assert_eq!(err.kind(), "already_reachable");

        let text = err.to_string();
        assert!(
            text.contains("3000/tcp") && text.contains("already reachable"),
            "the message must name the port and say it is already reachable: {text}"
        );
        assert!(
            text.contains("8443/tcp"),
            "and the port the forward would have used: {text}"
        );
        assert!(
            text.contains("still be open"),
            "and that closing the forward would not close the published port: {text}"
        );

        assert!(
            backend.forwarded().is_empty(),
            "a refusal must not have reached the firewall"
        );
        assert!(
            StateStore::open(&harness.path).unwrap().rules().is_empty(),
            "and must not have recorded anything"
        );
    }

    #[test]
    fn forward_refuses_an_already_reachable_container_ahead_of_the_firewall_and_the_port() {
        // Where the refusal sits in the order, pinned. Three things are true
        // at once here: the container is already reachable, the firewall is
        // not running, and something on this machine is listening on the
        // external port. The Docker fact is the one that must come out --
        // moving this check below `require_enforcing_firewall` would answer
        // `BackendUnavailable`, and moving it below the listening scan would
        // answer `ExternalPortInUse`. Both would send the user to fix
        // something that would not have made the forward right.
        let harness = Harness::new();
        let backend = FakeBackend::inactive();
        let clock = FixedClock(NOW);
        let runner =
            DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_EVERY_INTERFACE), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &FakeProcFs::new(PROC_NET_TCP_8443),
            )
            .unwrap_err();

        assert!(
            matches!(err, Error::AlreadyReachable(_)),
            "a stopped firewall and a busy external port must not answer a question \
             about what Docker already published: {err}"
        );
    }

    #[test]
    fn forward_refuses_when_a_second_docker_rule_exposes_the_port_the_first_one_restricts() {
        // `-p 127.0.0.1:3000:8080 -p 0.0.0.0:3000:8080`, loopback first. The
        // mapping this forward would be built from is found by first match,
        // so reading the refusal off that mapping would let this through --
        // onto a port the network already reaches. The check asks the whole
        // read instead.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_BOTH), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap_err();

        assert!(matches!(err, Error::AlreadyReachable(_)), "got {err}");
        assert!(
            backend.forwarded().is_empty(),
            "a refusal must not have reached the firewall"
        );
    }

    #[test]
    fn forward_reconciles_before_deciding_the_external_port_is_taken() {
        // A `firewall-cmd --reload` between two porthole commands: state
        // still claims 8443 is open, the firewall dropped it. Without the
        // sweep this would refuse a forward that should succeed.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());

        let mut store = harness.store();
        store.insert(ManagedRule {
            id: "ghost".to_string(),
            port: EXTERNAL_PORT,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            backend: BackendId::Firewalld,
            opened_at: NOW,
            expires_at: None,
            uid: 1000,
            handle: RuleHandle::Firewalld {
                zone: "TestZone".to_string(),
                rich_rule: "a rule the reload already dropped".to_string(),
            },
            forward: None,
        });

        let mut engine = make_engine(&backend, &runner, &clock, store);
        let rule = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap();

        assert_eq!(rule.port, EXTERNAL_PORT);
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(engine.rules()[0].id, rule.id);
    }

    #[test]
    fn forward_refuses_an_external_port_a_loopback_only_service_listens_on() {
        // The check does not look at what a socket is bound to, and this is
        // the case that would slip through if it started to: a service on
        // 127.0.0.1 is one porthole is not able to say the redirect leaves
        // alone.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &FakeProcFs::new(PROC_NET_TCP_8443_LOOPBACK),
            )
            .unwrap_err();

        assert!(matches!(err, Error::ExternalPortInUse { .. }), "got {err}");
    }

    #[test]
    fn a_forward_whose_timer_cannot_be_scheduled_is_taken_back_out() {
        // The same rollback `open` gets, through the same code: a rule in the
        // firewall that nothing will ever close is the failure porthole
        // exists to prevent.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new())
            .with_no_timer();
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap_err();

        assert!(err.to_string().contains("could not run"), "got {err}");
        assert!(
            backend.handles().is_empty(),
            "the rule must be gone from the firewall"
        );
        assert!(
            StateStore::open(&harness.path).unwrap().rules().is_empty(),
            "and gone from the state file"
        );
    }

    #[test]
    fn forward_refuses_udp_and_says_it_is_the_check_that_does_not_reach_yet() {
        // The listening scan reads /proc/net/tcp and /proc/net/tcp6, so on a
        // UDP port it finds nothing however much is there. Creating the
        // forward anyway would run a check that cannot fail and present it as
        // protection. The message has to say that is what is missing -- a
        // sentence reading "porthole does not do UDP" would close a door that
        // is not closed.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let mut req = forward_req(EXTERNAL_PORT);
        req.protocol = Protocol::Udp;
        let procfs = nothing_listening();
        let err = engine
            .forward(&req, PUBLISHED_PORT, 1000, &procfs)
            .unwrap_err();

        assert!(
            matches!(err, Error::ForwardCheckUnavailable(_)),
            "got {err}"
        );
        assert_eq!(err.exit_code(), ExitCode::ForwardCheckUnavailable);
        assert_eq!(err.kind(), "forward_check_unavailable");
        let text = err.to_string();
        assert!(
            text.contains("yet") && text.contains("TCP"),
            "the message must name the gap and leave it open: {text}"
        );
        assert!(
            text.contains("8443/udp"),
            "and name the port it was asked about: {text}"
        );

        assert!(
            backend.forwarded().is_empty(),
            "a refusal must not have reached the firewall"
        );
        // The refusal is a property of the request, so it is reached without
        // consulting anything. All three seams have to say so: a command
        // runner alone cannot, since the backend's health and the sweep's
        // rule listing never run a command and the `/proc` fake never does
        // either.
        assert!(runner.recorded().is_empty(), "no command ran");
        assert_eq!(backend.touched(), 0, "the firewall was not asked anything");
        assert_eq!(procfs.reads(), 0, "/proc was not read");
    }

    #[test]
    fn forward_refuses_while_the_firewall_is_not_running() {
        // Same refusal `open` makes, in the same words: a rule written where
        // nothing enforces it is a promise porthole cannot keep, and a user
        // whose firewall is stopped has to be told that and not something
        // downstream of it.
        let harness = Harness::new();
        let backend = FakeBackend::inactive();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap_err();

        assert_eq!(err.exit_code(), ExitCode::BackendUnavailable);
        assert!(
            backend.forwarded().is_empty(),
            "a refusal must not have reached the firewall"
        );
    }

    #[test]
    fn forward_refuses_without_claiming_reachability_when_activity_is_unknown() {
        // The same hedge `open` carries: "the firewall is not enforcing
        // rules" is a fact only a confirmed-stopped firewall supports, and a
        // ruleset porthole could not read supports only "porthole could not
        // tell".
        let harness = Harness::new();
        let backend = FakeBackend::active_unknown();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let err = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap_err();

        assert_eq!(err.exit_code(), ExitCode::BackendUnavailable);
        let text = err.to_string();
        assert!(
            text.contains("could not read enough of the ruleset"),
            "must say porthole could not tell, not that the firewall is confirmed \
             inactive: {text}"
        );
    }

    #[test]
    fn forward_creates_the_rule_and_records_the_mapping_it_was_built_from() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());
        let mut engine = make_engine(&backend, &runner, &clock, harness.store());

        let rule = engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap();

        // The rule is on the external port -- what the local network sees --
        // not on the port Docker published.
        assert_eq!(rule.port, EXTERNAL_PORT);
        assert_eq!(
            rule.forward,
            Some(ForwardTo {
                container_addr: CONTAINER_ADDR.parse().unwrap(),
                container_port: CONTAINER_PORT,
                published_port: PUBLISHED_PORT,
                protocol: Protocol::Tcp,
            })
        );
        assert_eq!(rule.opened_at, NOW);
        assert_eq!(rule.expires_at, Some(NOW + 3600));
        assert_eq!(rule.uid, 1000);

        // One rule reached the firewall, and it was a forward rather than an
        // open.
        assert_eq!(backend.forwarded().len(), 1);
        assert!(backend.opened().is_empty());
        assert_eq!(backend.markers(), vec![format!("porthole:{}", rule.id)]);

        // Persisted, mapping and all, and readable by a fresh reader: the
        // mapping is stored so a later check can ask whether this is still
        // the same service, which it cannot do from memory.
        let reloaded = StateStore::open(&harness.path).unwrap();
        assert_eq!(reloaded.rules().len(), 1);
        assert_eq!(reloaded.rules()[0].forward, rule.forward);

        // And it closes by itself: a rule with no timer is the failure
        // porthole exists to prevent.
        let last = runner.recorded().pop().unwrap();
        assert_eq!(last.program, "systemd-run");
        assert!(last.args.contains(&"--on-active=3600s".to_string()));
        assert!(last.args.contains(&rule.id));
    }

    // --- close_stale_forwards ------------------------------------------

    /// The same container, restarted onto a different address. Everything
    /// else about the mapping is unchanged, which is exactly what makes it
    /// dangerous: the forward still looks current if only the published port
    /// is compared.
    const DOCKER_CHAIN_MOVED: &str = "\
-N DOCKER
-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 3000 -j DNAT --to-destination 172.18.0.9:8080
";

    /// An engine holding one live forward towards [`CONTAINER_ADDR`], built
    /// through `forward` so the backend really holds the rule -- a
    /// hand-written state entry would be an orphan the first sweep drops,
    /// and every assertion below would pass for the wrong reason.
    fn engine_with_a_forward<'a>(
        backend: &'a FakeBackend,
        runner: &'a DockerRunner,
        clock: &'a FixedClock,
        store: StateStore,
    ) -> Engine<'a> {
        let mut engine = make_engine(backend, runner, clock, store);
        engine
            .forward(
                &forward_req(EXTERNAL_PORT),
                PUBLISHED_PORT,
                1000,
                &nothing_listening(),
            )
            .unwrap();
        engine
    }

    #[test]
    fn an_unreadable_docker_table_closes_nothing() {
        // Not knowing is not knowing it changed. Closing on a read error
        // takes access away for a transient fault -- the same reason a
        // resolution failure in the network monitor closes nothing, while a
        // confirmed "no network" closes everything scoped to a subnet.
        //
        // The forward is real and current when the read breaks, so an
        // implementation that read an unreadable table as an empty one would
        // close it here.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());
        let mut engine = engine_with_a_forward(&backend, &runner, &clock, harness.store());

        runner.answers(DockerChain::Unreadable);
        let closed = engine.close_stale_forwards();

        assert!(closed.is_empty(), "a failed read must close nothing");
        assert_eq!(engine.rules().len(), 1, "and must leave the record alone");
        assert_eq!(
            backend.handles().len(),
            1,
            "and must leave the firewall alone"
        );
        assert!(
            runner
                .recorded()
                .iter()
                .filter(|c| c.program == "iptables")
                .count()
                >= 2,
            "the read has to have been attempted at all"
        );
    }

    #[test]
    fn a_forward_whose_container_moved_is_closed_and_returned() {
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());
        let mut engine = engine_with_a_forward(&backend, &runner, &clock, harness.store());
        let opened = engine.rules()[0].clone();

        runner.answers(DockerChain::Reads(DOCKER_CHAIN_MOVED));
        let closed = engine.close_stale_forwards();

        assert_eq!(closed.len(), 1, "the moved forward must close");
        assert_eq!(closed[0].id, opened.id);
        assert_eq!(
            closed[0].forward.as_ref().unwrap().container_addr,
            CONTAINER_ADDR.parse::<std::net::Ipv4Addr>().unwrap(),
            "what is returned is the rule as it was, not as Docker is now"
        );
        assert!(engine.rules().is_empty(), "and must leave the state");
        assert!(
            backend.handles().is_empty(),
            "and must leave the firewall -- not merely the state file"
        );

        // Gone for a fresh reader too, so a helper restart cannot resurrect
        // a forward towards a container that is not there.
        assert!(StateStore::open(&harness.path).unwrap().rules().is_empty());
    }

    #[test]
    fn a_forward_whose_container_is_unchanged_survives_the_sweep() {
        // The negative half. Without it every assertion above is satisfied by
        // a method that closes every forward it finds.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads(DOCKER_CHAIN_LOOPBACK), Vec::new());
        let mut engine = engine_with_a_forward(&backend, &runner, &clock, harness.store());

        let closed = engine.close_stale_forwards();

        assert!(closed.is_empty(), "closed: {closed:?}");
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(backend.handles().len(), 1);
    }

    #[test]
    fn an_ordinary_open_survives_a_sweep_that_finds_no_container_at_all() {
        // A machine with no Docker answers an empty chain, which is an
        // answer and not a failure. A rule that never named a container has
        // nothing for that answer to contradict.
        let harness = Harness::new();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DockerChain::Reads("-N DOCKER\n"), subnet_open_script());
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

        assert!(engine.close_stale_forwards().is_empty());
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(backend.handles().len(), 1);
    }
}
