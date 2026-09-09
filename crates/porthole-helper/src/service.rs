//! The privileged object clients talk to.
//!
//! Every method follows the same shape, and the order is deliberate:
//!
//! 1. **Validate**, treating everything the client sent as untrusted. The
//!    helper never accepts a rule string and never acts on a value it would
//!    not have accepted from a person.
//! 2. **Resolve the scope**, because which polkit action applies depends on
//!    what the request actually amounts to — `0.0.0.0/0` is "everyone"
//!    however it was spelled. `forward` resolves for the second reason
//!    alone, the prompt: its action is the same whatever the scope turns
//!    out to be.
//! 3. **Authorize**, before touching anything. [`Porthole::forward`] has one
//!    step in front of this one that no other method has: it asks the
//!    detected firewall whether it can redirect at all. That answer needs no
//!    privilege, no input and no read, and on a firewall that cannot, every
//!    later question is moot — so asking it after the authorization would
//!    charge a person an administrator password to learn something already
//!    known. It is not the enforcement, which stays in `Engine::forward`.
//! 4. **Take the state lock and act.** Not before: a polkit check can block
//!    for as long as a human takes to type a password, and the lock would
//!    stall every other writer for that whole time.
//! 5. **Log to the journal with the requesting uid**, which comes from the bus
//!    daemon rather than from the client.
//! 6. **Announce it on the bus**, so a desktop agent can say something. Steps
//!    5 and 6 are one call ([`Porthole::announce_open`],
//!    [`Porthole::announce_close`]) rather than two statements per call site:
//!    the journal line and the signal are then built from the same
//!    [`CloseReason`] value, and there is exactly one place a close could go
//!    unannounced instead of one per method.
//!
//! A rule can also stop being open without any client asking. Every method
//! that takes the exclusive lock reconciles first, and that sweep drops from
//! state whatever the firewall no longer has -- a `firewall-cmd --reload`
//! while the helper is running is enough. Those drops come back from
//! [`Engine::take_reconciled`] and are announced through
//! [`Porthole::announce_reconciled`] **before** the method's own signal and
//! regardless of whether the method itself succeeded, because a `close`
//! whose rule the sweep just dropped fails, and that is precisely when a
//! subscriber would otherwise be left showing a port as open forever.
//!
//! # Where the announcements are actually tested
//!
//! No test may reach an `announce_*` call by *changing a firewall*: a `close`
//! that gets that far has to have removed a rule from a real one, and an
//! `open` has to have added one, and neither is something the development
//! host's firewall is available for. Three things stand in.
//!
//! `crates/porthole-helper/tests/signals.rs` drives the real `close` and
//! `close_by_id` over a real bus and checks that the paths which close
//! nothing announce nothing, and drives the `announce_*` functions
//! themselves against a subscriber to check the declaration and the payload.
//!
//! `crates/porthole-helper/tests/reconciled_signal.rs` reaches
//! [`Porthole::announce_reconciled`] from inside the real `close` method,
//! and does it on any machine: reconciliation only ever *reads* the
//! firewall's rule listing, so that test writes a `firewall-cmd` of its own
//! and puts it in front of `PATH`. It is the case that matters most --
//! the sweep drops the record, the close then fails, and the drop is
//! announced anyway.
//!
//! The emissions that really do change a firewall are measured in
//! `crates/porthole-cli/tests/container.rs`, against a real firewalld inside
//! a container, gated behind `PORTHOLE_CONTAINER_TESTS=1`: an open, an
//! ordinary close, the expiry timer's own close and `close --all`
//! (`signals_reach_a_subscriber_when_a_port_is_opened_and_closed`), the
//! start-up sweep (`the_start_up_sweep_announces_what_it_dropped`) and
//! [`crate::netmon`]'s network-change closes
//! (`a_subnet_the_machine_left_is_announced_along_with_the_rules_it_closed`).

use crate::authz::{caller_uid, Action, Authorizer, Details};
use crate::error::HelperError;
use porthole_core::backend::{self, BackendHealth, BackendId};
use porthole_core::clock::SystemClock;
use porthole_core::command::RealRunner;
use porthole_core::engine::{is_open_any, resolve_scope, Engine, Status};
use porthole_core::error::Error;
use porthole_core::ipc::{CloseReason, WireDockerPort, WireError, WireRule, WireStatus};
use porthole_core::listening::RealProcFs;
use porthole_core::model::{Lifetime, OpenRequest};
use porthole_core::net;
use porthole_core::state::StateStore;
use porthole_core::validate;
use std::path::PathBuf;
use zbus::object_server::SignalEmitter;

static SYSTEM_CLOCK: SystemClock = SystemClock;

pub struct Porthole {
    authorizer: Box<dyn Authorizer>,
    /// A second connection to the same bus, used only to ask the daemon which
    /// uid is behind a caller's name. Separate from the connection the object
    /// is served on, which the builder owns.
    bus: zbus::Connection,
    state_path: PathBuf,
    executable: PathBuf,
}

impl Porthole {
    pub fn new(
        authorizer: Box<dyn Authorizer>,
        bus: zbus::Connection,
        state_path: PathBuf,
        executable: PathBuf,
    ) -> Self {
        Porthole {
            authorizer,
            bus,
            state_path,
            executable,
        }
    }
}

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl Porthole {
    /// `scope` is what the user typed — `subnet`, `any`, a CIDR, an IP — and
    /// the helper parses it itself. `seconds` is 0 for until-reboot.
    async fn open(
        &self,
        port: u16,
        protocol: &str,
        scope: &str,
        seconds: u32,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<WireRule, HelperError> {
        // 1. Validate. Nothing the client sent is trusted.
        if port == 0 {
            return Err(HelperError::InvalidArgument(
                "port 0 is not a port; valid ports are 1-65535".to_string(),
            ));
        }
        let protocol = validate::parse_protocol(protocol).map_err(HelperError::from)?;
        let spec = validate::parse_scope(scope).map_err(HelperError::from)?;
        let lifetime = if seconds == 0 {
            Lifetime::UntilReboot
        } else {
            Lifetime::For(
                validate::parse_duration(&format!("{seconds}s")).map_err(HelperError::from)?,
            )
        };

        // 2. Resolve before choosing the action, and before taking any lock.
        let runner = RealRunner;
        let target = resolve_scope(&runner, &spec).map_err(HelperError::from)?;
        // Whether this amounts to the same exposure as "everyone" depends on
        // the local network, not just on how the target was spelled: a
        // network broader than the local subnet, or one this machine is not
        // even on, is not "the network you are on" no matter what the client
        // called it. `Ok()` on failure, not `?`: not being on a network is a
        // fact `is_open_any` already treats as the safe (stronger) direction,
        // not a reason to fail the whole request before authorization.
        let local = net::current_network(&runner).ok();
        let action = if is_open_any(&target, local.as_ref()) {
            Action::OpenAny
        } else {
            Action::OpenSubnet
        };
        // What the polkit dialog's `$(key)` substitutions can show: the port,
        // protocol and resolved target, so a person can tell an expected
        // prompt from an unexpected one rather than reading a static
        // sentence that could belong to any request.
        let details = crate::polkit::open_details(port, protocol, &target);

        // 3. Authorize.
        self.authorizer
            .check(action, &details, &header)
            .await
            .map_err(HelperError::from)?;

        let uid = caller_uid(&self.bus, &header)
            .await
            .map_err(HelperError::from)?;

        // 4. Only now take the lock and act.
        // Scoped so the `Engine` -- which borrows `&dyn CommandRunner` and
        // `&dyn Clock`, neither of them `Sync` -- is dropped before the
        // `.await` below: a zbus interface method's future has to be `Send`.
        // It also drops the exclusive state lock before the announcement
        // rather than after it, which is the right order regardless.
        //
        // The engine's own result and what its reconciliation dropped come
        // out separately, and the drops are announced first and
        // unconditionally: an operation that fails *because* the sweep just
        // dropped its rule is exactly the case where the drop most needs
        // saying (see `Engine::take_reconciled`).
        let (opened, reconciled) = {
            let backend = backend::detect(&runner).map_err(HelperError::from)?;
            let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
            let mut engine = Engine::new(
                backend.as_ref(),
                &runner,
                &SYSTEM_CLOCK,
                state,
                self.executable.clone(),
            );
            // `open_resolved`, not `open`: the target was resolved above,
            // before the authorization, because the polkit message names it.
            // Resolving it a second time here would make the address a
            // person read and the address written into the firewall two
            // separate lookups with a password prompt in between them --
            // which is exactly the property `forward` was built not to have.
            let opened = engine.open_resolved(port, protocol, target, lifetime, uid);
            (opened, engine.take_reconciled())
        };

        // 5 and 6. The journal, then the bus.
        Self::announce_reconciled(Some(&emitter), &reconciled).await;
        let rule = opened.map_err(HelperError::from)?;
        Self::announce_open(&emitter, &rule).await;

        Ok(WireRule::from_rule(&rule))
    }

    /// Redirect the external port `port` to whatever container publishes
    /// `published_port` on this machine. `scope` and `seconds` mean exactly
    /// what they mean to [`Porthole::open`]. `port` and `published_port` are
    /// two ports rather than one: `port` is what the local network connects
    /// to, `published_port` is what the person named, and a forward is the
    /// one operation where they may differ.
    ///
    /// [`Action::Forward`] whatever `scope` resolves to. The `open-*` split
    /// asks how far a permission reaches, and this question is a different
    /// one: a forward makes a port published on this machine answer to
    /// another machine, and the answer must not be carried over from an
    /// authentication given minutes ago for something else. So there is no
    /// `_keep` severity to choose between, and nothing to choose it with.
    ///
    /// The refusals a forward has of its own are enumerated in one place,
    /// [`porthole_core::error::FORWARD_REFUSALS`], and decided in one place,
    /// [`Engine::forward`], which is reached only after this has authorized.
    ///
    /// The first of them is asked here as well, and deliberately: whether
    /// the detected firewall can redirect at all needs no privilege, no
    /// input and no read, so asking it before the authorization above saves
    /// a person an administrator password for an operation their machine
    /// was never going to perform. It is not enforced here -- `Engine::
    /// forward` asks the same question again, first, and that is the answer
    /// that binds.
    // Eight arguments, two of them the macro's own header and emitter. Each
    // of the six a client sends is a separate thing the helper has to be
    // told, and folding them into a struct would put a type on the wire in
    // place of the six plain arguments the interface publishes.
    #[allow(clippy::too_many_arguments)]
    async fn forward(
        &self,
        port: u16,
        protocol: &str,
        scope: &str,
        seconds: u32,
        published_port: u16,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<WireRule, HelperError> {
        // 1. Validate, in `open`'s own order and for its own reason: nothing
        // the client sent is trusted, and nothing is authorized until the
        // request is one the helper would have accepted from a person.
        if port == 0 {
            return Err(HelperError::InvalidArgument(
                "port 0 is not a port; valid ports are 1-65535".to_string(),
            ));
        }
        if published_port == 0 {
            return Err(HelperError::InvalidArgument(
                "port 0 is not a port; no container can have published it".to_string(),
            ));
        }
        let protocol = validate::parse_protocol(protocol).map_err(HelperError::from)?;
        let spec = validate::parse_scope(scope).map_err(HelperError::from)?;
        let lifetime = if seconds == 0 {
            Lifetime::UntilReboot
        } else {
            Lifetime::For(
                validate::parse_duration(&format!("{seconds}s")).map_err(HelperError::from)?,
            )
        };

        // 2. Resolve before authorizing, so the prompt names the target
        // porthole worked out rather than the word the client sent. Which
        // action to ask for does not depend on it -- what the resolution is
        // for here is the message a person reads.
        let runner = RealRunner;
        let target = resolve_scope(&runner, &spec).map_err(HelperError::from)?;
        let details = crate::polkit::forward_details(port, protocol, &target, published_port);

        // 3. Ask the firewall whether it can redirect at all -- before
        // authorizing, not after.
        //
        // `forward_capability` runs no command and reads nothing: the answer
        // is a property of the detected backend and of no input, so it is
        // already known here. On ufw and on nftables it is "no", and asking
        // it after the authorization below would charge a person an
        // administrator password -- `auth_admin`, every time, no `_keep` --
        // to be told their firewall was never going to do this. Worse than
        // the annoyance: it trains password entry for an operation that
        // could not have happened.
        //
        // This is a client-side saving of a prompt, not a check: the same
        // question is asked again inside `Engine::forward`, first and before
        // any read, and that is where the refusal is enforced. A caller that
        // somehow got past this one is refused there.
        //
        // The cost is that `backend::detect`'s two probe commands
        // (`firewall-cmd --version` and `--state`, or their ufw/nftables
        // equivalents) now run before authentication. They already do for an
        // unauthenticated caller: `status` is `Action::List`, which the
        // shipped policy declares `yes`, and it detects the backend the same
        // way. Scoped so the backend -- which is not `Send` -- is dropped
        // before the `.await` below.
        {
            let backend = backend::detect(&runner).map_err(HelperError::from)?;
            backend.forward_capability().map_err(HelperError::from)?;
        }

        // 4. Authorize, before anything acts.
        self.authorizer
            .check(Action::Forward, &details, &header)
            .await
            .map_err(HelperError::from)?;

        let uid = caller_uid(&self.bus, &header)
            .await
            .map_err(HelperError::from)?;

        // 5. Only now take the lock and act. Scoped for the three reasons
        // `open`'s own block is scoped: the `Engine` is not `Send`, the
        // exclusive lock is released before the announcement, and what
        // reconciliation dropped comes out separately from the result.
        let (forwarded, reconciled) = {
            let backend = backend::detect(&runner).map_err(HelperError::from)?;
            let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
            let mut engine = Engine::new(
                backend.as_ref(),
                &runner,
                &SYSTEM_CLOCK,
                state,
                self.executable.clone(),
            );
            let req = OpenRequest {
                port,
                protocol,
                target,
                lifetime,
            };
            let forwarded = engine.forward(&req, published_port, uid, &RealProcFs);
            (forwarded, engine.take_reconciled())
        };

        // 6 and 7. The journal, then the bus -- the same announcement an
        // `open` makes, from the same `ManagedRule`, which is what carries
        // the mapping a subscriber needs to tell the two apart.
        Self::announce_reconciled(Some(&emitter), &reconciled).await;
        let rule = forwarded.map_err(HelperError::from)?;
        Self::announce_open(&emitter, &rule).await;

        Ok(WireRule::from_rule(&rule))
    }

    async fn close(
        &self,
        port: u16,
        protocol: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<WireRule, HelperError> {
        let protocol = validate::parse_protocol(protocol).map_err(HelperError::from)?;
        self.authorizer
            .check(Action::Close, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        // The audit trail names who asked for *this* close, which is not
        // necessarily who opened the rule: `close` is `yes` in the polkit
        // policy, reachable by any local user with no prompt at all, which is
        // exactly why it is the one operation where recording the requester
        // matters most.
        let closed_by = caller_uid(&self.bus, &header)
            .await
            .map_err(HelperError::from)?;

        // Scoped so the `Engine` -- which borrows `&dyn CommandRunner` and
        // `&dyn Clock`, neither of them `Sync` -- is dropped before the
        // `.await` below: a zbus interface method's future has to be `Send`.
        // It also drops the exclusive state lock before the announcement
        // rather than after it, which is the right order regardless.
        //
        // The engine's own result and what its reconciliation dropped come
        // out separately, and the drops are announced first and
        // unconditionally: an operation that fails *because* the sweep just
        // dropped its rule is exactly the case where the drop most needs
        // saying (see `Engine::take_reconciled`).
        let (closed, reconciled) = {
            let runner = RealRunner;
            let backend = backend::detect(&runner).map_err(HelperError::from)?;
            let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
            let mut engine = Engine::new(
                backend.as_ref(),
                &runner,
                &SYSTEM_CLOCK,
                state,
                self.executable.clone(),
            );
            let closed = engine.close_by_port(port, protocol, false);
            (closed, engine.take_reconciled())
        };
        Self::announce_reconciled(Some(&emitter), &reconciled).await;
        let rule = closed.map_err(HelperError::from)?;
        Self::announce_close(&emitter, &rule, closed_by, CloseReason::Requested).await;
        Ok(WireRule::from_rule(&rule))
    }

    /// `from_timer` is a claim the client makes about itself, accepted rather
    /// than independently verified. It is safe to accept: the only thing it
    /// changes is (a) whether this close also tries to stop the very timer
    /// unit that is calling it, and (b) the `, expired` marker in the journal
    /// line below. A client that lies and says `true` when it is not the
    /// timer merely skips cancelling a timer that either does not exist or
    /// was going to fire and find nothing anyway; a client that lies and says
    /// `false` merely leaves a stray timer behind, which fires later, finds
    /// no such rule, and exits. Neither lie reaches the firewall, the state
    /// file, or authorization above.
    async fn close_by_id(
        &self,
        id: &str,
        from_timer: bool,
        forget: bool,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<WireRule, HelperError> {
        self.authorizer
            .check(Action::Close, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        let closed_by = caller_uid(&self.bus, &header)
            .await
            .map_err(HelperError::from)?;

        // Scoped so the `Engine` -- which borrows `&dyn CommandRunner` and
        // `&dyn Clock`, neither of them `Sync` -- is dropped before the
        // `.await` below: a zbus interface method's future has to be `Send`.
        // It also drops the exclusive state lock before the announcement
        // rather than after it, which is the right order regardless.
        //
        // The engine's own result and what its reconciliation dropped come
        // out separately, and the drops are announced first and
        // unconditionally: an operation that fails *because* the sweep just
        // dropped its rule is exactly the case where the drop most needs
        // saying (see `Engine::take_reconciled`).
        let (closed, reconciled) = {
            let runner = RealRunner;
            let backend = backend::detect(&runner).map_err(HelperError::from)?;
            let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
            let mut engine = Engine::new(
                backend.as_ref(),
                &runner,
                &SYSTEM_CLOCK,
                state,
                self.executable.clone(),
            );
            let closed = engine.close_by_id(id, from_timer, forget);
            (closed, engine.take_reconciled())
        };
        Self::announce_reconciled(Some(&emitter), &reconciled).await;
        let rule = closed.map_err(HelperError::from)?;
        // `forget` never touched any firewall -- `Engine::forget_rule`
        // refuses it for anything a real close could still reach -- so the
        // journal must not say "closed", which `format_close_log` always
        // does. A different, explicit line for a different, explicit action.
        //
        // And no `RuleClosed` either, for the same reason: none of the
        // reasons a `RuleClosed` can carry is true of a forget, and a
        // subscriber told "closed" would tell someone a port had stopped
        // being reachable when porthole did not touch any firewall and does
        // not know whether it did.
        //
        // The cost is real and is disclosed where the people who need it
        // read it: `porthole_core::ipc`'s own `rule_closed` doc says that a
        // rule can leave `list` with no `RuleClosed` behind it, so an agent
        // that keeps its view from signals alone would go on showing a
        // forgotten rule as open. Inventing a reason of its own, or reusing
        // `requested`, would trade that for a worse claim.
        if forget {
            Self::log_forget(&rule, closed_by);
        } else {
            let reason = if from_timer {
                CloseReason::Expired
            } else {
                CloseReason::Requested
            };
            Self::announce_close(&emitter, &rule, closed_by, reason).await;
        }
        Ok(WireRule::from_rule(&rule))
    }

    /// Returns what closed and, separately, the failures — so one stuck rule
    /// cannot hide the others.
    async fn close_all(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(Vec<WireRule>, Vec<WireError>), HelperError> {
        self.authorizer
            .check(Action::Close, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        let closed_by = caller_uid(&self.bus, &header)
            .await
            .map_err(HelperError::from)?;

        // Scoped so the `Engine` -- which borrows `&dyn CommandRunner` and
        // `&dyn Clock`, neither of them `Sync` -- is dropped before the
        // `.await` below: a zbus interface method's future has to be `Send`.
        // It also drops the exclusive state lock before the announcement
        // rather than after it, which is the right order regardless.
        //
        // The engine's own result and what its reconciliation dropped come
        // out separately, and the drops are announced first and
        // unconditionally: an operation that fails *because* the sweep just
        // dropped its rule is exactly the case where the drop most needs
        // saying (see `Engine::take_reconciled`).
        let (closed, errors, reconciled) = {
            let runner = RealRunner;
            let backend = backend::detect(&runner).map_err(HelperError::from)?;
            let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
            let mut engine = Engine::new(
                backend.as_ref(),
                &runner,
                &SYSTEM_CLOCK,
                state,
                self.executable.clone(),
            );
            // `close --all` is never what the expiry timer invokes -- it
            // always closes a single rule by id -- so there is no
            // `from_timer` to thread through here.
            let (closed, errors) = engine.close_all(false);
            (closed, errors, engine.take_reconciled())
        };
        Self::announce_reconciled(Some(&emitter), &reconciled).await;
        for rule in &closed {
            Self::announce_close(&emitter, rule, closed_by, CloseReason::Requested).await;
        }
        Ok((
            closed.iter().map(WireRule::from_rule).collect(),
            // Structured, not `.to_string()`'d away: a script must not be
            // able to tell a `close --all` failure over the bus apart from
            // the same failure reported locally, and a bare string discards
            // exactly the `kind` and exit code that comparison needs.
            errors
                .iter()
                .map(|e| WireError {
                    message: e.to_string(),
                    kind: e.kind().to_string(),
                    code: e.exit_code() as i32,
                })
                .collect(),
        ))
    }

    async fn list(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Vec<WireRule>, HelperError> {
        self.authorizer
            .check(Action::List, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;
        // Read-only: the plain constructor, so a reader never blocks behind a
        // writer and never creates the state directory.
        let state = StateStore::open(&self.state_path).map_err(HelperError::from)?;
        Ok(state.rules().iter().map(WireRule::from_rule).collect())
    }

    async fn status(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<WireStatus, HelperError> {
        self.authorizer
            .check(Action::List, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        // Mirrors `porthole-cli`'s own `run.rs::Commands::Status` handling,
        // which a prior review already fixed this same collapse in: a
        // backend that could not be *detected* at all (a machine with no
        // firewall installed is the common case, but not the only one) is a
        // different, confirmed fact from one that was detected but could not
        // be *read* (`BackendHealth::active_unknown`'s own case) -- and it
        // must reach the wire as that fact, not as a bare method error. Left
        // as a `?` propagating through `HelperError`, this `detect` failure
        // became indistinguishable, on every client, from "the helper itself
        // could not be reached" -- exactly the collapse the GUI's own
        // `StatusBar` was caught rendering: a confirmed "no firewall" status,
        // wrapped in "could not reach the porthole helper". Synthesizing a
        // `Status` here, the same shape `run.rs` already does locally, means
        // every client -- this GUI and any future one -- renders the real
        // fact instead of each rediscovering the trap.
        let status = match backend::detect(&runner) {
            Ok(backend) => {
                // Read-only open: `Engine::status` reconciles read-only
                // (`SweepMode::ReadOnly`), so it never saves and never
                // touches the firewall -- see `reconcile.rs`. status must
                // not block behind a writer either, which is the other
                // reason this is the plain, non-exclusive open.
                let state = StateStore::open(&self.state_path).map_err(HelperError::from)?;
                let mut engine = Engine::new(
                    backend.as_ref(),
                    &runner,
                    &SYSTEM_CLOCK,
                    state,
                    self.executable.clone(),
                );
                engine.status().map_err(HelperError::from)?
            }
            Err(e) => status_for_undetected_backend(
                &e,
                net::current_network(&runner).ok(),
                StateStore::open(&self.state_path)
                    .map_err(HelperError::from)?
                    .rules()
                    .to_vec(),
            ),
        };
        Ok(WireStatus::from_status(&status))
    }

    /// Every port Docker currently has published, read from the `DOCKER`
    /// chain in the `nat` table -- see `porthole_core::docker`'s own module
    /// doc for why this needs to live behind the helper at all: reading the
    /// `nat` table needs root, which an unprivileged CLI process does not
    /// have. Gated on `Action::List`, exactly as unprivileged a read as
    /// `list`/`status` already are -- there is nothing here a caller could
    /// use to change anything.
    async fn docker_ports(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Vec<WireDockerPort>, HelperError> {
        self.authorizer
            .check(Action::List, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        let published = porthole_core::docker::published(&runner).map_err(HelperError::from)?;
        Ok(published
            .iter()
            .map(WireDockerPort::from_published)
            .collect())
    }

    /// The contract this helper speaks, so a client can tell which of the
    /// two of them is the older half.
    ///
    /// **No authorization, deliberately.** Charging a person an
    /// administrator password to find out whether their own two binaries
    /// match would be absurd, and the answer is not a secret: it is a
    /// compile-time constant of a package anyone can read, and every client
    /// on the machine already gets `list` for the asking. It is also the one
    /// call that must work when nothing else on this interface does -- a
    /// client that cannot read a `WireRule` still has to be able to read
    /// this -- so it takes no arguments, returns `u`, and touches nothing:
    /// no state file, no firewall, no lock, no polkit.
    ///
    /// The helper checks no versions of its own. It is the authority; it
    /// answers, and the clients decide.
    async fn protocol_version(&self) -> u32 {
        porthole_core::ipc::PROTOCOL_VERSION
    }

    // --- Signals ---------------------------------------------------------
    //
    // Broadcast, so nothing here may carry anything a bystander should not
    // see. `WireRule` is exactly what `list` already returns to every local
    // user (the polkit `list` action is `yes` for everyone), and it is the
    // wire type precisely because it leaves the `RuleHandle` -- the spec that
    // would let a caller remove a rule it never created -- on this side of
    // the bus. It does carry the opening uid, which is what lets an agent
    // decide whether a notification is for the person looking at the screen.

    /// The rule the helper just created -- not the request it came from.
    /// The id, the resolved target and the expiry are all decided here.
    #[zbus(signal)]
    async fn rule_opened(emitter: &SignalEmitter<'_>, rule: WireRule) -> zbus::Result<()>;

    /// A rule that has stopped being open, and why.
    #[zbus(signal)]
    async fn rule_closed(
        emitter: &SignalEmitter<'_>,
        rule: WireRule,
        reason: CloseReason,
    ) -> zbus::Result<()>;

    /// The machine's own subnet changed. Both CIDRs are empty for "no usable
    /// network" -- D-Bus has no optional types. Emitted by
    /// [`crate::netmon`], which is the only thing that looks.
    #[zbus(signal)]
    async fn network_changed(
        emitter: &SignalEmitter<'_>,
        old_cidr: &str,
        new_cidr: &str,
    ) -> zbus::Result<()>;
}

impl Porthole {
    /// The journal line and the `RuleOpened` signal, in that order.
    ///
    /// One function rather than two statements at the call site, for the same
    /// reason [`Porthole::announce_close`] is: an announcement that only half
    /// happened is the failure this whole task exists to prevent.
    pub async fn announce_open(
        emitter: &SignalEmitter<'_>,
        rule: &porthole_core::state::ManagedRule,
    ) {
        // The helper is a system service, so stderr lands in the journal.
        eprintln!("{}", format_open_log(rule));
        if let Err(e) = Self::rule_opened(emitter, WireRule::from_rule(rule)).await {
            // The rule is open and recorded either way; a bus that would not
            // take the announcement is not a reason to fail the request or to
            // leave the port open with no record of it.
            eprintln!("porthole: could not announce the open on the bus, continuing: {e}");
        }
    }

    /// The journal line and the `RuleClosed` signal, in that order.
    ///
    /// `closed_by` is the uid that asked for *this* close — not necessarily
    /// `rule.uid`, since any local user may close any rule. `reason` is the
    /// single value both halves are built from: milestone 1's `from_timer`
    /// flag was the only distinction the journal line could make, and
    /// [`CloseReason`] supersedes it, so the marker in the journal and the
    /// slug on the bus cannot say different things about the same close.
    pub async fn announce_close(
        emitter: &SignalEmitter<'_>,
        rule: &porthole_core::state::ManagedRule,
        closed_by: u32,
        reason: CloseReason,
    ) {
        eprintln!("{}", format_close_log(rule, closed_by, reason));
        if let Err(e) = Self::rule_closed(emitter, WireRule::from_rule(rule), reason).await {
            eprintln!("porthole: could not announce the close on the bus, continuing: {e}");
        }
    }

    /// A close nobody asked for: the journal line and the `RuleClosed`
    /// signal, in that order, for the two paths where there is no requesting
    /// uid to name -- [`crate::netmon`]'s network-change closes and the
    /// start-up reconciliation sweep.
    ///
    /// Separate from [`Porthole::announce_close`] because that line's
    /// "closed by uid=" would have to invent a requester for a close no
    /// client ever made.
    ///
    /// `emitter` is `None` when `SignalEmitter::new` failed. The journal line
    /// is the audit trail and is written either way, which is why the
    /// `Option` lives in here rather than at the call sites: there is no
    /// arrangement of them that can log without announcing or announce
    /// without logging.
    pub async fn announce_autoclose(
        emitter: Option<&SignalEmitter<'_>>,
        rule: &porthole_core::state::ManagedRule,
        reason: CloseReason,
    ) {
        eprintln!("{}", format_autoclose_log(rule, reason));
        let Some(emitter) = emitter else { return };
        if let Err(e) = Self::rule_closed(emitter, WireRule::from_rule(rule), reason).await {
            eprintln!("porthole: could not announce the close on the bus, continuing: {e}");
        }
    }

    /// Every record reconciliation dropped from state, announced as
    /// [`CloseReason::Reconciled`].
    ///
    /// One function for all of them -- the helper's start-up sweep, every
    /// interface method's own per-operation sweep, and the network monitor's
    /// -- so `Reconciled` means the same thing and reads the same way
    /// wherever it comes from. Usually empty, and cheap when it is.
    pub async fn announce_reconciled(
        emitter: Option<&SignalEmitter<'_>>,
        rules: &[porthole_core::state::ManagedRule],
    ) {
        for rule in rules {
            Self::announce_autoclose(emitter, rule, CloseReason::Reconciled).await;
        }
    }

    /// [`Porthole::network_changed`] for callers outside an interface method
    /// -- [`crate::netmon`], which is the only thing that ever looks at the
    /// network on its own. Empty string for "no usable network"; see the
    /// signal's own declaration.
    pub async fn announce_network_change(
        emitter: &SignalEmitter<'_>,
        old_cidr: &str,
        new_cidr: &str,
    ) {
        if let Err(e) = Self::network_changed(emitter, old_cidr, new_cidr).await {
            eprintln!(
                "porthole: could not announce the network change on the bus, continuing: {e}"
            );
        }
    }

    /// The `--forget` audit line: distinct from [`Porthole::log_close`]
    /// because nothing was closed -- `Engine::forget_rule` only ever runs
    /// for a rule recorded under a backend this machine no longer has, and
    /// removes porthole's own record of it without touching any firewall.
    fn log_forget(rule: &porthole_core::state::ManagedRule, forgotten_by: u32) {
        eprintln!("{}", format_forget_log(rule, forgotten_by));
    }
}

/// The `Status` a `detect` failure becomes on the wire -- split out from
/// [`Porthole::status`] so this mapping is testable without a real bus, a
/// real backend, or root (`tests/service.rs`'s own end-to-end suite runs
/// against whatever firewall this machine actually has, which cannot be
/// made to fail `detect` on demand). `error` is `detect`'s own error,
/// verbatim, as `BackendHealth::detail` -- never reworded, and never
/// silently reaching a client as "could not reach the helper": see
/// [`Porthole::status`]'s own comment for the collapse this exists to
/// avoid. `network` and `rules` are supplied by the caller rather than
/// looked up here, since neither depends on whether a backend was
/// detected -- the network probe and the state file are both independent
/// of that.
fn status_for_undetected_backend(
    error: &Error,
    network: Option<porthole_core::net::LocalNetwork>,
    rules: Vec<porthole_core::state::ManagedRule>,
) -> Status {
    Status {
        backend: BackendId::Firewalld,
        health: BackendHealth {
            available: false,
            active: false,
            // A backend that could not even be detected is not the same
            // fact as one that was detected and could not be read -- see
            // `active_unknown`'s own doc comment. `detect` failing this
            // way means no backend was ever available to ask, so there is
            // nothing left unresolved to call "unknown".
            active_unknown: false,
            version: None,
            detail: error.to_string(),
            caveat: None,
        },
        network,
        location: None,
        rules,
    }
}

/// The clause every journal line about a rule ends with when that rule was a
/// forward, and the empty string when it was an ordinary open.
///
/// A forward and an open are one line otherwise, and the audit trail is the
/// place that can least afford to describe one as the other: what answers on
/// the port is a container, and the mapping names which one. Only the
/// redirect's own detail is appended, so the line an `open` writes is the
/// line it always wrote.
///
/// **One clause, four lines.** It was written inline in [`format_open_log`]
/// while [`format_close_log`], [`format_autoclose_log`] and
/// [`format_forget_log`] said nothing, which is how an administrator came to
/// read a redirect open and a plain port close for the same rule. It is one
/// function rather than four matches for the reason `porthole-agent`'s
/// `subject` and `porthole-gui`'s `anyone_note` are each one function: more
/// than one wording of a single distinction is more than one thing that can
/// go stale separately.
///
/// It claims only what the rule was and where the traffic went. On firewalld
/// a forward is that one `forward-port` rich rule and nothing else -- there
/// is deliberately no accompanying accept, since writing one would expose the
/// *host's* own port on that number too (`docs/backends.md`) -- so this says
/// nothing about what else was written, because nothing else was.
///
/// Not [`porthole_core::ipc::WireRule::redirects`]: that predicate reads the
/// empty-`container_addr` sentinel the *wire* type carries, and nothing here
/// holds a `WireRule`. On a [`ManagedRule`](porthole_core::state::ManagedRule)
/// the same question is the typed `Option` this destructures, whose payload
/// the clause needs anyway.
fn forward_note(rule: &porthole_core::state::ManagedRule) -> String {
    match &rule.forward {
        Some(to) => format!(
            " -- redirected to {}:{}, published on this machine as {}",
            to.container_addr, to.container_port, to.published_port
        ),
        None => String::new(),
    }
}

/// Split out from [`Porthole::log_forget`] for the reason the other three
/// are, and carrying [`forward_note`] for the reason they do.
///
/// This is the one line here that describes a rule which is still in the
/// firewall: `--forget` drops porthole's record and touches nothing, which
/// the line already says. What that leaves is therefore not a permitted port
/// but a live redirect into a container that porthole has stopped tracking,
/// and the clause is what says which.
fn format_forget_log(rule: &porthole_core::state::ManagedRule, forgotten_by: u32) -> String {
    format!(
        "porthole: forgot {}/{} towards {} (recorded under backend {}, opened by uid={}, \
         forgotten by uid={}) -- no firewall was touched{}",
        rule.port,
        rule.protocol,
        rule.target,
        rule.backend,
        rule.uid,
        forgotten_by,
        forward_note(rule)
    )
}

/// Split out from [`Porthole::announce_open`] so the line itself is testable
/// without capturing stderr from a live process.
fn format_open_log(rule: &porthole_core::state::ManagedRule) -> String {
    format!(
        "porthole: uid={} opened {}/{} towards {} until {}{}",
        rule.uid,
        rule.port,
        rule.protocol,
        rule.target,
        rule.expires_at
            .map(|t| t.to_string())
            .unwrap_or_else(|| "reboot".to_string()),
        forward_note(rule)
    )
}

/// The journal line for a close nobody asked for -- see
/// [`Porthole::announce_autoclose`]. Split out for the same reason
/// [`format_close_log`] is.
///
/// `Reconciled` gets its own sentence rather than the "closed" one: nothing
/// was removed from any firewall for it. The firewall had already stopped
/// holding the rule by the time porthole looked, and all porthole did was
/// notice and drop its own record -- saying "closed" would claim porthole
/// did something it did not do, and would date the close to the moment of
/// the sweep rather than to whenever the rule actually vanished.
///
/// [`forward_note`] is appended to *both* sentences, and so to every reason
/// this handles. These are the closes porthole performs on its own -- an
/// expiry, a network change, a container that is no longer the one the rule
/// was created against, a record reconciliation dropped -- so they are
/// precisely the ones for which the journal is the only account anybody will
/// ever read: nobody was at a terminal to be told.
fn format_autoclose_log(rule: &porthole_core::state::ManagedRule, reason: CloseReason) -> String {
    match reason {
        CloseReason::Reconciled => format!(
            "porthole: dropped {}/{} towards {} from state (opened by uid={}) -- the firewall \
             no longer had it, {reason}{}",
            rule.port,
            rule.protocol,
            rule.target,
            rule.uid,
            forward_note(rule)
        ),
        _ => format!(
            "porthole: closed {}/{} towards {} (opened by uid={}) -- porthole closed this \
             itself, nobody asked, {reason}{}",
            rule.port,
            rule.protocol,
            rule.target,
            rule.uid,
            forward_note(rule)
        ),
    }
}

/// Split out from [`Porthole::announce_close`] so the line itself is testable
/// without capturing stderr from a live process.
///
/// The reason marker is [`CloseReason::as_str`] for every reason except
/// `Requested`, which is the unremarkable case and stays bare exactly as it
/// read before reason codes existed. It is the *same value* the `RuleClosed`
/// signal carries, so the journal and the bus cannot disagree about what a
/// close was -- which they could while `from_timer: bool` was the only thing
/// either had to go on.
///
/// The marker ends the line for an ordinary open and is followed by
/// [`forward_note`] for a forward, the same place and the same words
/// [`format_open_log`] puts it. A close that named neither read byte for byte
/// like an ordinary open ending, so the journal showed a redirect being
/// opened and a plain port being closed for one and the same rule.
fn format_close_log(
    rule: &porthole_core::state::ManagedRule,
    closed_by: u32,
    reason: CloseReason,
) -> String {
    format!(
        "porthole: closed {}/{} towards {} (opened by uid={}, closed by uid={}){}{}",
        rule.port,
        rule.protocol,
        rule.target,
        rule.uid,
        closed_by,
        match reason {
            CloseReason::Requested => String::new(),
            other => format!(", {other}"),
        },
        forward_note(rule)
    )
}

// `Box<dyn Authorizer>` from an Arc, so tests can keep a handle on what the
// authorizer was asked while the service owns it.
#[async_trait::async_trait]
impl Authorizer for std::sync::Arc<crate::authz::AlwaysAllow> {
    async fn check(
        &self,
        action: Action,
        details: &crate::authz::Details,
        header: &zbus::message::Header<'_>,
    ) -> Result<(), Error> {
        (**self).check(action, details, header).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::backend::{BackendId, RuleHandle};
    use porthole_core::model::{Protocol, Target};
    use porthole_core::state::ManagedRule;

    fn rule(opener_uid: u32) -> ManagedRule {
        ManagedRule {
            id: "abc".to_string(),
            port: 5173,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            backend: BackendId::Firewalld,
            opened_at: 1_757_000_000,
            expires_at: None,
            uid: opener_uid,
            handle: RuleHandle::Firewalld {
                zone: "FedoraWorkstation".to_string(),
                rich_rule: "rule ...".to_string(),
            },
            forward: None,
        }
    }

    /// The same rule, opened as a forward instead of an open. The mapping is
    /// [`the_open_line_says_when_what_it_opened_was_a_redirect`]'s, so every
    /// line built from it below is describing one and the same rule.
    fn forwarding_rule(opener_uid: u32) -> ManagedRule {
        let mut r = rule(opener_uid);
        r.forward = Some(porthole_core::forward::ForwardTo {
            container_addr: "172.18.0.2".parse().unwrap(),
            container_port: 80,
            published_port: 3000,
            protocol: Protocol::Tcp,
        });
        r
    }

    /// Every variant, listed here rather than iterated from the enum so that
    /// a reason added to the wire has to be added here by hand and cannot
    /// join the journal untested.
    ///
    /// `Requested` never reaches `format_autoclose_log` in practice --
    /// `close` sends it to [`format_close_log`], and `announce_autoclose`'s
    /// three callers send `NetworkChanged`, `TargetGone` and `Reconciled`.
    /// It is exercised there anyway because that function's `_` arm is total
    /// over the enum, and an arm no test enters is an arm that can lose the
    /// clause without anything noticing.
    const EVERY_REASON: [CloseReason; 5] = [
        CloseReason::Expired,
        CloseReason::Requested,
        CloseReason::NetworkChanged,
        CloseReason::Reconciled,
        CloseReason::TargetGone,
    ];

    #[test]
    fn the_close_line_names_both_uids_when_they_differ() {
        // I1: `close`, `close_by_id` and `close_all` must all log who *asked*
        // for the close, separately from who *opened* the rule — a test
        // where the two happen to be the same value would pass even if the
        // closer's uid were never wired in at all.
        let line = format_close_log(&rule(1000), 1001, CloseReason::Requested);
        assert!(line.contains("opened by uid=1000"), "got: {line}");
        assert!(line.contains("closed by uid=1001"), "got: {line}");
    }

    #[test]
    fn a_timer_triggered_close_carries_the_expired_marker() {
        // Milestone 1 added `, expired` so a close the timer fired reads
        // differently in the journal from one a person asked for. I2 wires
        // `from_timer` back across the bus so this survives the move to the
        // helper.
        let line = format_close_log(&rule(1000), 1000, CloseReason::Expired);
        assert!(line.ends_with(", expired"), "got: {line}");
    }

    #[test]
    fn a_human_initiated_close_carries_no_expired_marker() {
        let line = format_close_log(&rule(1000), 1000, CloseReason::Requested);
        assert!(!line.contains("expired"), "got: {line}");
    }

    #[test]
    fn the_journal_marker_is_the_same_slug_the_signal_carries() {
        // The whole point of `announce_close` taking one `CloseReason` is
        // that the line a person reads in the journal and the string an
        // agent matches on cannot describe the same close differently.
        // `Requested` is the deliberate exception: it is the unremarkable
        // case and stays bare, exactly as it read before reason codes
        // existed.
        for reason in [
            CloseReason::Expired,
            CloseReason::NetworkChanged,
            CloseReason::Reconciled,
        ] {
            let line = format_close_log(&rule(1000), 0, reason);
            assert!(
                line.ends_with(&format!(", {}", reason.as_str())),
                "{reason:?} logged as: {line}"
            );
        }
        assert!(
            !format_close_log(&rule(1000), 0, CloseReason::Requested).contains("requested"),
            "an ordinary close keeps the bare line it always had"
        );
    }

    #[test]
    fn a_close_nobody_asked_for_names_no_requester() {
        // `format_close_log`'s "closed by uid=" would have to invent one.
        // Both lines still name who *opened* the rule, which is the uid a
        // person reading the journal actually needs.
        let line = format_autoclose_log(&rule(1000), CloseReason::NetworkChanged);
        assert!(line.contains("opened by uid=1000"), "got: {line}");
        assert!(!line.contains("closed by uid"), "got: {line}");
        assert!(line.contains("nobody asked"), "got: {line}");
        assert!(line.ends_with("network-changed"), "got: {line}");
    }

    #[test]
    fn reconciliation_does_not_log_a_close_it_did_not_perform() {
        // The firewall had already stopped holding the rule; porthole found
        // its own record of it and dropped the record. Saying "closed" would
        // claim porthole did something it did not do, and would date the
        // close to the sweep rather than to whenever the rule vanished.
        let line = format_autoclose_log(&rule(1000), CloseReason::Reconciled);
        assert!(!line.contains("closed"), "got: {line}");
        assert!(
            line.contains("the firewall no longer had it"),
            "got: {line}"
        );
        assert!(line.ends_with("reconciled"), "got: {line}");
    }

    #[test]
    fn the_open_line_says_what_the_helper_decided_not_what_was_asked_for() {
        // The expiry in the journal is the absolute time the helper chose,
        // never the duration a client sent -- the same distinction
        // `RuleOpened` carries, built from the same `ManagedRule`.
        let mut r = rule(1000);
        r.expires_at = Some(1_757_003_600);
        let line = format_open_log(&r);
        assert!(line.contains("uid=1000 opened 5173/tcp"), "got: {line}");
        assert!(line.contains("towards 10.10.10.0/24"), "got: {line}");
        assert!(line.ends_with("until 1757003600"), "got: {line}");
        assert!(
            format_open_log(&rule(1000)).ends_with("until reboot"),
            "got: {}",
            format_open_log(&rule(1000))
        );
    }

    #[test]
    fn the_open_line_says_when_what_it_opened_was_a_redirect() {
        // Both lines start the same way, so a journal read for "opened
        // 5173/tcp" finds either. What follows is the difference: an open
        // permits whatever on this machine already answers there, and a
        // forward sends that port to a container instead. An audit trail
        // that recorded them identically could not be used to tell which
        // one happened.
        let mut r = rule(1000);
        r.forward = Some(porthole_core::forward::ForwardTo {
            container_addr: "172.18.0.2".parse().unwrap(),
            container_port: 80,
            published_port: 3000,
            protocol: Protocol::Tcp,
        });
        let line = format_open_log(&r);
        assert!(line.contains("redirected to 172.18.0.2:80"), "got: {line}");
        assert!(
            line.contains("published on this machine as 3000"),
            "got: {line}"
        );
        assert!(
            !format_open_log(&rule(1000)).contains("redirected"),
            "an open keeps the line it always had"
        );
    }

    #[test]
    fn a_close_of_a_redirect_says_so_whoever_asked_and_whatever_the_reason() {
        // The defect the owner found on first real use: the open line named
        // the redirect and the close line was byte for byte how an ordinary
        // `open` being closed reads. An administrator reading the journal saw
        // a redirect open and a plain port close, for one and the same rule.
        for reason in EVERY_REASON {
            let line = format_close_log(&forwarding_rule(1000), 1001, reason);
            assert!(
                line.contains("redirected to 172.18.0.2:80"),
                "{reason:?} closed as: {line}"
            );
            assert!(
                line.contains("published on this machine as 3000"),
                "{reason:?} must name which redirect ended: {line}"
            );
            // The control that makes the assertions above mean something:
            // an ordinary open must still write the line it always wrote.
            let plain = format_close_log(&rule(1000), 1001, reason);
            assert!(
                !plain.contains("redirect"),
                "{reason:?}: a rule that only permitted must claim no redirect: {plain}"
            );
        }
    }

    #[test]
    fn a_close_nobody_asked_for_says_when_the_rule_was_a_redirect() {
        // The worse half of the same defect. These are the closes porthole
        // performs on its own -- an expiry, a network change, a container
        // that moved, a record reconciliation dropped -- so nobody was at a
        // terminal to be told, and this line is the whole account.
        for reason in EVERY_REASON {
            let line = format_autoclose_log(&forwarding_rule(1000), reason);
            assert!(
                line.contains("redirected to 172.18.0.2:80"),
                "{reason:?} logged as: {line}"
            );
            assert!(
                line.contains("published on this machine as 3000"),
                "{reason:?} must name which redirect ended: {line}"
            );
            let plain = format_autoclose_log(&rule(1000), reason);
            assert!(
                !plain.contains("redirect"),
                "{reason:?}: a rule that only permitted must claim no redirect: {plain}"
            );
        }
    }

    #[test]
    fn a_close_says_the_redirect_in_the_open_lines_own_words() {
        // Four wordings of one distinction are four things that can go stale
        // separately -- the reason `porthole-agent`'s `subject` is one
        // function. This pins the journal's own four: whatever clause the
        // open line ends with, the close, autoclose and forget lines end with
        // that same one, so a further phrasing cannot be introduced in any of
        // them without failing here.
        let forward = forwarding_rule(1000);
        let opened = format_open_log(&forward);
        let clause = opened
            .find(" -- redirected to")
            .map(|i| &opened[i..])
            .unwrap_or_else(|| panic!("the open line stopped naming the redirect: {opened}"));

        for reason in EVERY_REASON {
            let closed = format_close_log(&forward, 1000, reason);
            assert!(
                closed.ends_with(clause),
                "{reason:?}: close says {closed:?}, open says {clause:?}"
            );
            let auto = format_autoclose_log(&forward, reason);
            assert!(
                auto.ends_with(clause),
                "{reason:?}: autoclose says {auto:?}, open says {clause:?}"
            );
        }
        let forgotten = format_forget_log(&forward, 1000);
        assert!(
            forgotten.ends_with(clause),
            "forget says {forgotten:?}, open says {clause:?}"
        );
    }

    #[test]
    fn a_forgotten_forward_says_what_the_firewall_was_left_holding() {
        // `--forget` drops porthole's record and touches no firewall, so
        // unlike every other line here the rule this one describes is still
        // in the ruleset. "forgot 5173/tcp towards 10.10.10.0/24" alone tells
        // an administrator a port was left permitted; what was really left is
        // a live redirect into a container that porthole has stopped tracking.
        let line = format_forget_log(&forwarding_rule(1000), 1001);
        assert!(line.contains("forgotten by uid=1001"), "got: {line}");
        assert!(line.contains("no firewall was touched"), "got: {line}");
        assert!(line.contains("redirected to 172.18.0.2:80"), "got: {line}");
        assert!(
            line.contains("published on this machine as 3000"),
            "got: {line}"
        );
        let plain = format_forget_log(&rule(1000), 1001);
        assert!(
            !plain.contains("redirect"),
            "a rule that only permitted keeps the line it always had: {plain}"
        );
        assert!(plain.ends_with("no firewall was touched"), "got: {plain}");
    }

    #[test]
    fn the_reason_a_forward_closed_for_is_still_in_its_line() {
        // The redirect clause goes after the reason marker, so the marker is
        // no longer the last thing on the line for a forward. It must still
        // be *on* it: `TargetGone` is the reason that only a forward can ever
        // carry, and a line that dropped it would say a redirect ended
        // without saying it was the container that went.
        for reason in EVERY_REASON {
            let auto = format_autoclose_log(&forwarding_rule(1000), reason);
            assert!(
                auto.contains(&format!(", {}", reason.as_str())),
                "{reason:?} lost its marker: {auto}"
            );
        }
        assert!(
            format_close_log(&forwarding_rule(1000), 1000, CloseReason::TargetGone)
                .contains(", target-gone"),
            "`format_close_log` must carry the marker too, before the clause"
        );
        assert!(
            !format_close_log(&forwarding_rule(1000), 1000, CloseReason::Requested)
                .contains("requested"),
            "and `Requested` stays bare on a forward exactly as on an open"
        );
    }

    #[test]
    fn an_undetected_backend_reports_as_no_firewall_not_as_a_bare_error() {
        // C1: `Porthole::status` used to `?`-propagate a `detect` failure
        // straight through `HelperError`, indistinguishable, on the one
        // client that exists today (the GUI), from "the helper itself
        // could not be reached" -- a confirmed "no firewall" collapsed into
        // an absence of information, the milestone-3 defect run backwards.
        let error = Error::BackendUnavailable(
            "no firewall found: none of firewalld, ufw or nftables is installed. \
             Without a firewall this port is already reachable from your network."
                .to_string(),
        );
        let status = status_for_undetected_backend(&error, None, Vec::new());
        assert!(
            !status.health.available,
            "a detect failure must report available: false"
        );
        assert!(!status.health.active);
        assert!(
            !status.health.active_unknown,
            "no backend was ever available to ask, so there is nothing left unresolved to \
             call \"unknown\""
        );
        assert!(
            status.health.detail.contains("already reachable"),
            "detect's own message must survive verbatim, not be reworded: {}",
            status.health.detail
        );

        // The fact this whole change exists to put on the wire correctly:
        // `firewall_available: false`, not a bare method error a client
        // could fold into "could not reach the helper at all".
        let wire = WireStatus::from_status(&status);
        assert!(!wire.firewall_available);
        assert!(
            wire.firewall_version.is_empty(),
            "no version was ever read for a backend that was never detected"
        );
    }
}
