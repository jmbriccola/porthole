//! Ending a root daemon that otherwise never ends.
//!
//! `porthole-helper` is D-Bus activated and has no `Restart=`. Once a client
//! addresses the bus name, the process stays up until something kills it --
//! so on a machine where somebody opened a port last month, a **root** daemon
//! is still running with nothing to do. Three packaging scriptlets exist for
//! no other reason than to end it across an upgrade, and none of them touches
//! the ordinary case: a helper activated once and left alive for weeks with no
//! rule open.
//!
//! With **zero rules the helper has nothing to do**, and that is measured
//! rather than argued. The only long-lived task in the process is
//! [`crate::netmon`], and with an empty state file its wake-up returns before
//! detecting a backend and before a single `ip` runs, clearing the subnet it
//! tracked on the way out. The state file is written temp-file-plus-rename per
//! operation, so nothing is buffered in memory. And a rule's automatic close
//! does not live here at all: it is a systemd transient timer outside this
//! process (`porthole_core::expiry`), which is why it still fires with the
//! helper stopped.
//!
//! **Never with a rule open.** The network monitor is needed then, and there
//! is no arrangement of the code below that can retire while the state file
//! holds anything -- but the lock is only half of why. The lock covers the
//! `in_flight`/`retiring` pair: [`Retirement::claim`] and
//! [`Retirement::admit`] read and write it under one `std::sync::Mutex`, so a
//! request cannot be admitted after the decision and the decision cannot be
//! taken while a request is executing. Whether the state file is *empty* is
//! read outside that lock, on a blocking thread, and what closes that gap is
//! an argument about who can write to the file rather than a lock over it:
//! see [`Retirement::claim`]'s own doc comment, which carries it.
//!
//! # The sequence, and why the obvious one is wrong
//!
//! *Release the name, then exit* is wrong twice, and the second way would
//! have introduced a new silent failure. Both were measured
//! (`.superpowers/sdd/2026-09-07-docker-forward/spike-helper-idle-exit.md`):
//!
//! 1. **systemd sends `SIGTERM` 40 microseconds after a `Type=dbus` unit
//!    releases its `BusName`.** The helper handled only `SIGINT`, so any drain
//!    would have been killed before it began. `main` now handles `SIGTERM`
//!    too, and asks [`Retirement::is_retiring`] whether this particular one is
//!    systemd acknowledging a retirement in progress.
//! 2. **After `ReleaseName`, every signal this instance emits is silently
//!    dropped** for every subscriber, because the bus resolves
//!    `sender=com.jacopobriccola.Porthole` to the *current* owner -- and
//!    matching on the well-known name is exactly how `porthole-agent` and
//!    `porthole-gui` subscribe. An `open` served during the drain would return
//!    a rule to its caller and emit a `RuleOpened` that nobody would ever see:
//!    a port opening with nothing announcing it.
//!
//! So the drain here **refuses** rather than serves. From the instant the
//! decision is taken -- atomically with "nothing is in flight", so there is no
//! window -- every interface method answers
//! [`crate::error::HelperError::Retiring`] instead of acting. That makes both
//! hazards impossible by construction rather than improbable by measurement:
//! no signal is emitted after the release because nothing acts after the
//! decision, and no rule can be opened by a process that is about to exit.
//!
//! The refusal is answered only once the name is really gone, so the client's
//! retry cannot land back on this instance: by the time anything is told to
//! ask again, this instance no longer owns the name it would ask. That is why
//! a `ReleaseName` that *fails* answers nothing at all -- the requests it was
//! holding lose their replies instead, which their callers retry just the
//! same, against a name this process is no longer there to own.
//!
//! Every porthole client retries once on that refusal, through the one
//! function all three of them call
//! (`porthole_core::ipc::once_more_if_worth_asking_again`), which is what
//! makes the whole arrangement robust rather than delicate -- and which is a
//! defect fixed in its own right, since the same retry covers a helper killed
//! by a package upgrade. It began in `porthole-cli` alone, and while it was
//! there alone the other two each got this refusal wrong in a way of their
//! own: `porthole-agent` reported a helper it could not reach, and
//! `porthole-gui` reported one that had answered with an error. Measured: a
//! caller arriving *before* the release is served; one arriving between
//! release and exit is served by a fresh instance the bus activates in
//! 22-31 ms; one arriving after exit likewise. The only fragile point was the
//! request already in flight, and refusing it is what removes the fragility.
//!
//! A refusal that is actually sent says so in the journal -- see
//! [`Retirement::admit`], which is where the one thing this process does *to*
//! a client without otherwise recording it stopped being unrecorded.
//!
//! # What this does not fix
//!
//! An `open --until-reboot` still pins the helper for the life of the boot,
//! by design: there is a rule open, so the monitor is needed. The complaint
//! this answers is the machine where that port has *since* closed.

use crate::error::HelperError;
use porthole_core::ipc::SERVICE;
use porthole_core::state::StateStore;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// How long the helper stays up with nothing open before it retires.
///
/// **Five minutes.** A cold activation was measured at 642 ms in a container
/// -- ~515 ms of it firewalld's Python CLI, run by the start-up
/// reconciliation sweep -- and the same read-only probes are slower on a real
/// desktop, so expect nearer a second there. That is the number this grace was
/// chosen against, and it has since been overtaken: `5d5b39c` skips that sweep
/// when it could only answer "nothing", which is exactly the state an idle
/// helper is activated into, and the same measurement is now 248-260 ms. Both
/// figures and their conditions are set out in one place,
/// `porthole_core::ipc::once_more_if_worth_asking_again`; the choice below
/// does not depend on which of them a reader takes.
///
/// What that cost is charged against is less than it looks: `porthole list`
/// and `porthole status` are answered by the **CLI** from the state file
/// without a bus call at all, and `open` and `forward` already involve a
/// polkit dialog measured in seconds of human time. It lands essentially on
/// `close` alone -- for the CLI. `porthole-gui` is not in that argument and
/// never was: its refresh calls `list`, `status` and `docker_ports` on the
/// helper every time anything says what is open may have changed, so a
/// window left open pays this cost far more often than any button does.
///
/// So the grace has to cover *a person operating on ports in a burst*, and
/// its only cost is the daemon living that much longer after the last rule
/// closed. Since the complaint being answered is "a month", anything from ten
/// seconds up solves it and the curve is flat; five minutes is long enough
/// that any follow-up command in one sitting is warm, and short enough that
/// the answer to "why is a root daemon running" is "because you closed a port
/// four minutes ago".
pub const GRACE: Duration = Duration::from_secs(300);

/// How long to let the bus settle after giving up the name, and again after
/// the last in-flight request has been answered.
///
/// Measured sufficient at 50 ms: D-Bus connections are FIFO, so once the
/// `ReleaseName` *reply* has arrived every message that will ever be routed
/// to this connection is already in its socket, and this is the time it takes
/// to read them. The second one is for the replies going the other way --
/// nothing inside a method can hold the process open until its own answer is
/// on the wire, so the process waits instead of the method.
pub const SETTLE: Duration = Duration::from_millis(50);

/// The grace, in milliseconds, for tests. **Debug builds only**, the same
/// rule `porthole_core::state::STATE_FILE_ENV` and [`crate::netmon::NETMON_ENV`]
/// follow: a release binary runs privileged and must not take behaviour from
/// the environment.
pub const GRACE_ENV: &str = "PORTHOLE_IDLE_GRACE_MS";

/// The settle, in milliseconds, for tests. **Debug builds only**, for the
/// same reason as [`GRACE_ENV`].
///
/// It exists so that a test can put a request *inside* a window that is
/// otherwise 50 ms wide: the one between the release and the exit, where the
/// old instance is still running and draining while the bus routes new calls
/// to a fresh one. [`PRERELEASE_ENV`] widens the other window, the one before
/// the release, which is a different fact and a different test.
pub const SETTLE_ENV: &str = "PORTHOLE_IDLE_SETTLE_MS";

/// How long to wait between deciding to retire and giving up the name, in
/// milliseconds. **Zero in production, and debug builds only** -- the same
/// rule as [`GRACE_ENV`], and the same purpose as [`SETTLE_ENV`], for the
/// other of this feature's two unaddressable windows.
///
/// [`SETTLE_ENV`] widens the window *after* the release, where a request is
/// no longer routed here at all -- the bus activates a fresh instance and
/// that one serves it. This widens the window *before* it, which is the only
/// moment at which a request can still reach an instance that has already
/// decided to go, and therefore the only moment at which
/// [`Retirement::admit`] can refuse anything. Without a knob it is the time a
/// `ReleaseName` takes to reach the bus daemon and come back: a fraction of a
/// millisecond, hit two or three times in a thousand calls under a load that
/// suppresses the very idleness it needs, and missed entirely about one run
/// in nine.
///
/// That matters more than a flaky test. The refusal path is the one place in
/// this crate where an interface method awaits anything, and an interface
/// method's future is polled on zbus's own executor thread, where a
/// runtime-dependent primitive panics (see [`Retirement::released`]). The
/// deterministic unit test for the same behaviour is a `#[tokio::test]`, so
/// it polls `admit` inside a tokio runtime where such a primitive works
/// perfectly. Entering this window on purpose is what turns the only guard
/// against that defect from a lottery into a check.
pub const PRERELEASE_ENV: &str = "PORTHOLE_IDLE_PRERELEASE_MS";

/// Test-only opt-in that makes a `--session` helper retire too. Honoured in
/// debug builds only. See [`should_run`] for what the pair of conditions is
/// for.
pub const SESSION_ENV: &str = "PORTHOLE_IDLE_EXIT";

/// What the refusal says. One sentence, and it names the remedy, because a
/// client without the retry -- an older `porthole`, a script driving the bus
/// directly -- will show it to a person verbatim.
const REFUSAL: &str = "the porthole helper was retiring when this request arrived and did not act \
                       on it: ask again, and the bus will start a fresh helper to serve it";

/// What the journal says when a refusal is actually sent -- see
/// [`Retirement::admit`], where the reasoning for recording it at all lives.
///
/// One line per refused request, so a reader counts them. It does not name the
/// method: [`Retirement::admit`] is called with no argument by every interface
/// method and adding one would put a hand-written name at eight call sites
/// with nothing holding it to the method it sits in. What the line has to
/// carry is that a client was turned away and that it was told to come back,
/// and both of those are true of every method alike.
///
/// Private, and matched from tests by a phrase spelled out there -- the same
/// arrangement `tests/idle_exit.rs` already has with `giving up` and `nothing
/// is left to answer`. A reworded line makes those tests fail saying they
/// measured nothing, which is loud; exporting the constant so they could
/// import it would make a rewording silently agree with itself.
const REFUSED_LOG: &str = "a request arrived after this helper had decided to retire and was \
                           refused rather than served; the client is told to ask again, and the \
                           bus serves the retry from a fresh helper";

/// Whether the retirement loop should run at all.
///
/// A production helper is on the system bus and is D-Bus activated: exiting
/// costs nothing, because the next client call brings it straight back.
/// `--session` is the test-only mode, and a `--session` helper is normally
/// started **by hand** by a test harness with no activation file anywhere --
/// nothing would bring it back, and every later call in that suite would fail.
/// So it retires there only when something says the bus can activate it, by
/// setting [`SESSION_ENV`]; `crates/porthole-helper/tests/idle_exit.rs` is
/// the only thing in this workspace that does -- it starts a `dbus-daemon`
/// with a `<servicedir>` of its own, which is what makes the claim true
/// there. `crates/porthole-cli/tests/container.rs` does not: its helper is
/// started by systemd on the system bus and never sees `--session` at all.
///
/// The same shape, and the same reasoning, as [`crate::netmon::should_run`].
pub fn should_run(session: bool) -> bool {
    decide(
        session,
        std::env::var_os(SESSION_ENV).is_some(),
        cfg!(debug_assertions),
    )
}

/// [`should_run`] with the environment and the build profile as plain values,
/// so both halves -- including the one a test binary can never be
/// (`debug_build: false`) -- are testable without touching either.
fn decide(session: bool, opted_in: bool, debug_build: bool) -> bool {
    !session || (debug_build && opted_in)
}

/// A duration override from the environment, honoured in debug builds only.
/// An unparseable or zero value is ignored rather than obeyed: a test that
/// misspells one gets the production behaviour and a slow test, not a helper
/// that retires instantly under every other test in the suite.
fn millis_from(override_value: Option<&str>, default: Duration, debug_build: bool) -> Duration {
    if !debug_build {
        return default;
    }
    match override_value.and_then(|v| v.parse::<u64>().ok()) {
        Some(ms) if ms > 0 => Duration::from_millis(ms),
        _ => default,
    }
}

/// How often the loop looks. A tenth of the grace, so the grace is honoured
/// to within ten percent, clamped at both ends: never so often that an idle
/// machine is re-reading a file for nothing, never so rarely that a test with
/// a short grace waits minutes for a tick.
fn check_interval(grace: Duration) -> Duration {
    (grace / 10).clamp(Duration::from_millis(20), Duration::from_secs(15))
}

/// What the helper is doing, as the retirement decision needs to see it.
///
/// One mutex over all three, and that is the whole correctness argument: the
/// decision to retire and the admission of a request read and write the same
/// lock, so a request cannot be admitted after the decision, and the decision
/// cannot be taken while a request is in flight.
#[derive(Debug)]
struct Bookkeeping {
    /// Interface methods executing right now. **Not** wall-clock quiet: a
    /// request parked on a polkit password prompt is in flight for as long as
    /// a person takes to type, which is minutes, not milliseconds.
    in_flight: usize,
    /// When the last request finished, or the last tick that saw a rule.
    last_active: Instant,
    /// Set once, and never cleared: from here on this instance acts on
    /// nothing.
    retiring: bool,
}

pub struct Retirement {
    book: Mutex<Bookkeeping>,
    /// Carries `true` once the well-known name has been given up (or the
    /// attempt to give it up has failed, which is the same thing as far as
    /// anything waiting on it is concerned: there is nothing left to wait
    /// for).
    ///
    /// **A `tokio::sync` channel and not a `tokio::time` poll**, and the
    /// difference is a crash rather than a preference: what waits on this is
    /// an interface method, and an interface method's future is polled on
    /// **zbus's own executor thread**, which is not a tokio runtime context.
    /// A `tokio::time::sleep` there panics with "there is no reactor
    /// running", takes the executor thread with it, and every caller with a
    /// call outstanding gets `NoReply` -- measured, by
    /// `a_request_that_races_the_decision_to_retire_is_refused_rather_than_served`,
    /// which is what turned an unreachable-looking hazard into a reproducible
    /// one. `tokio::sync`'s primitives are runtime-independent and work
    /// wherever they are polled.
    released: watch::Sender<bool>,
    grace: Duration,
    settle: Duration,
    /// Zero in production. See [`PRERELEASE_ENV`], which is the only thing
    /// that ever makes it anything else.
    prerelease: Duration,
    enabled: bool,
}

/// One interface method, counted for as long as this lives.
pub struct Busy {
    owner: Arc<Retirement>,
}

impl Drop for Busy {
    fn drop(&mut self) {
        let mut book = self.owner.lock();
        book.in_flight -= 1;
        book.last_active = Instant::now();
    }
}

impl Retirement {
    fn with(grace: Duration, settle: Duration, prerelease: Duration, enabled: bool) -> Arc<Self> {
        Arc::new(Retirement {
            book: Mutex::new(Bookkeeping {
                in_flight: 0,
                last_active: Instant::now(),
                retiring: false,
            }),
            released: watch::channel(false).0,
            grace,
            settle,
            prerelease,
            enabled,
        })
    }

    /// The production arrangement: the grace and the settle from the
    /// constants, both overridable in debug builds alone.
    pub fn from_env(session: bool) -> Arc<Self> {
        Self::with(
            millis_from(
                std::env::var(GRACE_ENV).ok().as_deref(),
                GRACE,
                cfg!(debug_assertions),
            ),
            millis_from(
                std::env::var(SETTLE_ENV).ok().as_deref(),
                SETTLE,
                cfg!(debug_assertions),
            ),
            millis_from(
                std::env::var(PRERELEASE_ENV).ok().as_deref(),
                Duration::ZERO,
                cfg!(debug_assertions),
            ),
            should_run(session),
        )
    }

    /// One that never retires, whoever calls what on it: everything that
    /// serves the interface outside a real helper process -- every test in
    /// this workspace that builds a `Porthole` of its own, and any future
    /// caller that has no bus name to give up.
    ///
    /// Not merely a `run` that is never spawned: [`Retirement::claim`]
    /// refuses too, so a `Porthole` built with this cannot be talked into
    /// refusing a request no matter what else in the process goes wrong.
    pub fn never() -> Arc<Self> {
        Self::with(GRACE, SETTLE, Duration::ZERO, false)
    }

    /// Poisoning is taken rather than panicked on: what is behind the lock is
    /// three plain values with no invariant to be left half-written, and a
    /// panic in one request must not stop the process retiring ever again.
    fn lock(&self) -> std::sync::MutexGuard<'_, Bookkeeping> {
        self.book.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether this instance has already decided to go. Read by `main`'s
    /// `SIGTERM` handler: systemd sends one within microseconds of the
    /// release, and that one must not end the process before the drain has
    /// finished.
    pub fn is_retiring(&self) -> bool {
        self.lock().retiring
    }

    /// Admit one interface method, or refuse it because this instance is on
    /// its way out.
    ///
    /// The guard is taken **before** the decision is read, and is held across
    /// the refusal's own wait: a request waiting to be refused counts as in
    /// flight, so [`Retirement::drain`] cannot decide the process is finished
    /// while one is still parked on the release.
    ///
    /// It is *not* what keeps the process alive until the refusal reaches the
    /// wire, and the distinction is worth having straight: the guard is
    /// dropped before this returns `Err`, and zbus writes the reply only after
    /// the method returns. The trailing settle in [`Retirement::retire`] is
    /// what covers that last hop, and says so at its own call site. Nothing
    /// inside a method can hold a process open past its own return.
    ///
    /// # The refusal is recorded, and why it was the one thing that was not
    ///
    /// The helper's journal is its account of what it did: every open, every
    /// close, every record reconciliation, the decision to retire, a
    /// `ReleaseName` that failed, a drain that overran. Turning a client's
    /// request away was the one thing it did to somebody without saying so --
    /// and the line it *did* write, `giving up ... and exiting`, states an
    /// intention rather than an effect. Two instances of that line say nothing
    /// about whether either retirement inconvenienced anybody.
    ///
    /// It matters most for the client this refusal is worded for. A porthole
    /// of this version asks again and the person never learns any of it
    /// happened; an older `porthole`, or a script driving the bus directly,
    /// shows [`REFUSAL`] verbatim and stops -- and then the machine's only
    /// record of why is here. An administrator reading a journal after "it
    /// said it could not reopen my port" should find the refusal, not have to
    /// infer it from a retirement that happened around the same time.
    ///
    /// It cannot become noise: only a request routed to this instance between
    /// the decision and the release can reach this branch at all, and in
    /// production that window is the time a `ReleaseName` takes to travel to
    /// the bus daemon and back.
    ///
    /// **After the wait, not before.** A refusal is only a refusal once it can
    /// be sent. Where the release *failed*, [`Retirement::await_release`] never
    /// completes, this caller is answered by the process exiting with a
    /// `NoReply`, and nothing here claims otherwise -- that path logs its own
    /// line, in [`Retirement::retire`], saying exactly that.
    pub async fn admit(self: &Arc<Self>) -> Result<Busy, HelperError> {
        let retiring = {
            let mut book = self.lock();
            book.in_flight += 1;
            book.retiring
        };
        let busy = Busy {
            owner: self.clone(),
        };
        if !retiring {
            return Ok(busy);
        }
        // Answer only once the name is really gone, so the client's retry
        // reaches the fresh instance rather than this one.
        self.await_release().await;
        drop(busy);
        eprintln!("porthole-helper: {REFUSED_LOG}");
        Err(HelperError::Retiring(REFUSAL.to_string()))
    }

    /// Wait until the well-known name has been given up.
    ///
    /// Ordinarily bounded by the `ReleaseName` round trip -- a message to the
    /// bus daemon and back. **Not bounded at all when the release fails**, and
    /// deliberately: [`Retirement::retire`] then records nothing, this never
    /// completes, and the caller is answered by the process exiting rather
    /// than by a refusal that would send its retry back to an instance still
    /// owning the name. [`Retirement::drain`]'s own bound is what ends the
    /// wait, at which point the caller gets `NoReply` -- which
    /// `porthole_core::ipc::worth_asking_again` covers too, and whose retry
    /// finds no owner and activates a fresh helper.
    async fn await_release(&self) {
        let mut released = self.released.subscribe();
        // `borrow` first, through `wait_for`'s own initial check: the release
        // may already have happened before this method was ever admitted.
        let _ = released.wait_for(|released| *released).await;
    }

    /// Take the decision to retire, or say why not.
    ///
    /// `rules_are_empty` is read outside this lock, and that is safe for a
    /// reason worth writing down: the only thing in this process that can put
    /// a rule *into* the state file is an interface method, so a rule that
    /// appeared after the read either is still in flight (`in_flight != 0`
    /// below) or has finished (`last_active` is now, and the grace check
    /// below fails). The network monitor only ever closes.
    ///
    /// A tick that sees a rule stamps `last_active`, which is what makes the
    /// grace run from **the later of** the last request completing and the
    /// last rule closing -- including a rule the monitor or an expiry timer
    /// closed, which is no request of anybody's.
    fn claim(&self, rules_are_empty: bool) -> bool {
        if !self.enabled {
            return false;
        }
        let mut book = self.lock();
        if book.retiring {
            return false;
        }
        if !rules_are_empty {
            book.last_active = Instant::now();
            return false;
        }
        if book.in_flight != 0 {
            return false;
        }
        if book.last_active.elapsed() < self.grace {
            return false;
        }
        book.retiring = true;
        true
    }

    /// Watch for the machine being idle, and retire when it is. Never
    /// returns: it either loops forever or ends the process.
    pub async fn run(self: Arc<Self>, conn: zbus::Connection, state_path: PathBuf) {
        if !self.enabled {
            std::future::pending::<()>().await;
        }
        let mut ticker = tokio::time::interval(check_interval(self.grace));
        // The first tick fires immediately, and the process has just started:
        // nothing can be idle yet.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let path = state_path.clone();
            // On a blocking thread: it is a file read, and this crate already
            // documents why those must not run on an async worker
            // (`porthole_core::state`'s own `LOCK_TIMEOUT` doc comment). The
            // plain, non-locking open -- a reader must never block behind a
            // writer, and a helper that took the exclusive lock every few
            // seconds would be the thing a new instance's start-up sweep
            // silently skipped on.
            let empty = tokio::task::spawn_blocking(move || {
                StateStore::open(&path).map(|state| state.rules().is_empty())
            })
            .await;
            // A state file that could not be read is not a state file with
            // nothing in it. Look again next tick rather than retire on an
            // absence of information.
            let Ok(Ok(empty)) = empty else { continue };
            if !self.claim(empty) {
                continue;
            }
            self.retire(&conn).await;
        }
    }

    /// Release, settle, drain, exit -- the sequence measured correct, with
    /// the drain refusing rather than serving (see this module's own docs).
    ///
    /// Diverges: the process is gone by the time this would return.
    async fn retire(&self, conn: &zbus::Connection) -> ! {
        eprintln!(
            "porthole-helper: nothing has been open for {:?} and nothing is in flight -- \
             giving up {SERVICE} and exiting. The bus starts a new helper the moment one is \
             wanted.",
            self.grace
        );

        // Zero in production, and the only thing that ever makes it anything
        // else is a test placing a request inside the window this opens --
        // see `PRERELEASE_ENV`, which is where the whole of the reasoning is.
        if !self.prerelease.is_zero() {
            tokio::time::sleep(self.prerelease).await;
        }

        // The FIFO barrier. Once this reply is in, every message that will
        // ever be routed to this connection is already in its socket.
        //
        // Whether the name is really gone is what decides whether anything
        // may be *told* to ask again: a refusal reaching a client whose retry
        // would land back here would spend that client's one retry against
        // the same answer.
        let name_is_gone = match conn.release_name(SERVICE).await {
            Ok(true) => true,
            Ok(false) => {
                eprintln!(
                    "porthole-helper: the bus says this connection did not own {SERVICE}; exiting \
                     anyway, since it is not serving it either"
                );
                // Not ours to give up means nothing can be routed here *as
                // the owner*, which is the same thing a release buys.
                true
            }
            Err(e) => {
                eprintln!(
                    "porthole-helper: could not give up {SERVICE} ({e}); exiting without telling \
                     anything to ask again, because a retry could land back on this same \
                     instance. What was already routed here loses its reply instead, and the \
                     client's retry then finds the name unowned and activates a fresh helper."
                );
                false
            }
        };
        // Only now, and only if the name really is gone. A request still
        // waiting when this is not sent stays waiting until the drain below
        // gives up on it and the process exits, which hands its caller a
        // `NoReply` -- the other failure `worth_asking_again` covers, and the
        // one whose retry cannot come back here because there is nothing here
        // to come back to.
        if name_is_gone {
            let _ = self.released.send(true);
        }

        // Settle, drain, and do it once more.
        //
        // The first settle is systemd's window too: it sends SIGTERM within
        // microseconds of the line above, and `main` is what keeps that from
        // ending the process here.
        //
        // Twice rather than once, at no extra cost when there is nothing to
        // find: a request can be read out of the socket *after* a drain has
        // already seen nothing outstanding, and the second settle is also
        // what gives the last refusal's reply time to reach the wire --
        // nothing inside a method can hold the process open until its own
        // answer is written, so the process waits instead of the method.
        // Bounded at two: there is always a last instant, and the client
        // retry is what covers it (`porthole-cli`'s `worth_asking_again`).
        for _ in 0..2 {
            tokio::time::sleep(self.settle).await;
            self.drain().await;
        }
        // And one last settle after the last drain, because `drain` returns
        // the instant a method *returned* -- which is before zbus has written
        // its answer. Exiting there loses the reply that was just produced.
        tokio::time::sleep(self.settle).await;

        eprintln!("porthole-helper: no rule is open and nothing is left to answer; exiting");
        std::process::exit(0);
    }

    /// Wait for every request that was already routed here to be answered.
    ///
    /// Bounded, and the bound does two jobs. On the ordinary path it is a bug
    /// net: each of those requests is a refusal that returns as soon as the
    /// release has been recorded, so the wait is milliseconds and the bound is
    /// never reached. On the path where `ReleaseName` *failed* it is the
    /// mechanism -- nothing records a release, every waiting refusal stays
    /// waiting, and this is what ends them, by exiting. Their callers get
    /// `NoReply` and retry, which is the outcome that path is choosing on
    /// purpose (see [`Retirement::await_release`]).
    ///
    /// Five seconds against systemd's own `TimeoutStopSec` default of 90.
    async fn drain(&self) {
        const LIMIT: Duration = Duration::from_secs(5);
        let deadline = Instant::now() + LIMIT;
        while self.lock().in_flight != 0 {
            if Instant::now() >= deadline {
                eprintln!(
                    "porthole-helper: {} request(s) still unanswered after {} seconds of \
                     draining; exiting anyway",
                    self.lock().in_flight,
                    LIMIT.as_secs()
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_helper_does_not_retire_unless_something_says_the_bus_can_bring_it_back() {
        // The distinction is not session-versus-system, it is
        // activated-versus-started-by-hand: `helper_e2e.rs` spawns a
        // `--session` helper itself, with no activation file anywhere, and a
        // helper that retired there would take every later test in the binary
        // with it.
        assert!(decide(false, false, true), "a system-bus helper retires");
        assert!(decide(false, false, false));
        assert!(!decide(true, false, true), "`--session` alone does not");
        assert!(decide(true, true, true), "`--session` plus the opt-in does");

        // A release binary runs privileged and must not take this from the
        // environment -- the same rule `PORTHOLE_STATE_FILE` follows. A test
        // binary is always a debug build, so passing the profile in is the
        // only way to check the release half at all.
        assert!(
            !decide(true, true, false),
            "a release build must ignore the opt-in entirely"
        );
    }

    #[test]
    fn the_grace_comes_from_the_environment_only_in_a_debug_build() {
        assert_eq!(
            millis_from(Some("1500"), GRACE, true),
            Duration::from_millis(1500)
        );
        assert_eq!(
            millis_from(Some("1500"), GRACE, false),
            GRACE,
            "a release helper must not take its own lifetime from the environment"
        );
        // A misspelled override is a slow test, never a helper that retires
        // out from under every other test in the suite.
        for bad in [None, Some(""), Some("0"), Some("soon"), Some("-1")] {
            assert_eq!(millis_from(bad, GRACE, true), GRACE, "{bad:?}");
        }
    }

    #[test]
    fn the_loop_looks_often_enough_to_honour_the_grace_and_no_oftener() {
        assert_eq!(check_interval(GRACE), Duration::from_secs(15));
        assert_eq!(
            check_interval(Duration::from_secs(30)),
            Duration::from_secs(3)
        );
        // A test-length grace must not be rounded up into a wait of minutes.
        assert_eq!(
            check_interval(Duration::from_millis(500)),
            Duration::from_millis(50)
        );
        assert_eq!(
            check_interval(Duration::from_millis(10)),
            Duration::from_millis(20),
            "and never so often that an idle machine re-reads a file for nothing"
        );
    }

    /// An eligible retirement whose grace has already elapsed, so `claim`
    /// turns on the three facts under test rather than on a wait.
    fn ready() -> Arc<Retirement> {
        let r = Retirement::with(GRACE, SETTLE, Duration::ZERO, true);
        {
            let mut book = r.lock();
            book.last_active = Instant::now() - GRACE - Duration::from_secs(1);
        }
        r
    }

    #[test]
    fn a_helper_that_is_not_eligible_to_retire_cannot_be_talked_into_it() {
        // `Retirement::never` is what every `Porthole` outside a real helper
        // process is built with. It has to refuse the decision itself, not
        // merely never be asked for it: a test whose service object started
        // answering `Retiring` would be reporting something no helper it
        // stands for could ever say.
        let r = Retirement::never();
        {
            let mut book = r.lock();
            book.last_active = Instant::now() - GRACE - Duration::from_secs(1);
        }
        assert!(
            !r.claim(true),
            "idle, empty, past the grace -- and not eligible"
        );
        assert!(!r.is_retiring());
    }

    #[test]
    fn a_helper_with_a_rule_open_never_retires_however_long_it_sits() {
        let r = ready();
        assert!(!r.claim(false), "a rule is open; the monitor is needed");
        // And the tick that saw it restarted the grace, so even the instant
        // the last rule closes is not enough on its own.
        assert!(!r.claim(true), "the grace runs from the last rule closing");
        assert!(!r.is_retiring());
    }

    #[tokio::test]
    async fn a_request_in_flight_holds_the_helper_open_however_long_it_takes() {
        // A request parked on a polkit password prompt is in flight for
        // minutes. Wall-clock quiet would have retired out from under the
        // dialog.
        let r = ready();
        let busy = r.admit().await.expect("not retiring, so it is admitted");
        assert!(!r.claim(true), "something is executing");
        drop(busy);
        // Dropping it also stamps the activity, so the next decision waits out
        // a fresh grace rather than firing immediately.
        assert!(!r.claim(true));
    }

    #[tokio::test]
    async fn once_the_decision_is_taken_every_request_is_refused_rather_than_served() {
        // The whole safety argument: a request admitted after the decision
        // would emit a signal no subscriber can receive (the bus resolves the
        // sender name to the *current* owner), and could open a rule the
        // process is about to exit with.
        let r = ready();
        assert!(r.claim(true), "idle, empty and past the grace");
        assert!(r.is_retiring());

        // The refusal waits for the release, so it is answered only once the
        // name is really gone -- pin that by refusing to answer before it.
        let waiting = r.clone();
        let refusal = tokio::spawn(async move { waiting.admit().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!refusal.is_finished(), "answered before the name was gone");
        assert_eq!(
            r.lock().in_flight,
            1,
            "and it counts as in flight while it waits, so the drain waits for it"
        );

        r.released.send(true).expect("the sender outlives the test");
        let refused = refusal.await.expect("the task ran");
        let err = refused.err().expect("a retiring helper refuses");
        assert!(
            err.to_string().contains("ask again"),
            "the refusal must name the remedy, since a client without the \
             retry shows it verbatim: {err}"
        );
        assert_eq!(r.lock().in_flight, 0, "and it stopped counting once it did");
    }

    #[test]
    fn the_decision_is_taken_once_and_never_reconsidered() {
        let r = ready();
        assert!(r.claim(true));
        assert!(
            !r.claim(true),
            "a second claim would release the name twice"
        );
    }

    #[test]
    fn a_helper_that_has_just_been_asked_something_waits_out_the_whole_grace() {
        let r = Retirement::with(GRACE, SETTLE, Duration::ZERO, true);
        assert!(
            !r.claim(true),
            "the process has only just started; nothing is idle yet"
        );
    }
}
