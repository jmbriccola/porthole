//! porthole's session half: the thing that tells the user a port closed.
//!
//! The helper is a system service and cannot comfortably reach a user's
//! session bus. By the time a port expires or the machine leaves the network
//! a rule was scoped to, the window that opened it is almost always gone --
//! so without something listening in the session, a close that nobody asked
//! for is announced to nobody.
//!
//! One job, and no interface of its own: listen on the **system** bus for
//! `RuleClosed`, and call `org.freedesktop.Notifications` on the **session**
//! bus. It serves no object and holds no view of what is open -- `list` is
//! the authority for that, and this never shows a list. The only thing it
//! remembers is which notification was about which rule, so a `Reopen` click
//! has something to re-send (see [`Pending`]).
//!
//! It does own one session-bus name, and only so that a session never has two
//! agents at once. porthole ships both a systemd user unit and an XDG
//! autostart entry, because desktops differ in which they honour, and a
//! desktop that honours both would otherwise show every close twice.
//!
//! The name goes to the agent started **last**: each one asks for it with
//! replacement allowed and takes it from whoever holds it, and the one that
//! loses it stops. That is what makes `systemctl --user restart` mean
//! something after an upgrade -- see [`claim_session`], which is also where
//! the one case that cannot be taken over is handled, and said out loud.
//!
//! # Order of operations at start-up, and why it is that order
//!
//! Subscribe first, then wake the helper. A signal sent before a subscriber's
//! match rule exists is simply gone, and the helper's start-up sweep
//! announces what it dropped as soon as it owns the bus name. The helper is
//! D-Bus activated, so the very act of calling it is what starts it: an agent
//! that subscribes and *then* calls receives that sweep's announcements,
//! while one that calls first can lose them. The `list` call below is made
//! for that ordering alone -- its answer is not kept.
//!
//! # What is proven, and what is not
//!
//! `tests/session.rs` drives this binary over a private session bus against a
//! stand-in notification service and a stand-in helper: a close notifies, a
//! close belonging to another uid does not, a `Reopen` click re-sends the
//! original request with the original duration -- an `open` for a rule that
//! permitted and a `forward` for one that redirected, which are two different
//! methods and not two spellings of one -- and a bus with no notification
//! service at all leaves the process running. Two of them are about the name:
//! a second agent takes it from the first, which the bus is asked about
//! rather than either agent's journal, and one that meets a holder refusing
//! to yield puts a notice on the screen. Two more are about the one message
//! this agent cannot act on: a helper whose `RuleClosed` this binary cannot
//! decode, and one whose answer to the start-up `list` it cannot decode,
//! each of which puts a notice on the screen and stops the process --
//! against, in the same file, a helper that is simply absent, which leaves
//! it running. What none of that touches is a
//! real notification daemon (the stand-in answers `Notify` and emits
//! `ActionInvoked`, it does not draw anything), the real helper, or polkit --
//! so "the prompt appears and the port comes back" is not covered by any test
//! in this repository.
//!
//! The start-up ordering above is not covered either. Every test there that
//! stands a helper up does so before the agent, so none of them exercises an
//! agent whose subscription is what the helper is started into, and nothing
//! here would fail if that ordering were reversed.
//!
//! Nor is the exit status after a lost bus covered end to end. That harness
//! points both bus addresses at one private daemon, so taking it down ends
//! the system and the session streams together, and which of them reports it
//! first varies between runs -- measured, not assumed. A real agent holds two
//! separate connections and loses one at a time, but no test here can produce
//! that. What is covered is the decision itself, as a unit test on [`Ended`].

mod notify;

use futures_util::StreamExt;
use notify::{NotificationsProxy, REOPEN};
use porthole_core::ipc::{alignment, Alignment, PortholeProxy, WireRule, PROTOCOL_VERSION};
use std::path::{Path, PathBuf};

/// The session-bus name one agent per session holds. Not an interface: this
/// process serves nothing, and the name exists only so that a session's
/// agents can settle which of them is the agent -- see [`claim_session`].
/// Deliberately not the helper's own `com.jacopobriccola.Porthole`, which is
/// a system-bus name owned by something else entirely.
const AGENT_SERVICE: &str = "com.jacopobriccola.PortholeAgent";

/// Set in the environment of the agent [`replace_this_agent`] starts, to
/// **the helper version that prompted the replacement**, and read by that
/// agent to bound how often it may try.
///
/// Without a bound the pathological case loops for as long as anything keeps
/// starting agents: a machine whose *installed* `porthole-agent` really is
/// older than its helper would re-execute the same old binary, find the same
/// answer, and go round again -- a busy loop, not a slow one, since nothing
/// in the path sleeps. `tests/session.rs`'s
/// `an_agent_that_is_still_the_older_half_after_replacing_itself_does_not_loop`
/// is what proves the bound holds, against a helper that never stops
/// reporting a newer version.
///
/// **A version rather than a flag**, and the difference is a real case: a
/// bare "already tried" survives a *successful* recovery, so a second
/// upgrade in the same login session would not be repaired -- and the
/// journal line refusing it would assert that the installed agent is the old
/// one, which after the first recovery it is not. Carrying the version
/// bounds the attempts at one per helper version, which keeps the no-loop
/// property (a helper that never moves is never retried) and repairs every
/// upgrade that does move it.
///
/// A value in the environment of a session that never came from an agent
/// disables the replacement for helpers at or below it -- an environment
/// variable is a small surface, and this is what it does.
const REEXECED: &str = "PORTHOLE_AGENT_REEXECED";

/// How many notifications can be waiting for a click at once.
///
/// Each entry is one rule kept alive only so a `Reopen` on its notification
/// has something to re-send. Entries leave when the notification closes,
/// which is the ordinary case; the bound is what happens when a server never
/// says so. Past it, the oldest is dropped and a click on that notification
/// is refused with a line in the journal rather than acted on with a guess.
const MAX_PENDING: usize = 32;

/// The rules whose notifications are still on screen, oldest last.
///
/// A `Vec` rather than a map: it holds at most [`MAX_PENDING`] entries, a
/// click scans it once, and this way "newest" is a position rather than an
/// assumption about how a notification server numbers things.
///
/// A notification id identifies a notification within one run of one
/// notification server. It says nothing across a restart of that server, and
/// nothing about a different server: the next run starts numbering again, so
/// an entry left here from before a restart can carry the same id as one
/// added after it. Two things keep a click off the wrong entry. The list is
/// emptied whenever the notification service changes owner, so entries from
/// a previous run do not survive into the next one; and a click is matched
/// against the newest entry with that id, not the oldest. Only the first
/// removes the possibility -- the second is what happens if the first ever
/// fails to fire.
type Pending = Vec<(u32, WireRule)>;

/// Which signal stream ended, and therefore why this process is stopping.
///
/// The distinction decides the exit status, and through it whether anything
/// starts a new agent -- see [`main`]'s own doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// The system bus went away. Nothing will wake this agent again.
    SystemBus,
    /// The session bus went away, which is the session itself ending.
    SessionBus,
    /// A newer agent took [`AGENT_SERVICE`]. Not a failure and not a loss:
    /// one agent still owns the name and announces closes, and it is the
    /// other one. See [`claim_session`].
    Replaced,
    /// The helper sent something this binary could not read -- see
    /// [`announce_undecodable`] for why that ends the process instead of
    /// being skipped, and why it is not a failure status.
    Undecodable,
}

impl Ended {
    /// `1` for a lost system bus, `0` for the two that are not failures.
    ///
    /// `SystemBus` must not collapse into the others: `Restart=on-failure` in
    /// `data/porthole-agent.service` is what brings a new agent after a lost
    /// system bus, and it can only tell them apart by this number. Restarting
    /// after `Replaced` would be worse than useless -- the new agent would
    /// take the name back from the one that just took it, and the two would
    /// trade it for as long as the start limit allowed.
    fn exit_code(self) -> u8 {
        match self {
            Ended::SystemBus => 1,
            Ended::SessionBus | Ended::Replaced | Ended::Undecodable => 0,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Ended::SystemBus => {
                "the system bus connection ended; stopping with a failure status so the \
                 service manager starts a new agent"
            }
            Ended::SessionBus => "the session bus connection ended; stopping",
            Ended::Replaced => {
                "a newer agent took this session's agent name; stopping so closes are not \
                 announced twice"
            }
            Ended::Undecodable => {
                "the helper sent a message this agent could not read, so nothing it says \
                 from here on would be announced; stopping and saying so on screen"
            }
        }
    }
}

/// Exit status, and what a service manager should make of it.
///
/// Every start-up failure below exits `SUCCESS`. None of them is a
/// condition a restart could change -- no session bus, no system bus, no
/// notification interface, no way to watch for a replacement, or
/// [`AGENT_SERVICE`] held by something that will not yield it -- so the unit
/// stays stopped rather than looping. The same goes for the session bus
/// ending: that is the session itself going away, and there is no screen
/// left to notify. And for being replaced by a newer agent, which is a
/// success in the plainest sense: the job is being done, by the process that
/// took over.
///
/// A helper this agent cannot read exits `SUCCESS` too, and that one is a
/// decision rather than an inheritance -- see [`announce_undecodable`].
///
/// Losing the **system** bus mid-run is the one case that exits `FAILURE`.
/// The agent cannot rebuild that connection from inside its own loop, and
/// what remains is a process that will never be woken again -- so it stops
/// and says so with a status a service manager can act on. That is what
/// `Restart=on-failure` in `data/porthole-agent.service` is for, and why
/// the two cases must not share an exit status.
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let uid = current_uid();

    let session = match zbus::Connection::session().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("porthole-agent: no session bus, so nothing to notify on: {e}");
            return std::process::ExitCode::SUCCESS;
        }
    };
    // Before the claim, not after: see `watch_for_replacement`.
    let Some(mut replaced) = watch_for_replacement(&session).await else {
        return std::process::ExitCode::SUCCESS;
    };
    // First, and before anything is woken or subscribed to: two agents in
    // one session would show every close twice.
    if !claim_session(&session).await {
        return std::process::ExitCode::SUCCESS;
    }

    let system = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("porthole-agent: no system bus, so nothing to listen to: {e}");
            return std::process::ExitCode::SUCCESS;
        }
    };
    let porthole = match PortholeProxy::new(&system).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("porthole-agent: could not bind the helper's interface: {e}");
            return std::process::ExitCode::SUCCESS;
        }
    };
    // Awaited here, before the `list` below: this is the call that installs
    // the match rule, and the ordering above is the whole point of it.
    let mut closes = match porthole.receive_rule_closed().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("porthole-agent: could not subscribe to the helper's signals: {e}");
            return std::process::ExitCode::SUCCESS;
        }
    };

    // Before the first version read, not after: the helper taking the name
    // is what says it has just started -- and possibly just been upgraded --
    // and a restart that happened between the read and this subscription
    // would be one nothing here ever hears about. Measured unprivileged on
    // a system bus with porthole's real policy, including the case where
    // the subscription precedes the name ever being owned.
    let mut helper_owners = porthole
        .inner()
        .receive_owner_changed()
        .await
        .inspect_err(|e| {
            // Not fatal, unlike the notification service's own owner
            // stream above it: an agent that cannot notice a restart still
            // announces every close it can read, which is its whole job.
            // What it loses is the re-check, so it says so and goes on with
            // the one at start-up.
            eprintln!(
                "porthole-agent: could not watch for the helper being restarted ({e}); the \
                 version check runs once, at start-up, and not again"
            )
        })
        .ok();

    let notifications = match NotificationsProxy::new(&session).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("porthole-agent: could not bind the notification interface: {e}");
            return std::process::ExitCode::SUCCESS;
        }
    };
    let (mut actions, mut dismissals) = match (
        notifications.receive_action_invoked().await,
        notifications.receive_notification_closed().await,
    ) {
        (Ok(a), Ok(d)) => (a, d),
        (a, d) => {
            let e = a.err().or(d.err()).expect("one of the two failed");
            eprintln!("porthole-agent: could not subscribe to notification actions: {e}");
            return std::process::ExitCode::SUCCESS;
        }
    };

    // The cue to forget every id in `pending`: they are only meaningful
    // within one run of one notification server. See [`Pending`].
    let mut owners = match notifications.inner().receive_owner_changed().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("porthole-agent: could not watch the notification service's owner: {e}");
            return std::process::ExitCode::SUCCESS;
        }
    };

    // Before the `list` below, so that if that call comes back unreadable
    // the notice it puts on screen already knows which half is old. It is
    // also a call, so it wakes a D-Bus activated helper -- after the
    // subscription above, which is the ordering this module's own doc
    // comment is about.
    let mut helper = realign(&system).await;

    // Not for its answer. Calling the helper is what starts it, and the
    // subscription above already exists, so whatever its start-up sweep
    // announces arrives here instead of being sent to nobody.
    //
    // Most failures here are ordinary -- no helper installed, or none
    // activatable -- and change nothing about what this process does next.
    // One is not: `list`'s *return* carries `WireRule`, so an answer this
    // binary cannot decode is the same fact `on_close` below meets, arriving
    // earlier. "Listening anyway" is the wrong answer to it, and it is the
    // answer this printed while the user had no notifications at all: the
    // agent that could not read `list` could not read `RuleClosed` either,
    // and it said so once, to a journal, and carried on for the rest of the
    // login. See [`announce_undecodable`].
    if let Err(e) = porthole.list().await {
        if porthole_core::ipc::is_undecodable(&e) {
            eprintln!("porthole-agent: could not read the helper's answer to list ({e})");
            eprintln!("porthole-agent: {}", Ended::Undecodable.reason());
            announce_undecodable(&notifications, helper).await;
            return std::process::ExitCode::from(Ended::Undecodable.exit_code());
        }
        eprintln!("porthole-agent: could not reach the helper ({e}); listening anyway");
    }

    eprintln!("porthole-agent: listening for uid {uid}");

    // A stream here ends when the connection under it does, and neither
    // connection can be rebuilt from inside this loop, so the end of any of
    // the three signal streams ends the process rather than leaving it
    // running with one half of its job -- an agent that has lost the system
    // bus is a process nothing will ever wake again.
    //
    // Which bus ended decides the exit status, and therefore whether
    // anything starts a new agent: see [`main`]'s own doc comment.
    let mut pending: Pending = Vec::new();
    let ended = loop {
        tokio::select! {
            biased;
            // First on purpose. An owner change and a close can be ready in
            // the same breath, and the order they are taken in decides
            // whether the close's notification is recorded and then thrown
            // away, or thrown away and then recorded. Polled first, an owner
            // change already on the wire empties the list before the close
            // fills it.
            //
            // It does not cover an owner change that becomes ready while a
            // `Notify` is still in flight: that one is applied after the
            // notification it did not invalidate has been recorded, so a
            // click on that notification is refused. Refusing is the
            // direction that cannot open the wrong port.
            //
            // A refutable pattern, unlike the three below: this is the one
            // branch allowed to end without ending the loop, and matching it
            // unconditionally would make a terminated stream return
            // immediately forever.
            Some(_) = owners.next() => {
                eprintln!(
                    "porthole-agent: the notification service changed; forgetting {} \
                     notification id(s), so a later click cannot be matched to one of them",
                    pending.len()
                );
                pending.clear();
            }
            // Ahead of the four below on purpose. A newer agent has the
            // name and is about to be subscribed to the same signals; from
            // this point on, anything this process announces is announced
            // twice. Stopping first can leave a close announced by neither
            // -- see `claim_session` for why that is the direction chosen.
            //
            // The bus sends `NameLost` only to the connection that lost the
            // name, and this connection asked for one name, so there is
            // nothing here to filter.
            lost = replaced.next() => {
                match lost {
                    Some(_) => break Ended::Replaced,
                    // The stream is on the session connection, so its end is
                    // that connection's end.
                    None => break Ended::SessionBus,
                }
            }
            // The helper's bus name changed owner, which is the helper having
            // just started -- after an upgrade, that is the new one. Re-read
            // the version, through a proxy built for that one call: the
            // measured trap is a *cached property*, which at exactly this
            // moment answers with the version of the helper that has just
            // died.
            //
            // This is where the common case resolves itself: an agent that
            // outlived a package upgrade learns it is the older half the
            // moment the upgraded helper comes back, and starts the agent
            // that upgrade installed. `Some(None)` is the helper *losing*
            // the name, and there is nothing to ask then.
            //
            // **After the replacement branch above**, and that ordering is a
            // decision: an agent that has already lost the session name is
            // not this session's agent any more, and re-executing from here
            // would put a third agent in front of the one that just replaced
            // this one. Being replaced wins; the agent that took the name
            // makes this same check for itself at its own start-up.
            //
            // A replacement started from here loses `pending`: the new image
            // begins with an empty list, so a click on a notification that
            // was already on screen is answered by the journal line in
            // `on_action` rather than by an `open`. That is the same refusal
            // an id pushed off `MAX_PENDING` gets, and it is the direction
            // that cannot open a port nobody asked for -- against which the
            // alternative is an agent that cannot read the helper at all.
            //
            // A refutable pattern for the same reason the first branch has
            // one: this stream is `None` when no match rule could be
            // installed, and `next_owner` keeps that branch inert rather
            // than instantly ready forever.
            Some(owner) = next_owner(&mut helper_owners) => {
                if owner.is_some() {
                    helper = realign(&system).await;
                }
            }
            close = closes.next() => {
                let Some(signal) = close else {
                    break Ended::SystemBus;
                };
                // The arm this whole binary was silent in. zbus delivers a
                // signal whose body does not match and leaves the stream
                // alive; only `args()` refuses, and this used to `continue`
                // -- so an agent that could not read one `RuleClosed` could
                // not read any of them and went on saying nothing about
                // every close for the rest of the login. Measured, and it is
                // what a user actually got after an upgrade. See
                // [`announce_undecodable`].
                let args = match signal.args() {
                    Ok(args) => args,
                    Err(e) => {
                        eprintln!("porthole-agent: could not read a RuleClosed the helper sent ({e})");
                        break Ended::Undecodable;
                    }
                };
                on_close(&notifications, &mut pending, args.rule(), *args.reason(), uid).await;
            }
            // The two below are the notification service's own signals, not
            // the helper's, and they end differently on purpose. `ActionInvoked`
            // is `us` and `NotificationClosed` is `uu` -- a freedesktop
            // interface porthole does not version and has never changed --
            // and an agent that cannot read one of them still announces
            // every close, which is its job; what it loses is a click. So
            // this reports and carries on where the helper's own signal
            // stops the process. Reporting is the part that was missing:
            // both of these discarded the error in silence too.
            action = actions.next() => {
                let Some(signal) = action else {
                    break Ended::SessionBus;
                };
                let args = match signal.args() {
                    Ok(args) => args,
                    Err(e) => {
                        eprintln!(
                            "porthole-agent: could not read an ActionInvoked from the \
                             notification service ({e}); that click is lost, and closes are \
                             still being announced"
                        );
                        continue;
                    }
                };
                on_action(&porthole, &notifications, &pending, args.id, args.action_key);
            }
            dismissal = dismissals.next() => {
                let Some(signal) = dismissal else {
                    break Ended::SessionBus;
                };
                let args = match signal.args() {
                    Ok(args) => args,
                    Err(e) => {
                        eprintln!(
                            "porthole-agent: could not read a NotificationClosed from the \
                             notification service ({e}); one notification's id stays on the \
                             pending list until it is pushed off"
                        );
                        continue;
                    }
                };
                pending.retain(|(id, _)| *id != args.id);
            }
        }
    };

    eprintln!("porthole-agent: {}", ended.reason());
    if ended == Ended::Undecodable {
        announce_undecodable(&notifications, helper).await;
    }
    std::process::ExitCode::from(ended.exit_code())
}

/// Ask the helper which contract it speaks, and act on the answer.
///
/// Run at start-up and again on every change of the helper's bus-name owner
/// -- which is exactly when the helper has been restarted, and therefore
/// possibly upgraded, under a live agent. Each run reads afresh: a
/// **method**, through a proxy built for the one call, never a cached
/// property (see `porthole_core::ipc::read_protocol_version`, where the
/// measurement behind that is recorded).
///
/// What it returns is what the agent then knows, and it is used for exactly
/// one thing: naming the right remedy when a message arrives that this
/// binary cannot read. `None` is an honest answer here -- the helper may not
/// be there at all, and "not installed" must not be reported as "out of
/// date".
///
/// **A version difference is not by itself a reason to stop.** This agent
/// carries on with whatever it learns; the thing that stops it is still a
/// message it cannot decode, exactly as before this contract existed. The
/// one exception is the case it can fix by itself, below.
async fn realign(system: &zbus::Connection) -> Option<Alignment> {
    let version = match porthole_core::ipc::read_protocol_version(system).await {
        Ok(version) => version,
        Err(e) => {
            eprintln!(
                "porthole-agent: could not read the helper's protocol version ({e}); \
                 carrying on without knowing which of the two is older"
            );
            return None;
        }
    };
    let alignment = alignment(version);
    match alignment {
        Alignment::Same => eprintln!(
            "porthole-agent: the helper speaks porthole's protocol {version}, and so does \
             this agent"
        ),
        Alignment::HelperIsOlder => eprintln!(
            "porthole-agent: {} and this agent speaks {PROTOCOL_VERSION}, so the helper is \
             the older half; restarting it needs privilege, so this agent carries on and \
             says which half to restart if a message it cannot read arrives",
            what_the_helper_said(version)
        ),
        Alignment::ThisOneIsOlder => replace_this_agent(version),
    }
    Some(alignment)
}

/// What the helper actually answered, for a journal line to report.
///
/// **0 is not a number any helper reports** -- `porthole_core::ipc`'s own
/// constant says so in terms. It is what an absent member is *read* as, so
/// that one comparison orders every case; writing it into a sentence as the
/// helper's own answer states something no helper ever said, and sends the
/// reader of that journal looking for a version 0 that does not exist.
fn what_the_helper_said(version: u32) -> String {
    if version == porthole_core::ipc::PROTOCOL_VERSION_ABSENT {
        "the helper answers no protocol version at all, which is what a porthole helper \
         from before this contract does"
            .to_string()
    } else {
        format!("the helper speaks porthole's protocol {version}")
    }
}

/// Start again from the binary on disk, which after a package upgrade is
/// the new one -- and return only if that could not be done.
///
/// This is the whole reason the version is on the wire. The common case by
/// far is a session agent that outlived a package upgrade: its own remedy
/// is to be replaced by the agent that is now installed, and it is the one
/// remedy of the two that needs nobody's privilege and nobody's attention.
/// A blind restart could not be offered before, because nothing said which
/// half was old and guessing wrong shows a notice five times over against a
/// helper left behind by the same upgrade.
///
/// **At most once per helper version**, through [`REEXECED`], and that
/// bound is not theoretical: a machine whose installed agent really is the
/// older half answers the same way every time. Per *version* rather than per
/// process, so that a second upgrade in one session is repaired like the
/// first -- see [`REEXECED`].
///
/// **The path, not `/proc/self/exe`.** That symlink names the *inode*, and
/// after an upgrade the inode is still this old binary -- re-running it
/// would be the loop above with extra steps. `current_exe` reads the
/// symlink's text, which for a replaced file is `<path> (deleted)`
/// (measured on this machine: a `mv` over a running binary, which is what
/// rpm and dpkg do, and the stripped path is the new file). See
/// [`binary_on_disk`].
fn replace_this_agent(helper_version: u32) {
    use std::os::unix::process::CommandExt as _;

    if already_tried_for(helper_version) {
        eprintln!(
            "porthole-agent: the helper speaks porthole's protocol {helper_version} and this \
             agent speaks {PROTOCOL_VERSION}; an agent in this session has already started \
             itself afresh for that same helper version and is still the older half, so the \
             porthole-agent installed here is the one from before the upgrade. Not trying \
             again -- carrying on, and a message this agent cannot read will say so on \
             screen"
        );
        return;
    }
    let Some(path) = std::env::current_exe()
        .inspect_err(|e| {
            eprintln!("porthole-agent: could not find its own binary on disk ({e})");
        })
        .ok()
        .and_then(|current| binary_on_disk(&current))
    else {
        eprintln!(
            "porthole-agent: the helper speaks porthole's protocol {helper_version} and this \
             agent speaks {PROTOCOL_VERSION}, but this agent's own binary is not where it \
             was started from any more, so there is nothing to start instead of it"
        );
        return;
    };
    eprintln!(
        "porthole-agent: the helper speaks porthole's protocol {helper_version} and this \
         agent speaks {PROTOCOL_VERSION}, so this agent is the older half; re-executing \
         {} , which is the binary an upgrade has already replaced",
        path.display()
    );
    // Returns only on failure: on success this process is gone. The bus
    // connections go with it -- their sockets are close-on-exec -- so the
    // session name is released and the agent started here takes it back
    // through `claim_session`'s own `ReplaceExisting`.
    let e = std::process::Command::new(&path)
        .args(std::env::args_os().skip(1))
        .env(REEXECED, helper_version.to_string())
        .exec();
    eprintln!(
        "porthole-agent: could not re-execute {}: {e}; carrying on as the older half",
        path.display()
    );
}

/// Whether an agent in this session has already replaced itself for a helper
/// at least this new.
///
/// `>=` rather than `==`, so the bound cannot be walked around by a helper
/// that goes *backwards*: a downgrade to a version still ahead of this build
/// is the same unrepairable situation as the one already tried, and trying
/// again would be the loop the marker exists to stop. A helper that moves
/// *forward* is a new upgrade, and gets its own attempt.
///
/// A value that is not a number at all counts as "already tried": it did not
/// come from [`replace_this_agent`], and guessing about it in the direction
/// that re-executes is the direction that can loop.
fn already_tried_for(helper_version: u32) -> bool {
    let Ok(value) = std::env::var(REEXECED) else {
        return false;
    };
    match value.trim().parse::<u32>() {
        Ok(tried) => tried >= helper_version,
        Err(_) => true,
    }
}

/// Where this process's own binary is **now**, given what `current_exe`
/// reported.
///
/// Measured on this machine rather than assumed, because the whole
/// re-execution depends on it. `current_exe` reads
/// `readlink("/proc/self/exe")`, a link to the running *inode*; replace the
/// file under a running process the way a package upgrade does (`mv` over
/// it) and the link's text becomes `<path> (deleted)` while `<path>` itself
/// is the new file. So:
///
/// - an ordinary path that still exists is itself;
/// - `<path> (deleted)` where `<path>` exists is `<path>` -- the upgraded
///   binary, which is the one worth starting;
/// - anything else is `None`, including `<path> (deleted)` where the path
///   has simply been removed (measured too: a plain `rm` gives the same
///   suffix and leaves nothing behind). Starting the deleted inode would
///   start this same old binary again.
///
/// A file genuinely named `... (deleted)` is not confused with either: the
/// first branch finds it, because it exists.
fn binary_on_disk(current: &Path) -> Option<PathBuf> {
    if current.exists() {
        return Some(current.to_path_buf());
    }
    let replaced = PathBuf::from(current.to_str()?.strip_suffix(" (deleted)")?);
    replaced.exists().then_some(replaced)
}

/// The rule behind the notification with this id, newest first.
///
/// Newest rather than first-found, and the reason is the whole of
/// [`Pending`]'s own doc: an id is unique within one run of one notification
/// server, and an entry outliving that run can collide with a fresh one. The
/// newest entry with an id is the notification on the screen; an older one
/// is a notification the user cannot see and did not click. Backwards, this
/// opens a port the user never looked at while they believe they authorized
/// the one they did.
fn newest_with_id(pending: &Pending, id: u32) -> Option<&WireRule> {
    pending
        .iter()
        .rev()
        .find(|(pending_id, _)| *pending_id == id)
        .map(|(_, rule)| rule)
}

/// One `RuleClosed`.
async fn on_close(
    notifications: &NotificationsProxy<'_>,
    pending: &mut Pending,
    rule: &WireRule,
    reason: porthole_core::ipc::CloseReason,
    uid: u32,
) {
    if !notify::should_notify(rule, uid) || !notify::is_worth_announcing(reason) {
        return;
    }
    let n = notify::notification_for(rule, reason);
    match notify::show(notifications, &n).await {
        Ok(id) => {
            // The only record that a close was actually announced to
            // somebody. A `Notify` that returns an id has been accepted by a
            // server; what the server then did with it is not visible here.
            eprintln!(
                "porthole-agent: notified about {}/{} ({reason}) as #{id}",
                rule.port, rule.protocol
            );
            if !n.actions.is_empty() {
                if pending.len() >= MAX_PENDING {
                    pending.remove(0);
                }
                pending.push((id, rule.clone()));
            }
        }
        // The one failure this must survive rather than report: a session
        // with no notification service answers every `Notify` this way, and
        // a user unit that gave up here would be restarted into the same
        // session to fail again. The journal still records what closed.
        Err(e) => eprintln!(
            "porthole-agent: {}/{} closed ({reason}) but could not be shown: {e}",
            rule.port, rule.protocol
        ),
    }
}

/// One `ActionInvoked`.
///
/// Spawned rather than awaited: `open` goes through polkit, which can sit on
/// a password prompt for as long as the user takes to answer it, and the
/// signal loop must keep reading meanwhile.
fn on_action(
    porthole: &PortholeProxy<'static>,
    notifications: &NotificationsProxy<'static>,
    pending: &Pending,
    id: u32,
    key: &str,
) {
    if key != REOPEN {
        return;
    }
    let Some(rule) = newest_with_id(pending, id) else {
        eprintln!("porthole-agent: a reopen arrived for a notification this no longer holds");
        return;
    };
    let porthole = porthole.clone();
    let notifications = notifications.clone();
    let rule = rule.clone();
    tokio::spawn(async move { reopen(porthole, notifications, rule).await });
}

/// Which request a `Reopen` re-sends, and everything it carries.
///
/// One shape for both acts, because everything but the last field is the
/// same in both -- see [`reopen_request`] for why the last field is decided
/// from the rule and not from the reason the notification was about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReopenRequest {
    port: u16,
    protocol: String,
    scope: String,
    seconds: u32,
    /// `Some` for a rule that redirects: the port Docker publishes the
    /// container on, which is the number the original request named and the
    /// number the helper resolves a container address from, afresh, each
    /// time it acts. `None` for a rule that only permits.
    published_port: Option<u16>,
}

/// What re-sending this rule's own request means.
///
/// Decided from the rule, never from the [`porthole_core::ipc::CloseReason`]
/// that put the notification on screen. The two are not interchangeable: a
/// forward can expire like anything else, and until this existed a `Reopen`
/// on an expired *forward* sent `open` for its external port -- permitting
/// the local network to a port on this machine that nothing answers on,
/// while the user believed they had restored the redirect they were looking
/// at. `CloseReason::TargetGone` only made that path easier to reach; it did
/// not create it.
///
/// Which of the two a rule was is [`WireRule::redirects`]'s question, asked
/// here through that one method rather than re-derived from
/// `container_addr` a second time -- the notification's own wording asks it
/// too, and so does `porthole-gui`'s row, and a rule described as one act
/// and re-sent as the other is exactly what copies of this predicate
/// eventually produce. It lives on `WireRule` in `porthole_core::ipc`, which
/// is where the sentinel is defined.
fn reopen_request(rule: &WireRule) -> ReopenRequest {
    ReopenRequest {
        port: rule.port,
        protocol: rule.protocol.clone(),
        scope: reopen_scope(rule),
        seconds: original_duration(rule),
        published_port: rule.redirects().then_some(rule.published_port),
    }
}

/// Re-send the original request: the same port, the same protocol, the same
/// scope, and the same length of time -- as an `open` for a rule that only
/// permitted, and as a `forward` for one that redirected.
///
/// A forward is re-sent by its **published port**, never by the container
/// address the closed rule happened to hold. That address is the one thing
/// about a forward that porthole refuses to carry forward on its own (see
/// `CloseReason::TargetGone`), and the helper resolving it again from
/// Docker's own table is the whole reason a gone container is something a
/// click can recover from at all.
///
/// polkit will ask again where the scope warrants it -- and for a forward it
/// asks every time, whatever the scope. That is the point of polkit asking,
/// not an obstacle: this is a fresh request, made because someone clicked a
/// button, and it is authorized as one.
async fn reopen(
    porthole: PortholeProxy<'static>,
    notifications: NotificationsProxy<'_>,
    rule: WireRule,
) {
    let request = reopen_request(&rule);
    let outcome = match request.published_port {
        Some(published_port) => {
            porthole
                .forward(
                    request.port,
                    &request.protocol,
                    &request.scope,
                    request.seconds,
                    published_port,
                )
                .await
        }
        None => {
            porthole
                .open(
                    request.port,
                    &request.protocol,
                    &request.scope,
                    request.seconds,
                )
                .await
        }
    };
    match outcome {
        Ok(reopened) => eprintln!(
            "porthole-agent: reopened {}/{} towards {}",
            reopened.port, reopened.protocol, reopened.target
        ),
        Err(e) => {
            let failure = notify::Notification {
                summary: format!("Could not reopen port {}/{}", rule.port, rule.protocol),
                body: format!("{e}"),
                actions: Vec::new(),
            };
            if let Err(e2) = notify::show(&notifications, &failure).await {
                eprintln!("porthole-agent: reopen failed ({e}), and so did saying so ({e2})");
            }
        }
    }
}

/// The scope string the helper's own parser takes, rebuilt from the rule.
///
/// A `network` rule carries its CIDR, which parses back to exactly itself --
/// including a single host, which is stored as a `/32`. An `anywhere` rule's
/// target renders as the word `anywhere`, and that is not a spelling the
/// parser accepts: `any` is.
fn reopen_scope(rule: &WireRule) -> String {
    if rule.scope == "anywhere" {
        "any".to_string()
    } else {
        rule.target.clone()
    }
}

/// How long the rule was opened for -- not the moment it would have ended.
///
/// `0` means until-reboot in both directions: on the wire it is
/// `expires_at`'s "no expiry" sentinel, and in `open`'s `seconds` it is the
/// until-reboot lifetime. A rule whose recorded expiry precedes its own
/// opening cannot produce a negative duration here; it produces zero, which
/// is the until-reboot request, so the saturation is spelled out rather than
/// left to wrap.
fn original_duration(rule: &WireRule) -> u32 {
    if rule.expires_at == 0 {
        return 0;
    }
    u32::try_from(rule.expires_at.saturating_sub(rule.opened_at)).unwrap_or(u32::MAX)
}

/// Watch for this connection losing [`AGENT_SERVICE`] to somebody else.
///
/// Created **before** [`claim_session`] requests the name, which is
/// `Connection::request_name_with_flags`'s own documented caveat: a
/// `NameLost` emitted between the request and the stream's creation is one
/// this process never sees.
///
/// An agent that cannot watch for this must not start at all. It would be
/// replaceable and unable to notice it had been replaced, which is a live
/// second agent announcing every close twice -- the one thing the name exists
/// to prevent.
async fn watch_for_replacement(session: &zbus::Connection) -> Option<zbus::fdo::NameLostStream> {
    let dbus = zbus::fdo::DBusProxy::new(session)
        .await
        .inspect_err(|e| eprintln!("porthole-agent: could not bind the bus's own interface: {e}"))
        .ok()?;
    dbus.receive_name_lost()
        .await
        .inspect_err(|e| {
            eprintln!(
                "porthole-agent: could not watch for a newer agent taking {AGENT_SERVICE}, and \
                 an agent that cannot notice it was replaced would announce every close \
                 twice; stopping: {e}"
            )
        })
        .ok()
}

/// Take the session-bus name that means "this session's agent is this one",
/// taking it from an older agent if one holds it.
///
/// **`ReplaceExisting` and `AllowReplacement`, added after an upgrade left a
/// user with no notifications at all.** An agent from a previous login held
/// the name -- the user bus outlives a login session, so it can -- and every
/// agent started since, including the one `systemctl --user restart` started,
/// found the name taken and exited. `restart` could not help: the stale
/// process is not the unit's, so systemd had nothing to stop. The failure was
/// silent, and the running agent was the one from before the upgrade.
///
/// That agent was not merely redundant, it was mute, which is why the user
/// saw nothing at all rather than one notification per close. `RuleClosed`
/// carries a [`WireRule`], and the forward feature added three members to it:
/// the body's signature went from `((sqssssttu)s)` to `((sqssssttusqq)s)`.
/// Measured, not inferred -- and measured again afterwards, which corrected
/// the half of this paragraph that used to blame zbus. **zbus delivers the
/// signal.** The typed stream yields it, the stream stays alive and hands
/// over later matching signals normally, and only `args()` refuses, with
/// `Signature mismatch: got ((sqssssttusqq)s), expected ((sqssssttu)s)`. The
/// silence was this binary's own: its loop discarded that error and went
/// round again. It does not any more -- see [`announce_undecodable`], which
/// is now what a stale agent does instead of announcing nothing whatsoever.
///
/// So the newer agent wins. `AllowReplacement` is the half that matters next
/// time: it is what lets the agent after this one take the name from it, and
/// an agent that did not offer it would recreate exactly the situation above.
/// `ReplaceExisting` only works against an owner that offered replacement, so
/// it cannot take the name from a pre-upgrade agent -- that case is the
/// `NameTaken` arm below, which is why that arm now puts something on the
/// screen instead of a line in a journal nobody reads.
///
/// Exactly one agent still owns the name at any moment, so the double
/// announcement the name exists to prevent is still excluded. What replacing
/// costs is a moment: the replaced agent stops when its `NameLost` arrives,
/// and the newer one subscribes to the helper's signals just after taking the
/// name, so a close falling between the two is announced by neither. That
/// direction is the deliberate one -- the alternative order overlaps the two
/// agents' subscriptions instead, and announces some closes twice.
///
/// `DoNotQueue` for the reason it was always here: an agent that cannot have
/// the name must find out now and stop, not sit in a queue and quietly turn
/// into a live second agent later.
async fn claim_session(session: &zbus::Connection) -> bool {
    use zbus::fdo::{RequestNameFlags, RequestNameReply};
    let flags = RequestNameFlags::AllowReplacement
        | RequestNameFlags::ReplaceExisting
        | RequestNameFlags::DoNotQueue;
    match session.request_name_with_flags(AGENT_SERVICE, flags).await {
        Ok(RequestNameReply::PrimaryOwner) => true,
        // Measured rather than assumed: with `DoNotQueue`, this zbus reports
        // a name somebody else holds as `Error::NameTaken` and not as one of
        // the other replies. Both readings say the same thing, so both are
        // handled here rather than one of them falling through to the
        // catch-all below and being reported as a bus failure.
        //
        // With `ReplaceExisting` above, reaching this arm means the holder
        // refused to be replaced -- so it is not an agent of this version,
        // and the user is about to have no notifications without being told.
        // Hence the notice: see `notify::stale_agent_notice`.
        Ok(_) | Err(zbus::Error::NameTaken) => {
            eprintln!(
                "porthole-agent: {AGENT_SERVICE} is held by something that will not give it \
                 up, so this agent is stopping; a porthole-agent of this version would have \
                 yielded, so that is most likely an older one still running"
            );
            announce_stale_agent(session).await;
            false
        }
        Err(e) => {
            eprintln!("porthole-agent: could not claim {AGENT_SERVICE}, so stopping: {e}");
            false
        }
    }
}

/// Put [`notify::stale_agent_notice`] on the screen, if there is a screen.
///
/// Best effort by construction: this runs while the agent is giving up, and
/// a session with no notification service is exactly the session where the
/// journal line above is all there can be. Failing to show it must not turn
/// a quiet stop into a noisy one.
/// Say on screen that this agent cannot read what the helper sends, on its
/// way out.
///
/// **Why it stops rather than skips.** Both places that reach here have
/// established the same thing: the helper and this binary disagree about the
/// shape of `WireRule`, which every `RuleClosed` carries. That does not go
/// away with the next signal -- the next one is the same shape -- so an
/// agent that skipped one would skip all of them, which is precisely the
/// failure that was reported: no desktop notification at all, for any close,
/// in complete silence, from a still-running agent left over from before an
/// upgrade. Carrying on is not a lesser action here; it is the whole defect.
///
/// **Why on screen and not only in the journal.** The same reason
/// [`notify::stale_agent_notice`] is: the failure is invisible by
/// construction. Ports still open and close on time, nothing crashes, the
/// unit reads `inactive (dead)` exactly as it would after any ordinary
/// stop. The one place it shows is a journal nobody opens unprompted -- and
/// this agent had already written a line there, `could not reach the helper
/// (...); listening anyway`, and nobody saw it.
///
/// **Why `SUCCESS` and not a restart.** `Restart=on-failure` would be a
/// guess about which of the two binaries is the old one, and nothing here
/// knows: `SignatureMismatch` names two signatures and says nothing about
/// which is newer (see [`porthole_core::ipc::is_undecodable`]). Guessing
/// wrong loops -- an upgrade on Debian or Arch leaves the *helper* running
/// from before it, and against that helper a fresh agent fails identically,
/// five times over, showing this notice at each attempt until systemd's
/// start limit stops it. So the unit stays stopped, as it does for every
/// other start-up refusal here, and the notice says what to do instead.
async fn announce_undecodable(notifications: &NotificationsProxy<'_>, helper: Option<Alignment>) {
    if let Err(e) = notify::show(notifications, &notify::undecodable_notice(helper)).await {
        eprintln!("porthole-agent: and could not say so on screen either: {e}");
    }
}

/// The next owner of the helper's name, or a future that never finishes
/// when nothing is watching for one.
///
/// `std::future::pending` rather than an empty stream: a `select!` branch
/// over a stream that has ended is ready immediately and forever, which
/// would spin the loop at whatever speed the machine allows. Failing to
/// install that match rule is not fatal here -- the agent keeps announcing
/// closes -- so the branch has to be inert rather than absent.
async fn next_owner(
    owners: &mut Option<zbus::proxy::OwnerChangedStream<'_>>,
) -> Option<Option<zbus::names::UniqueName<'static>>> {
    match owners {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

async fn announce_stale_agent(session: &zbus::Connection) {
    let shown = match NotificationsProxy::new(session).await {
        Ok(proxy) => notify::show(&proxy, &notify::stale_agent_notice()).await,
        Err(e) => Err(e),
    };
    if let Err(e) = shown {
        eprintln!("porthole-agent: and could not say so on screen either: {e}");
    }
}

fn current_uid() -> u32 {
    // SAFETY: getuid takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lost_system_bus_and_a_lost_session_bus_do_not_share_an_exit_status() {
        // `Restart=on-failure` in data/porthole-agent.service brings a new
        // agent after a lost system bus and leaves a closing session alone.
        // It can only tell those apart by this number, so collapsing the two
        // would either strand the user without notifications or restart an
        // agent every time they log out.
        assert_eq!(Ended::SystemBus.exit_code(), 1);
        assert_eq!(Ended::SessionBus.exit_code(), 0);
        // And being replaced is not a failure either. `on-failure` here would
        // start an agent that takes the name straight back from the one that
        // just took it, and the two would trade it until the start limit
        // stopped them.
        assert_eq!(Ended::Replaced.exit_code(), 0);
        // And a helper this agent cannot read is not a restart either --
        // see `announce_undecodable` for why a restart there is a guess
        // about which of the two binaries is old, and what it costs when
        // the guess is wrong.
        assert_eq!(Ended::Undecodable.exit_code(), 0);
    }

    #[test]
    fn each_stopping_reason_says_which_bus_it_lost() {
        // The journal line is the only record of why an agent stopped.
        assert!(Ended::SystemBus.reason().contains("system bus"));
        assert!(Ended::SessionBus.reason().contains("session bus"));
        // This one lost no bus, and must not read as though it had: the
        // agent is fine, it simply is not the session's agent any more.
        let replaced = Ended::Replaced.reason();
        assert!(replaced.contains("newer agent"), "{replaced}");
        assert!(
            !replaced.contains("bus connection ended"),
            "a replaced agent's connections are both alive: {replaced}"
        );
        // This one lost no bus either, and its connections are both alive
        // too: what it lost is the ability to read what arrives on one of
        // them. A journal line that read as a bus failure would send the
        // reader looking for the wrong thing entirely.
        let undecodable = Ended::Undecodable.reason();
        assert!(undecodable.contains("could not read"), "{undecodable}");
        assert!(
            !undecodable.contains("bus connection ended"),
            "the bus is fine; the message on it is not: {undecodable}"
        );
    }

    #[test]
    fn the_binary_to_restart_is_the_one_on_disk_and_never_the_running_inode() {
        // Measured on this machine, because the whole re-execution rests on
        // it: `mv` a new file over a running binary -- which is what rpm
        // and dpkg do -- and `readlink /proc/<pid>/exe`, which is what
        // `current_exe` reads, comes back as `<path> (deleted)` while
        // `<path>` is the *new* file. A re-execution that took the link at
        // face value would either fail to find anything or, going through
        // `/proc/self/exe` itself, run the same old inode again -- which is
        // the loop this whole path exists to avoid.
        let dir = tempfile::TempDir::new().expect("a temp dir");
        let live = dir.path().join("porthole-agent");
        std::fs::write(&live, b"#!/bin/sh\n").expect("writable");

        assert_eq!(
            binary_on_disk(&live),
            Some(live.clone()),
            "an ordinary path that is still there is itself"
        );

        let replaced = dir.path().join("porthole-agent (deleted)");
        assert_eq!(
            binary_on_disk(&replaced),
            Some(live.clone()),
            "and the upgraded file is what the deleted inode's own path names"
        );

        // The other half of the measurement: a plain `rm` produces the same
        // suffix and leaves nothing behind. Starting the deleted inode
        // would start this same old binary, so there is nothing to start.
        std::fs::remove_file(&live).expect("removable");
        assert_eq!(binary_on_disk(&replaced), None);
        assert_eq!(binary_on_disk(&live), None);

        // And a file that really is called `... (deleted)` is itself, not
        // the path with the suffix cut off: it exists, so nothing is cut.
        std::fs::write(&replaced, b"#!/bin/sh\n").expect("writable");
        assert_eq!(binary_on_disk(&replaced), Some(replaced));
    }

    /// An arbitrary but fixed opening time, so a duration in a check below
    /// reads as a duration rather than as the difference of two literals.
    const OPENED: u64 = 1_757_000_000;

    fn rule(scope: &str, target: &str, opened_at: u64, expires_at: u64) -> WireRule {
        WireRule {
            id: "abc".to_string(),
            port: 5173,
            protocol: "tcp".to_string(),
            target: target.to_string(),
            scope: scope.to_string(),
            backend: "firewalld".to_string(),
            opened_at,
            expires_at,
            uid: 1000,
            // Not a forward: an empty address is what says so.
            container_addr: String::new(),
            container_port: 0,
            published_port: 0,
        }
    }

    #[test]
    fn a_click_reopens_the_notification_on_the_screen_not_one_that_outlived_a_restart() {
        // A notification id is unique within one run of one notification
        // server. Restart the server and it starts numbering again, so an
        // entry that outlived the restart can carry the id of one added
        // after it. Matching the first entry found would reopen 5173 while
        // the user is looking at a notification about 8080 and believes that
        // is what they authorized.
        let stale = rule("network", "10.10.10.0/24", 0, 0);
        let live = WireRule {
            port: 8080,
            ..rule("network", "192.168.1.0/24", 0, 0)
        };
        let pending: Pending = vec![(7, stale), (7, live)];

        assert_eq!(
            newest_with_id(&pending, 7).map(|r| r.port),
            Some(8080),
            "the newest entry with the id is the notification on the screen"
        );
        assert_eq!(newest_with_id(&pending, 8), None);
        assert_eq!(newest_with_id(&Pending::new(), 7), None);
    }

    #[test]
    fn a_reopen_sends_the_scope_the_helpers_parser_accepts() {
        // The wire form renders `Target::Anywhere` as the word `anywhere`,
        // and `porthole_core::validate::parse_scope` does not take that word.
        // Sending it back verbatim would turn every reopen of an open-to-
        // everyone rule into an invalid-argument error.
        assert_eq!(reopen_scope(&rule("anywhere", "anywhere", 0, 0)), "any");
        assert_eq!(
            reopen_scope(&rule("network", "10.10.10.0/24", 0, 0)),
            "10.10.10.0/24"
        );
        assert_eq!(
            reopen_scope(&rule("network", "10.10.10.5/32", 0, 0)),
            "10.10.10.5/32"
        );
    }

    #[test]
    fn a_reopen_of_a_forward_re_sends_a_forward_and_never_an_open() {
        // The harm this prevents: `open` on a forward's external port
        // permits the local network to a port on this machine that nothing
        // answers on -- the redirect is what made that port mean anything,
        // and it is gone. The user clicked a button on a notification about
        // a redirect and would have got a plain hole instead.
        //
        // The published port is what goes back, not the container address
        // the closed rule held: the helper resolves the container from
        // Docker's own table when it acts, which is the only reason a
        // container that moved is recoverable at one click.
        let forward = WireRule {
            port: 8443,
            container_addr: "172.18.0.2".to_string(),
            container_port: 8080,
            published_port: 3000,
            ..rule("network", "10.10.10.0/24", OPENED, OPENED + 3600)
        };
        assert_eq!(
            reopen_request(&forward),
            ReopenRequest {
                port: 8443,
                protocol: "tcp".to_string(),
                scope: "10.10.10.0/24".to_string(),
                seconds: 3600,
                published_port: Some(3000),
            }
        );

        // And the other half: a rule that only permits must not acquire a
        // forward out of the two ports, which are `0` on it and are also
        // what a forward to a container port nobody published would carry.
        let permit = rule("network", "10.10.10.0/24", OPENED, OPENED + 3600);
        assert_eq!(reopen_request(&permit).published_port, None);

        // And a forward carrying zeroes in both ports is still a forward.
        // The address is the only field that can say which act a rule was,
        // which is exactly why the wire uses it as the sentinel.
        let odd = WireRule {
            container_port: 0,
            published_port: 0,
            ..forward
        };
        assert_eq!(reopen_request(&odd).published_port, Some(0));
    }

    #[test]
    fn a_reopen_sends_the_original_duration_not_the_original_deadline() {
        // An hour-long rule reopens for an hour, whenever it is clicked --
        // not until the instant the first one would have ended, which is in
        // the past by the time the notification is on screen.
        assert_eq!(
            original_duration(&rule(
                "network",
                "10.10.10.0/24",
                1_757_000_000,
                1_757_003_600
            )),
            3600
        );
        assert_eq!(
            original_duration(&rule("network", "10.10.10.0/24", 1_757_000_000, 0)),
            0,
            "0 is until-reboot on the wire and until-reboot in the request"
        );
        assert_eq!(
            original_duration(&rule(
                "network",
                "10.10.10.0/24",
                1_757_003_600,
                1_757_000_000
            )),
            0,
            "an expiry before its own opening asks for nothing, never a wrapped duration"
        );
    }
}
