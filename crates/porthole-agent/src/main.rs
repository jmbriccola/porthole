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
//! to yield puts a notice on the screen. What none of that touches is a
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
use porthole_core::ipc::{PortholeProxy, WireRule};

/// The session-bus name one agent per session holds. Not an interface: this
/// process serves nothing, and the name exists only so that a session's
/// agents can settle which of them is the agent -- see [`claim_session`].
/// Deliberately not the helper's own `com.jacopobriccola.Porthole`, which is
/// a system-bus name owned by something else entirely.
const AGENT_SERVICE: &str = "com.jacopobriccola.PortholeAgent";

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
            Ended::SessionBus | Ended::Replaced => 0,
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

    // Not for its answer. Calling the helper is what starts it, and the
    // subscription above already exists, so whatever its start-up sweep
    // announces arrives here instead of being sent to nobody. A failure is
    // ordinary -- no helper installed, or none activatable -- and changes
    // nothing about what this process does next.
    if let Err(e) = porthole.list().await {
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
            // Ahead of the three below on purpose. A newer agent has the
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
            close = closes.next() => {
                let Some(signal) = close else {
                    break Ended::SystemBus;
                };
                let Ok(args) = signal.args() else { continue };
                on_close(&notifications, &mut pending, args.rule(), *args.reason(), uid).await;
            }
            action = actions.next() => {
                let Some(signal) = action else {
                    break Ended::SessionBus;
                };
                let Ok(args) = signal.args() else { continue };
                on_action(&porthole, &notifications, &pending, args.id, args.action_key);
            }
            dismissal = dismissals.next() => {
                let Some(signal) = dismissal else {
                    break Ended::SessionBus;
                };
                let Ok(args) = signal.args() else { continue };
                pending.retain(|(id, _)| *id != args.id);
            }
        }
    };

    eprintln!("porthole-agent: {}", ended.reason());
    std::process::ExitCode::from(ended.exit_code())
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
/// That agent was not merely redundant, it was deaf, which is why the user
/// saw nothing at all rather than one notification per close. `RuleClosed`
/// carries a [`WireRule`], and the forward feature added three members to it:
/// the body's signature went from `((sqssssttu)s)` to `((sqssssttusqq)s)`,
/// and zbus refuses the whole signal on a signature mismatch. Measured, not
/// inferred -- a message built with the current type and read with the old
/// one answers `Signature mismatch: got ((sqssssttusqq)s), expected
/// ((sqssssttu)s)`, and this binary's own loop drops a signal whose `args()`
/// fails. So a stale agent holding the name announces nothing whatsoever.
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
