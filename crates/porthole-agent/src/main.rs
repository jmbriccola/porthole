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
//! It does own one session-bus name, and only to refuse to be started twice.
//! porthole ships both a systemd user unit and an XDG autostart entry,
//! because desktops differ in which they honour, and a desktop that honours
//! both would otherwise show every close twice. Whichever copy loses the
//! name says so and exits.
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
//! original `open` with the original duration, and a bus with no notification
//! service at all leaves the process running. What none of that touches is a
//! real notification daemon (the stand-in answers `Notify` and emits
//! `ActionInvoked`, it does not draw anything), the real helper, or polkit --
//! so "the prompt appears and the port comes back" is not covered by any test
//! in this repository.
//!
//! The start-up ordering above is not covered either. All three tests bring
//! their stand-in helper up before the agent, so none of them exercises an
//! agent whose subscription is what the helper is started into, and nothing
//! here would fail if that ordering were reversed.

mod notify;

use futures_util::StreamExt;
use notify::{NotificationsProxy, REOPEN};
use porthole_core::ipc::{PortholeProxy, WireRule};

/// The session-bus name one agent per session holds. Not an interface: this
/// process serves nothing, and the name exists only so a second copy can
/// discover it is a second copy. Deliberately not the helper's own
/// `com.jacopobriccola.Porthole`, which is a system-bus name owned by
/// something else entirely.
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let uid = current_uid();

    let session = match zbus::Connection::session().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("porthole-agent: no session bus, so nothing to notify on: {e}");
            return;
        }
    };
    // First, and before anything is woken or subscribed to: a second agent
    // in one session would show every close twice.
    if !claim_session(&session).await {
        return;
    }

    let system = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("porthole-agent: no system bus, so nothing to listen to: {e}");
            return;
        }
    };
    let porthole = match PortholeProxy::new(&system).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("porthole-agent: could not bind the helper's interface: {e}");
            return;
        }
    };
    // Awaited here, before the `list` below: this is the call that installs
    // the match rule, and the ordering above is the whole point of it.
    let mut closes = match porthole.receive_rule_closed().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("porthole-agent: could not subscribe to the helper's signals: {e}");
            return;
        }
    };

    let notifications = match NotificationsProxy::new(&session).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("porthole-agent: could not bind the notification interface: {e}");
            return;
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
            return;
        }
    };

    // The cue to forget every id in `pending`: they are only meaningful
    // within one run of one notification server. See [`Pending`].
    let mut owners = match notifications.inner().receive_owner_changed().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("porthole-agent: could not watch the notification service's owner: {e}");
            return;
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
    // bus is a process nothing will ever wake again. Nothing restarts it:
    // `data/porthole-agent.service` sets no `Restart=`, so this is a stop
    // and not a bounce, and the line it prints is the only record of why.
    let mut pending: Pending = Vec::new();
    loop {
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
            close = closes.next() => {
                let Some(signal) = close else {
                    eprintln!("porthole-agent: the system bus connection ended; stopping");
                    break;
                };
                let Ok(args) = signal.args() else { continue };
                on_close(&notifications, &mut pending, args.rule(), *args.reason(), uid).await;
            }
            action = actions.next() => {
                let Some(signal) = action else {
                    eprintln!("porthole-agent: the session bus connection ended; stopping");
                    break;
                };
                let Ok(args) = signal.args() else { continue };
                on_action(&porthole, &notifications, &pending, args.id, args.action_key);
            }
            dismissal = dismissals.next() => {
                let Some(signal) = dismissal else {
                    eprintln!("porthole-agent: the session bus connection ended; stopping");
                    break;
                };
                let Ok(args) = signal.args() else { continue };
                pending.retain(|(id, _)| *id != args.id);
            }
        }
    }
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

/// Re-send the original `open`: the same port, the same protocol, the same
/// scope, and the same length of time.
///
/// polkit will ask again where the scope warrants it. That is the point of
/// polkit asking, not an obstacle: this is a fresh request to open a port,
/// made because someone clicked a button, and it is authorized as one.
async fn reopen(
    porthole: PortholeProxy<'static>,
    notifications: NotificationsProxy<'_>,
    rule: WireRule,
) {
    let scope = reopen_scope(&rule);
    let seconds = original_duration(&rule);
    match porthole
        .open(rule.port, &rule.protocol, &scope, seconds)
        .await
    {
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

/// Take the session-bus name that means "this session already has an agent",
/// or report that somebody else has it.
///
/// `DoNotQueue` rather than the default: a second agent must find out now and
/// stop, not sit in a queue waiting to inherit the name if the first one ever
/// exits, quietly turning into a live second agent later.
///
/// Anything other than becoming the primary owner is a reason to stop, and
/// that includes a bus that refuses the request outright -- there is no
/// reading of either outcome under which starting a second notifier is the
/// better answer.
async fn claim_session(session: &zbus::Connection) -> bool {
    use zbus::fdo::{RequestNameFlags, RequestNameReply};
    match session
        .request_name_with_flags(AGENT_SERVICE, RequestNameFlags::DoNotQueue.into())
        .await
    {
        Ok(RequestNameReply::PrimaryOwner) => true,
        // Measured rather than assumed: with `DoNotQueue`, this zbus reports
        // a name somebody else holds as `Error::NameTaken` and not as one of
        // the other replies. Both readings say the same thing, so both are
        // handled here rather than one of them falling through to the
        // catch-all below and being reported as a bus failure.
        Ok(_) | Err(zbus::Error::NameTaken) => {
            eprintln!(
                "porthole-agent: this session already has an agent ({AGENT_SERVICE} is taken); \
                 stopping so closes are not announced twice"
            );
            false
        }
        Err(e) => {
            eprintln!("porthole-agent: could not claim {AGENT_SERVICE}, so stopping: {e}");
            false
        }
    }
}

fn current_uid() -> u32 {
    // SAFETY: getuid takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

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
