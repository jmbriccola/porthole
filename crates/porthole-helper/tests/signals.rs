//! The signals, over a real bus, received by a real subscriber.
//!
//! # What each half of this file proves, and what it does not
//!
//! The tests in the first half use the *ambient* session bus, a probe name of
//! their own, and the same `announce_*` functions
//! `porthole_helper::service::Porthole`'s own methods call. They prove the
//! declaration, the payload and the subscribe-and-receive path: a signal
//! emitted by the helper's own code arrives at an ordinary client that asked
//! for it, carrying what it is supposed to carry.
//!
//! **What they do not prove is that `open` reaches its own `announce_open`
//! call.** An `open` that gets that far has to have changed a real firewall,
//! which nothing in this workspace may do on a development host. Two things
//! stand in for it. The close paths below drive the real methods and show
//! that the ones which close nothing announce nothing, so the emission is
//! not unconditional. And `crates/porthole-cli/tests/container.rs` drives
//! every emitting path against a real firewalld inside a container, gated
//! behind `PORTHOLE_CONTAINER_TESTS=1` so none of it runs here:
//! `signals_reach_a_subscriber_when_a_port_is_opened_and_closed` (an open,
//! an ordinary close, the expiry timer's close and `close --all`),
//! `the_start_up_sweep_announces_what_it_dropped`, and
//! `a_subnet_the_machine_left_is_announced_along_with_the_rules_it_closed`.
//!
//! The second half starts its own `dbus-daemon` on a config that includes the
//! shipped `data/com.jacopobriccola.Porthole.conf`, and checks what that
//! policy does to a signal in flight. Never the system bus: every daemon here
//! is a private session bus this file starts and kills.

use futures_util::StreamExt;
use porthole_core::backend::{BackendId, RuleHandle};
use porthole_core::cli_path::CLI_CANDIDATES;
use porthole_core::command::RealRunner;
use porthole_core::ipc::{CloseReason, PortholeProxy, PATH, SERVICE};
use porthole_core::model::{Protocol, Target};
use porthole_core::state::{ManagedRule, StateStore};
use porthole_helper::authz::AlwaysAllow;
use porthole_helper::service::Porthole;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use zbus::object_server::SignalEmitter;

/// Long enough that a loaded machine does not fail a test that would have
/// passed, short enough that a genuinely missing signal is not a five-minute
/// wait.
const ARRIVES_WITHIN: Duration = Duration::from_secs(5);

/// How long a "nothing must arrive" assertion waits before believing it.
/// Shorter on purpose: every one of them is paired with a positive test on
/// the same bus that shows a signal does arrive well inside
/// [`ARRIVES_WITHIN`], so this is not the interval a real signal would need.
const STAYS_SILENT_FOR: Duration = Duration::from_millis(750);

/// A unique bus name per test, so tests can run in parallel and none of them
/// ever squats the production name. Exactly what `tests/service.rs` does, and
/// for the same reason.
fn probe_name(suffix: &str) -> String {
    format!("com.jacopobriccola.PortholeTest{suffix}")
}

/// Serve the real service object under a probe name on the ambient session
/// bus, and hand back a connection signals can be emitted from.
async fn serve(suffix: &str, state: &Path) -> (zbus::Connection, String) {
    let bus = zbus::Connection::session().await.unwrap();
    let service = Porthole::new(
        Box::new(Arc::new(AlwaysAllow::default())),
        bus,
        state.to_path_buf(),
        std::path::PathBuf::from(CLI_CANDIDATES[0]),
    );
    let name = probe_name(suffix);
    let conn = zbus::connection::Builder::session()
        .unwrap()
        .name(name.clone())
        .unwrap()
        .serve_at(PATH, service)
        .unwrap()
        .build()
        .await
        .unwrap();
    (conn, name)
}

async fn proxy_to(name: &str) -> PortholeProxy<'static> {
    let client = zbus::Connection::session().await.unwrap();
    PortholeProxy::builder(&client)
        .destination(name.to_string())
        .unwrap()
        .build()
        .await
        .unwrap()
}

fn emitter(conn: &zbus::Connection) -> SignalEmitter<'static> {
    SignalEmitter::new(conn, PATH).unwrap().into_owned()
}

/// The rule a helper decided on, which is deliberately nothing like the
/// request that produced it: the id is minted here, `subnet` has already been
/// resolved to a CIDR, and `--for 1h` has already become an absolute epoch.
fn created_rule() -> ManagedRule {
    ManagedRule {
        id: "9f1c0e6a-3d21-4a77-9c4e-5d2b7a0f8e13".to_string(),
        port: 5173,
        protocol: Protocol::Tcp,
        target: Target::Network {
            cidr: "10.10.10.0/24".parse().unwrap(),
        },
        backend: BackendId::Firewalld,
        opened_at: 1_757_000_000,
        expires_at: Some(1_757_003_600),
        uid: 1000,
        handle: RuleHandle::Firewalld {
            zone: "FedoraWorkstation".to_string(),
            rich_rule: "the exact spec needed to remove this".to_string(),
        },
        forward: None,
    }
}

async fn next_signal<S>(stream: &mut S) -> S::Item
where
    S: futures_util::Stream + Unpin,
{
    tokio::time::timeout(ARRIVES_WITHIN, stream.next())
        .await
        .expect("no signal arrived before the timeout")
        .expect("the signal stream ended instead of yielding")
}

async fn stays_silent<S>(stream: &mut S) -> bool
where
    S: futures_util::Stream + Unpin,
{
    tokio::time::timeout(STAYS_SILENT_FOR, stream.next())
        .await
        .is_err()
}

// ---------------------------------------------------------------------------
// The payload
// ---------------------------------------------------------------------------

#[tokio::test]
async fn opening_a_rule_emits_rule_opened_with_the_rule_that_was_created() {
    // Not the request: the rule. They differ -- the id, the resolved target
    // and the expiry are all decided by the helper. A subscriber that
    // rebuilt the notification from what a client asked for ("5173, subnet,
    // one hour") would be showing three things porthole never agreed to.
    //
    // This calls `announce_open`, the one function `Porthole::open` uses to
    // say anything at all; it does not call `open` itself, which would have
    // to change a real firewall to get this far. See this file's own module
    // docs.
    let dir = TempDir::new().unwrap();
    let (server, name) = serve("SigOpened", &dir.path().join("state.json")).await;
    let proxy = proxy_to(&name).await;
    let mut signals = proxy.receive_rule_opened().await.unwrap();

    let created = created_rule();
    Porthole::announce_open(&emitter(&server), &created).await;

    let signal = next_signal(&mut signals).await;
    let rule = signal.args().unwrap().rule;

    assert_eq!(
        rule.id, created.id,
        "the id is minted by the helper; no client ever sent it"
    );
    assert_eq!(
        rule.target, "10.10.10.0/24",
        "the target is the resolved subnet, not the word the client typed"
    );
    assert_eq!(
        rule.expires_at, 1_757_003_600,
        "the expiry is the absolute time the helper chose, not a duration"
    );
    assert_eq!(rule.port, 5173);
    assert_eq!(rule.protocol, "tcp");
    assert_eq!(rule.scope, "network");
    assert_eq!(rule.backend, "firewalld");
}

#[tokio::test]
async fn every_close_carries_why() {
    // "expired", "requested", "network-changed", "reconciled",
    // "target-gone". The notification says something different for each, and
    // a single undifferentiated ClosedSignal would force the agent to guess.
    //
    // `porthole_core::ipc`'s own `every_close_carries_why` pins the slugs
    // and their encoding; this one pins them where a subscriber
    // actually meets them -- on the bus, decoded by the published proxy,
    // paired with the rule they describe.
    let dir = TempDir::new().unwrap();
    let (server, name) = serve("SigWhy", &dir.path().join("state.json")).await;
    let proxy = proxy_to(&name).await;
    let mut signals = proxy.receive_rule_closed().await.unwrap();

    let rule = created_rule();
    let emitter = emitter(&server);

    for (reason, expected) in [
        (CloseReason::Expired, "expired"),
        (CloseReason::Requested, "requested"),
        (CloseReason::NetworkChanged, "network-changed"),
        (CloseReason::Reconciled, "reconciled"),
        (CloseReason::TargetGone, "target-gone"),
    ] {
        Porthole::announce_autoclose(Some(&emitter), &rule, reason).await;

        let signal = next_signal(&mut signals).await;
        let args = signal.args().unwrap();
        assert_eq!(args.reason, reason);
        assert_eq!(
            args.reason.as_str(),
            expected,
            "a subscriber matching on the slug must see exactly {expected}"
        );
        assert_eq!(args.rule.id, rule.id, "the reason travels with its rule");
    }
}

#[tokio::test]
async fn any_user_on_the_bus_may_receive_signals_but_only_the_owner_sees_their_own_rules() {
    // The signal carries a uid. The agent filters on it. A signal is a
    // broadcast, so it must not carry anything a bystander should not see --
    // a port number and a CIDR are already visible to anyone who can run
    // `porthole list`, which polkit allows for everyone.
    //
    // Two independent client connections here, neither of them the emitter,
    // stand in for two subscribers: on one machine's session bus they are
    // the same uid, so what this shows is that a connection that neither
    // emitted nor owns the name still receives the broadcast -- not that two
    // different logins do. What it does show exactly is what such a
    // subscriber gets: the opening uid, so it can decide whether the
    // notification is for the person at the screen, and no `RuleHandle`,
    // which is the one thing on a `ManagedRule` that would let a bystander
    // remove a rule they never created.
    let dir = TempDir::new().unwrap();
    let (server, name) = serve("SigBroadcast", &dir.path().join("state.json")).await;
    let bystander = proxy_to(&name).await;
    let agent = proxy_to(&name).await;
    let mut bystander_signals = bystander.receive_rule_closed().await.unwrap();
    let mut agent_signals = agent.receive_rule_closed().await.unwrap();

    let rule = created_rule();
    Porthole::announce_close(&emitter(&server), &rule, 1001, CloseReason::Requested).await;

    for stream in [&mut bystander_signals, &mut agent_signals] {
        let signal = next_signal(stream).await;
        let args = signal.args().unwrap();
        assert_eq!(
            args.rule.uid, 1000,
            "the opening uid is what an agent filters its notifications on"
        );

        // The removal spec must not be reachable from the broadcast at all.
        let body = format!("{:?}", args.rule);
        assert!(
            !body.contains("the exact spec needed to remove this"),
            "the rule handle rode the broadcast: {body}"
        );
        assert!(!body.contains("rich_rule"), "got: {body}");
    }
}

// ---------------------------------------------------------------------------
// The real methods, on the paths that can run here
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_close_that_finds_nothing_announces_nothing() {
    // Drives the real `close` method over a real bus. It fails -- nothing is
    // open -- and must therefore announce nothing: a `RuleClosed` a
    // subscriber acted on would tell someone a port had stopped being
    // reachable when porthole never closed anything. This is the half of the
    // wiring a development host can check end to end; the positive half
    // needs a firewall it may actually change (the container suite).
    let dir = TempDir::new().unwrap();
    let (_server, name) = serve("SigNoClose", &dir.path().join("state.json")).await;
    let proxy = proxy_to(&name).await;
    let mut signals = proxy.receive_rule_closed().await.unwrap();

    let failed = proxy.close(5173, "tcp").await;
    assert!(failed.is_err(), "nothing is open, so this must fail");
    assert!(
        stays_silent(&mut signals).await,
        "a close that closed nothing announced one anyway"
    );
}

#[tokio::test]
async fn a_record_the_firewall_no_longer_has_is_announced_by_the_operation_that_finds_it() {
    // The reload case, with no restart anywhere: the firewall has forgotten
    // a rule, porthole's state file has not, and the next operation's own
    // reconciliation sweep drops the record. Before this was plumbed the
    // drop was silent on the journal and on the bus, so a client that keeps
    // its view from signals showed the port as open forever.
    //
    // The close below *fails* -- the sweep dropped the rule a moment before
    // it looked -- which is the case that matters most and the one a naive
    // wiring would miss, because the method returns early.
    //
    // Firewalld only: the record's handle has to be one the detected backend
    // would recognise as its own, and this is the backend whose read-only
    // listing (`firewall-cmd --list-rich-rules`) an unprivileged caller can
    // actually run. Nothing here mutates the firewall -- firewalld cannot
    // prove which rules are porthole's, so its orphan sweep never runs (see
    // `reconcile.rs`).
    let runner = RealRunner;
    match porthole_core::backend::detect(&runner) {
        Ok(backend) if backend.id() == BackendId::Firewalld => {}
        Ok(backend) => {
            eprintln!(
                "skipped: this host detects {}, and this test needs a firewalld handle",
                backend.id()
            );
            return;
        }
        Err(e) => {
            eprintln!("skipped: no firewall backend on this host: {e}");
            return;
        }
    }

    let dir = TempDir::new().unwrap();
    let state_path = dir.path().join("state.json");
    let mut orphan = created_rule();
    orphan.expires_at = None;
    let mut store = StateStore::open(&state_path).unwrap();
    store.insert(orphan.clone());
    store.save().unwrap();

    let (_server, name) = serve("SigReconciled", &state_path).await;
    let proxy = proxy_to(&name).await;
    let mut signals = proxy.receive_rule_closed().await.unwrap();

    let failed = proxy.close(orphan.port, "tcp").await;
    assert!(
        failed.is_err(),
        "the sweep dropped the record first, so the close has nothing to find"
    );

    let signal = next_signal(&mut signals).await;
    let args = signal.args().unwrap();
    assert_eq!(
        args.reason,
        CloseReason::Reconciled,
        "porthole did not close this one -- it found the record of a rule the \
         firewall no longer had"
    );
    assert_eq!(args.rule.id, orphan.id);
    assert_eq!(args.rule.port, orphan.port);

    // And the record really is gone, so a `list` and the signal agree.
    assert!(proxy.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_forget_announces_no_close_because_nothing_was_closed() {
    // `close --id <id> --forget` drops porthole's record of a rule recorded
    // under a backend this machine no longer has, and touches no firewall at
    // all (`Engine::forget_rule`). None of the reasons a `RuleClosed` can
    // carry is true of it, and a subscriber told "closed" would report a
    // port as no longer reachable when porthole neither closed it nor knows
    // whether anything did. So: the journal gets its own "forgot" line, and
    // the bus gets nothing.
    //
    // This is a real `close_by_id` call, all the way through the engine, on
    // the one close path that can succeed on a host whose firewall must not
    // be touched.
    let runner = RealRunner;
    let Ok(detected) = porthole_core::backend::detect(&runner) else {
        eprintln!("skipped: no firewall backend on this host, so nothing is 'foreign' to it");
        return;
    };
    let foreign = [BackendId::Ufw, BackendId::Nftables, BackendId::Firewalld]
        .into_iter()
        .find(|id| *id != detected.id())
        .expect("three backends, one detected");

    let dir = TempDir::new().unwrap();
    let state_path = dir.path().join("state.json");
    let mut orphan = created_rule();
    orphan.backend = foreign;
    // No expiry: a forget of a timed rule would try to cancel a systemd
    // timer, which is not this test's business.
    orphan.expires_at = None;
    let mut store = StateStore::open(&state_path).unwrap();
    store.insert(orphan.clone());
    store.save().unwrap();

    let (_server, name) = serve("SigForget", &state_path).await;
    let proxy = proxy_to(&name).await;
    let mut signals = proxy.receive_rule_closed().await.unwrap();

    let forgotten = proxy
        .close_by_id(&orphan.id, false, true)
        .await
        .expect("a foreign-backend record can be forgotten");
    assert_eq!(forgotten.id, orphan.id);
    assert!(
        stays_silent(&mut signals).await,
        "a forget touched no firewall but announced a close"
    );
}

// ---------------------------------------------------------------------------
// The shipped D-Bus policy, in a real dbus-daemon
// ---------------------------------------------------------------------------

/// A `dbus-daemon` this test started and will kill, and the address it
/// printed.
struct PrivateBus {
    child: std::process::Child,
    address: String,
    /// Holds the socket's directory open for the daemon's lifetime.
    _dir: TempDir,
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn shipped_policy() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/com.jacopobriccola.Porthole.conf")
        .canonicalize()
        .expect("data/com.jacopobriccola.Porthole.conf")
        .to_string_lossy()
        .into_owned()
}

/// A session-bus config whose default policy refuses to deliver anything the
/// porthole service sends, so that whether a signal arrives depends entirely
/// on whether the shipped policy is `include`d.
///
/// The deny is stricter than any real bus: Fedora's own
/// `/usr/share/dbus-1/system.conf` allows `receive_type="signal"` for
/// everyone in its default policy, so on a stock system bus porthole's
/// signals would reach a subscriber whether or not the shipped file said
/// anything about receiving. That is precisely why the deny is here -- it is
/// the only way to make the shipped `<allow receive_sender=.../>` line the
/// thing being measured rather than a line that happens to be redundant on
/// the machine the test runs on.
fn bus_config(socket_dir: &Path, include_shipped_policy: bool) -> String {
    let include = if include_shipped_policy {
        format!("<include>{}</include>", shipped_policy())
    } else {
        String::new()
    };
    format!(
        r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir={dir}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
    <deny receive_sender="{service}"/>
  </policy>
  {include}
</busconfig>
"#,
        dir = socket_dir.display(),
        service = SERVICE,
    )
}

/// Start a private session `dbus-daemon` on `config`. `None` when
/// `dbus-daemon` is not installed, which is a reason to skip loudly rather
/// than to fail.
fn start_bus(include_shipped_policy: bool) -> Option<PrivateBus> {
    use std::io::BufRead;

    // `TempDir::new` lands under TMPDIR; a deep path would blow the 108-byte
    // limit on a unix socket name and `dbus-daemon` would refuse to start
    // with "Socket name too long".
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("bus.conf");
    std::fs::write(&config_path, bus_config(dir.path(), include_shipped_policy)).unwrap();

    let mut child = match std::process::Command::new("dbus-daemon")
        .arg(format!("--config-file={}", config_path.display()))
        .arg("--print-address")
        .arg("--nofork")
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("skipped: dbus-daemon is not runnable here: {e}");
            return None;
        }
    };

    let stdout = child.stdout.take().expect("piped");
    let mut address = String::new();
    let read = std::io::BufReader::new(stdout).read_line(&mut address);
    if read.is_err() || address.trim().is_empty() {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "dbus-daemon started but printed no address; the config it was given was:\n{}",
            bus_config(dir.path(), include_shipped_policy)
        );
    }

    Some(PrivateBus {
        child,
        address: address.trim().to_string(),
        _dir: dir,
    })
}

/// Own the shipped service name on `bus` and emit one `RuleClosed`; return
/// whether a plain subscriber on the same bus received it.
///
/// The subscriber is an ordinary client using the published proxy, not
/// `dbus-monitor`: a monitor connection is exempt from receive policy
/// altogether, so it would report a signal delivered no matter what the
/// policy said.
async fn signal_survives(bus: &PrivateBus) -> bool {
    let server = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(SERVICE)
        .unwrap()
        .build()
        .await
        .unwrap();
    let client = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let proxy = PortholeProxy::new(&client).await.unwrap();
    let mut signals = proxy.receive_rule_closed().await.unwrap();

    Porthole::announce_autoclose(
        Some(&emitter(&server)),
        &created_rule(),
        CloseReason::Expired,
    )
    .await;

    // `Ok(Some(_))`, not `is_ok()`: a stream that *ended* also completes the
    // timeout, and counting that as a delivered signal would make the
    // positive leg of the only test that measures the shipped policy pass on
    // a dead subscriber.
    matches!(
        tokio::time::timeout(ARRIVES_WITHIN, signals.next()).await,
        Ok(Some(_))
    )
}

#[tokio::test]
async fn the_shipped_bus_policy_is_what_a_real_dbus_daemon_parses() {
    // A policy file dbus-daemon cannot parse is not a policy: the daemon
    // refuses to start, and on the system bus that means the helper never
    // gets its name. Nothing short of a real daemon reading the real file
    // checks this -- a string search over the XML would pass on a file with
    // a misspelled attribute or an unclosed element.
    let Some(bus) = start_bus(true) else { return };
    assert!(
        bus.address.starts_with("unix:"),
        "got: {}",
        bus.address.as_str()
    );
}

#[tokio::test]
async fn the_shipped_policy_is_what_lets_a_signal_reach_a_subscriber() {
    // The pair of assertions is the point. A bus whose default policy
    // refuses to deliver anything the porthole service sends delivers the
    // signal anyway once the shipped file is included, and does not when it
    // is left out -- so it is the shipped `<allow receive_sender=.../>` line
    // doing it, not the bus being permissive.
    //
    // What this does not say is that the line is load-bearing on a stock
    // system bus. It is not: Fedora's `/usr/share/dbus-1/system.conf`
    // already allows `receive_type="signal"` for everyone, so a subscriber
    // there would get these signals with or without it. See `bus_config`.
    let Some(with_policy) = start_bus(true) else {
        return;
    };
    assert!(
        signal_survives(&with_policy).await,
        "the shipped policy was included and the signal still did not arrive"
    );

    let Some(without_policy) = start_bus(false) else {
        return;
    };
    assert!(
        !signal_survives(&without_policy).await,
        "the signal arrived with the shipped policy left out, so this test \
         proves nothing about the policy -- the bus is delivering it for \
         some other reason"
    );
}
