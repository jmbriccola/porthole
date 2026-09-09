//! The real helper, D-Bus activated, retiring and being activated again.
//!
//! Everything here drives the **real `porthole-helper` binary** through a
//! **real bus that can activate it**: a private `dbus-daemon` this file starts,
//! with a `<servicedir>` of its own holding a `com.jacopobriccola.Porthole`
//! activation file. That is the one thing `crates/porthole-cli/tests/helper_e2e.rs`
//! cannot do -- it spawns the helper by hand, so a helper that exited there
//! would simply be gone -- and it is the whole point: a retirement is only
//! safe because the next call brings a fresh instance back, and nothing that
//! cannot activate one can show that.
//!
//! # What this file asks of the machine running it
//!
//! **No firewall, no system bus, no root, and no state outside its own
//! temporary directory.** Every helper it activates is started by a wrapper
//! script that puts a stub `firewall-cmd` and a stub `ip` in front of its
//! `PATH` and points `PORTHOLE_STATE_FILE` at a temporary file -- the same
//! means `helper_e2e.rs` uses and for the same reason, written out in that
//! file's own module doc. The stub answers as **firewalld**, whose
//! `Ownership::Unprovable` makes the start-up sweep skip the direction that
//! could remove a rule, so there is no arrangement of these tests in which
//! anything reaches a real ruleset.
//!
//! It does need `/usr/bin/porthole` (or `/usr/local/bin/porthole`) to exist
//! and be root-owned, because `porthole_core::cli_path::resolve_cli` offers a
//! helper nothing else and the helper refuses to start without one. A helper
//! that refuses to start never claims the name, so the first assertion here
//! fails with the helper's own stderr from [`Bus::log`] rather than leaving
//! anybody guessing.
//!
//! # Nothing here skips
//!
//! `porthole-helper --session` exists only in a debug build, and so does the
//! grace override every test here depends on, so a `cargo test --release`
//! reports these `ignored`, by name. Everything else is an assertion.

use futures_util::StreamExt;
use porthole_core::backend::{BackendId, RuleHandle};
use porthole_core::ipc::{CloseReason, PortholeProxy, PATH, RETIRING_ERROR, SERVICE};
use porthole_core::model::{Protocol, Target};
use porthole_core::state::{ManagedRule, StateStore};
use std::io::BufRead as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// The zone the stub firewalld answers with. Not a real zone name on any
/// machine, so a rule handle built here could not collide with one from a
/// firewall that is actually installed.
const STUB_ZONE: &str = "porthole-idle-exit-test";

/// How long a "the helper has gone" or "the signal arrived" assertion waits
/// before believing the opposite. Generous: every grace below is under two
/// seconds, so this is not the interval anything is expected to need.
const WITHIN: Duration = Duration::from_secs(20);

/// A private `dbus-daemon` that can activate `com.jacopobriccola.Porthole`,
/// and everything the helper it activates is pointed at.
struct Bus {
    daemon: Child,
    address: String,
    dir: TempDir,
}

impl Drop for Bus {
    fn drop(&mut self) {
        // The daemon first: it is what would otherwise activate another
        // helper while the temporary directory is being removed.
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

/// `CARGO_BIN_EXE_<name>` resolves only for a binary in this test's own
/// package, which `porthole-helper` is -- see `helper_e2e.rs`'s own note for
/// the sibling-package case that does not work.
fn helper_bin() -> &'static str {
    env!("CARGO_BIN_EXE_porthole-helper")
}

fn write_executable(path: &Path, body: &str) {
    std::fs::write(path, body).expect("writing a script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

impl Bus {
    /// Start a bus that will activate a helper with `grace_ms` before it
    /// retires and `settle_ms` on each side of its drain.
    fn start(grace_ms: u64, settle_ms: u64) -> Self {
        // Shallow, because a unix socket path is capped at 108 bytes and
        // `dbus-daemon` refuses to start with "Socket name too long".
        let dir = TempDir::new().expect("a temporary directory");
        let bin = dir.path().join("bin");
        let services = dir.path().join("services");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&services).unwrap();

        // The rich rules the stub firewalld lists. A test rewrites this file
        // to make the firewall "have" a rule or not, which is what decides
        // whether the start-up sweep keeps a seeded state record or drops it.
        std::fs::write(dir.path().join("rich-rules"), "").unwrap();

        write_executable(
            &bin.join("firewall-cmd"),
            &format!(
                "#!/bin/sh\n\
                 for arg in \"$@\"; do\n\
                 case \"$arg\" in\n\
                 --version) echo '2.4.4'; exit 0 ;;\n\
                 --state) echo 'running'; exit 0 ;;\n\
                 --get-default-zone) echo '{STUB_ZONE}'; exit 0 ;;\n\
                 --list-rich-rules) cat '{rules}'; exit 0 ;;\n\
                 esac\n\
                 done\n\
                 echo \"idle-exit stub firewall-cmd: unhandled $*\" >&2\n\
                 exit 2\n",
                rules = dir.path().join("rich-rules").display(),
            ),
        );
        write_executable(
            &bin.join("ip"),
            "#!/bin/sh\n\
             case \"$*\" in\n\
             *'route show default'*)\n\
             echo '[{\"dst\":\"default\",\"dev\":\"wlo1\",\"metric\":600}]' ;;\n\
             *'addr show'*)\n\
             echo '[{\"ifindex\":2,\"ifname\":\"wlo1\",\"addr_info\":[{\"family\":\"inet\",\
             \"local\":\"10.10.10.119\",\"prefixlen\":24,\"scope\":\"global\"}]}]' ;;\n\
             *) echo \"idle-exit stub ip: unhandled $*\" >&2; exit 2 ;;\n\
             esac\n",
        );

        // The environment lives in this wrapper rather than in the bus
        // daemon's own, so what an activated helper is given does not depend
        // on what a bus daemon happens to pass on to its children -- and so
        // that every instance's stderr lands in one log this file can read.
        // `std::env::set_var` is not available to a test binary with other
        // tests' threads running, which is the other half of why this is a
        // script.
        let wrapper = dir.path().join("activate-helper");
        write_executable(
            &wrapper,
            &format!(
                "#!/bin/sh\n\
                 export PATH='{bin}':\"$PATH\"\n\
                 export PORTHOLE_STATE_FILE='{state}'\n\
                 export PORTHOLE_IDLE_GRACE_MS={grace_ms}\n\
                 export PORTHOLE_IDLE_SETTLE_MS={settle_ms}\n\
                 export PORTHOLE_IDLE_EXIT=1\n\
                 exec '{helper}' --session >>'{log}' 2>&1\n",
                bin = bin.display(),
                state = dir.path().join("state.json").display(),
                helper = helper_bin(),
                log = dir.path().join("helper.log").display(),
            ),
        );
        std::fs::write(dir.path().join("helper.log"), "").unwrap();

        std::fs::write(
            services.join("com.jacopobriccola.Porthole.service"),
            format!(
                "[D-BUS Service]\nName={SERVICE}\nExec={}\n",
                wrapper.display()
            ),
        )
        .unwrap();

        let config = dir.path().join("bus.conf");
        std::fs::write(
            &config,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir={dir}</listen>
  <auth>EXTERNAL</auth>
  <servicedir>{services}</servicedir>
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
  </policy>
</busconfig>
"#,
                dir = dir.path().display(),
                services = services.display(),
            ),
        )
        .unwrap();

        // Asserted, not skipped. `dbus-broker` cannot stand in: this needs a
        // daemon that reads a `busconfig` file with a `<servicedir>` in it,
        // and skipping would report success on an activation nothing had
        // performed. `tests/signals.rs` requires the same binary for the same
        // kind of reason.
        let mut daemon = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config.display()))
            .arg("--print-address")
            .arg("--nofork")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "`dbus-daemon` would not run ({e}). It is required, not optional: it is \
                     the only bus here that can *activate* porthole-helper, and activation is \
                     what makes retiring safe. Install it (Fedora: `dbus-daemon`, Debian: \
                     `dbus`, Arch: `dbus`)."
                )
            });
        let mut address = String::new();
        std::io::BufReader::new(daemon.stdout.take().expect("piped"))
            .read_line(&mut address)
            .expect("the private bus prints its address");
        let address = address.trim().to_string();
        assert!(!address.is_empty(), "dbus-daemon printed no address");

        Bus {
            daemon,
            address,
            dir,
        }
    }

    async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .expect("an address zbus can parse")
            .build()
            .await
            .expect("the private bus accepts a client")
    }

    async fn proxy(&self) -> PortholeProxy<'static> {
        PortholeProxy::new(&self.connect().await)
            .await
            .expect("the published proxy")
    }

    fn state_path(&self) -> PathBuf {
        self.dir.path().join("state.json")
    }

    /// Everything every activated helper has written to its stderr, in order.
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("helper.log")).unwrap_or_default()
    }

    /// How many helper processes this bus has activated. Counted from the one
    /// line a helper writes the instant it owns the name, so it counts
    /// instances that actually served, not processes that started.
    fn activations(&self) -> usize {
        self.log()
            .lines()
            .filter(|l| l.contains(&format!("serving {SERVICE}")))
            .count()
    }

    /// Make the stub firewalld list `rules`, one per line.
    fn firewall_holds(&self, rules: &str) {
        std::fs::write(self.dir.path().join("rich-rules"), rules).unwrap();
    }
}

/// A rule as porthole records one, with a handle naming `rich_rule` in the
/// stub's zone -- so whether the firewall "has" it is decided entirely by
/// [`Bus::firewall_holds`].
fn recorded(port: u16, rich_rule: &str) -> ManagedRule {
    ManagedRule {
        id: format!("idle-exit-{port}"),
        port,
        protocol: Protocol::Tcp,
        target: Target::Network {
            cidr: "10.10.10.0/24".parse().unwrap(),
        },
        backend: BackendId::Firewalld,
        opened_at: 1_757_000_000,
        // No expiry: cancelling one would reach `systemd-run`, which is not
        // what any of this is about.
        expires_at: None,
        uid: 1000,
        handle: RuleHandle::Firewalld {
            zone: STUB_ZONE.to_string(),
            rich_rule: rich_rule.to_string(),
        },
        forward: None,
    }
}

fn seed(path: &Path, rule: ManagedRule) {
    let mut store = StateStore::open_exclusive(path).expect("the state file");
    store.insert(rule);
    store.save().expect("saving the seeded rule");
}

async fn owner_of(conn: &zbus::Connection) -> Option<String> {
    let dbus = zbus::fdo::DBusProxy::new(conn)
        .await
        .expect("the bus proxy");
    dbus.get_name_owner(SERVICE.try_into().unwrap())
        .await
        .ok()
        .map(|n| n.to_string())
}

async fn someone_owns_the_name(conn: &zbus::Connection) -> bool {
    let dbus = zbus::fdo::DBusProxy::new(conn)
        .await
        .expect("the bus proxy");
    dbus.name_has_owner(SERVICE.try_into().unwrap())
        .await
        .expect("the bus answers NameHasOwner")
}

/// Wait for the name to be given up, or fail saying what the helper said.
async fn wait_until_the_helper_has_gone(bus: &Bus, conn: &zbus::Connection) {
    let deadline = Instant::now() + WITHIN;
    while Instant::now() < deadline {
        if !someone_owns_the_name(conn).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "the helper still owns {SERVICE} after {WITHIN:?} with nothing open.\n--- its log ---\n{}",
        bus.log()
    );
}

// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "`porthole-helper --session` and the grace override are debug-only"
)]
async fn a_helper_with_nothing_open_gives_up_the_name_and_the_next_call_gets_a_fresh_one() {
    let bus = Bus::start(600, 50);
    let client = bus.connect().await;

    // The control that makes everything below mean something: nothing is
    // running yet, so "the name has an owner" later is this bus activating a
    // helper rather than something that was already there.
    assert!(
        !someone_owns_the_name(&client).await,
        "something already owns {SERVICE} on a bus this test just created"
    );

    let proxy = bus.proxy().await;
    assert!(
        proxy.list().await.expect("the helper answers").is_empty(),
        "nothing was ever opened"
    );
    let first = owner_of(&client)
        .await
        .expect("the call activated a helper");
    assert_eq!(bus.activations(), 1, "log:\n{}", bus.log());

    wait_until_the_helper_has_gone(&bus, &client).await;
    assert!(
        bus.log().contains("giving up"),
        "it must say why it went, in the journal a person would read:\n{}",
        bus.log()
    );

    // And back again, which is the half that makes exiting safe at all.
    assert!(proxy.list().await.expect("re-activated").is_empty());
    let second = owner_of(&client).await.expect("a new helper");
    assert_ne!(
        first, second,
        "the same process answered twice, so nothing ever retired"
    );
    assert_eq!(
        bus.activations(),
        2,
        "two instances, not one that never went:\n{}",
        bus.log()
    );
}

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "`porthole-helper --session` and the grace override are debug-only"
)]
async fn a_helper_with_a_rule_recorded_never_retires_however_long_it_sits() {
    // The one thing this feature may never do. The network monitor is needed
    // while a rule is open, and there is no grace long enough to make leaving
    // it uncovered acceptable.
    const RICH_RULE: &str = r#"rule family="ipv4" source address="10.10.10.0/24" port port="5173" protocol="tcp" accept"#;

    let bus = Bus::start(300, 50);
    // The firewall really has it, so the start-up sweep keeps the record
    // rather than dropping it -- without this the state would be empty by the
    // time the first tick looked, and this test would pass against a helper
    // that retires with rules open.
    bus.firewall_holds(&format!("{RICH_RULE}\n"));
    seed(&bus.state_path(), recorded(5173, RICH_RULE));

    let client = bus.connect().await;
    let proxy = bus.proxy().await;
    let rules = proxy.list().await.expect("the helper answers");
    assert_eq!(
        rules.len(),
        1,
        "the seeded rule must survive the start-up sweep, or this test proves \
         nothing -- log:\n{}",
        bus.log()
    );

    // Ten graces, and not one idle tick may take it.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert!(
        someone_owns_the_name(&client).await,
        "a helper retired with a rule open, leaving the network monitor gone \
         while the port stayed permitted:\n{}",
        bus.log()
    );
    assert!(
        !bus.log().contains("giving up"),
        "and it must not even have decided to:\n{}",
        bus.log()
    );
    assert_eq!(bus.activations(), 1);

    // The other half, so the wait above is not passing because the helper
    // simply never retires: take the rule away and it goes.
    bus.firewall_holds("");
    let (closed, errors) = proxy.close_all().await.expect("close --all");
    assert!(
        closed.is_empty() && errors.is_empty(),
        "{closed:?} {errors:?}"
    );
    wait_until_the_helper_has_gone(&bus, &client).await;
}

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "`porthole-helper --session` and the grace override are debug-only"
)]
async fn a_call_arriving_while_the_old_helper_still_drains_is_served_by_a_fresh_one() {
    // Two helpers alive at once, which could not happen before this feature,
    // and the thing that makes the whole sequence cheap: giving up the name is
    // a routing barrier, so a call that arrives **after** it is never routed
    // to the leaving instance at all -- the bus starts a new one and that one
    // serves it. Nobody waits for the drain, and nobody is refused.
    //
    // The settle is what makes that window addressable rather than a matter of
    // luck: 50 ms in production, four seconds here, so the call below lands
    // squarely inside the drain instead of after it.
    let bus = Bus::start(1000, 4000);
    let client = bus.connect().await;
    let proxy = bus.proxy().await;

    proxy.list().await.expect("the helper answers");
    let retiring_instance = owner_of(&client).await.expect("a helper");

    // Grace 1000 ms, looked at every 100 ms, so the decision falls in
    // [1.0 s, 1.1 s] and the drain runs for about eight seconds after it.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let log = bus.log();
    assert!(
        log.contains("giving up"),
        "the helper had not started retiring yet, so this test is measuring \
         nothing:\n{log}"
    );
    assert!(
        !log.contains("nothing is left to answer"),
        "it had already finished and exited, so this call meets no drain at \
         all:\n{log}"
    );

    let served = proxy.list().await.expect("a fresh instance serves it");
    assert!(served.is_empty());
    let serving_instance = owner_of(&client).await.expect("a helper");
    assert_ne!(
        retiring_instance, serving_instance,
        "the instance that had already given up the name answered anyway -- \
         anything it announced would reach nobody"
    );
    assert_eq!(
        bus.activations(),
        2,
        "two live helpers, the second serving while the first drains:\n{}",
        bus.log()
    );
}

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "`porthole-helper --session` and the grace override are debug-only"
)]
async fn no_announcement_is_lost_across_a_run_of_retirements() {
    // The load arm, and the one that could catch a mistake the three tests
    // above cannot: calls placed at every phase of the retire-and-return cycle,
    // each of which must both be answered and be *announced* to a subscriber
    // that never re-subscribes. Losing an announcement is the failure this
    // whole sequence exists to prevent, and it is silent -- the caller's own
    // reply arrives regardless -- so nothing but a subscriber watching across
    // the crossings can see it.
    //
    // The grace is short and the sleep between calls sweeps a range wider than
    // it, so calls land before, during and after retirements rather than at one
    // fixed offset from them.
    const ROUNDS: u16 = 40;
    let bus = Bus::start(150, 50);
    let proxy = bus.proxy().await;
    let mut closes = proxy.receive_rule_closed().await.expect("a subscription");

    let mut retried = 0usize;
    for round in 0..ROUNDS {
        let port = 20_000 + round;
        seed(
            &bus.state_path(),
            recorded(port, "a rule the firewall lost"),
        );

        // Exactly what `porthole-cli` does: one call, and one retry on the two
        // failures a fresh instance can turn into service. A third kind of
        // failure, or a second failure on the retry, fails the test.
        let closed = match proxy.close_all().await {
            Ok(v) => v,
            Err(e) if porthole_core::ipc::worth_asking_again(&e) => {
                retried += 1;
                proxy.close_all().await.unwrap_or_else(|e| {
                    panic!("round {round}: the retry failed too: {e}\n{}", bus.log())
                })
            }
            Err(e) => panic!(
                "round {round}: a failure no client can do anything about: {e}\n{}",
                bus.log()
            ),
        };
        assert!(closed.0.is_empty(), "the sweep had already dropped it");

        // The announcement for *this* round, from whichever instance served
        // it. Later signals are never consumed looking for an earlier one: the
        // port is unique per round and rises, so a missing announcement stops
        // this loop rather than being papered over by the next.
        let deadline = Instant::now() + WITHIN;
        loop {
            assert!(
                Instant::now() < deadline,
                "round {round}: {port} was dropped from state and never announced -- \
                 a port stopped being open with nothing saying so\n{}",
                bus.log()
            );
            let signal = tokio::time::timeout(WITHIN, closes.next())
                .await
                .unwrap_or_else(|_| panic!("round {round}: no announcement at all\n{}", bus.log()))
                .expect("the subscription ended");
            let args = signal.args().expect("a readable body");
            assert!(
                args.rule.port <= port,
                "round {round}: heard {} before {port}, so {port}'s own announcement \
                 was lost\n{}",
                args.rule.port,
                bus.log()
            );
            if args.rule.port == port {
                assert_eq!(args.reason, CloseReason::Reconciled);
                break;
            }
        }

        // Sweeps the phase: 0, 190, 130, 70, 10, 200, ... milliseconds against
        // a 150 ms grace, so calls arrive before, during and after retirements
        // rather than at one fixed offset from them.
        tokio::time::sleep(Duration::from_millis((u64::from(round) * 190) % 240)).await;
    }

    // Without this the whole loop would pass against a helper that never
    // retired at all -- which is exactly how the spike's first attempt at this
    // measurement reported a clean run: a crossing that did not happen counts
    // as a crossing survived. The number is a floor, not an expectation.
    let crossings = bus.activations();
    assert!(
        crossings >= 5,
        "only {crossings} helper(s) served {ROUNDS} rounds, so almost nothing \
         retired and this test measured almost nothing:\n{}",
        bus.log()
    );
    eprintln!(
        "{ROUNDS} rounds across {crossings} helper instances, {retried} retried, \
         0 announcements lost"
    );
}

#[tokio::test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "`porthole-helper --session` and the grace override are debug-only"
)]
async fn a_subscriber_hears_an_instance_that_did_not_exist_when_it_subscribed() {
    // `porthole-agent` and `porthole-gui` both subscribe by matching on the
    // well-known name, and they are long-lived: if a retirement cost them
    // their subscription, every announcement after the first idle period
    // would be lost and nothing would say so. It does not -- the bus resolves
    // the name to whoever owns it now -- and this is where that is pinned
    // against the real helper rather than reasoned about.
    let bus = Bus::start(600, 50);
    let client = bus.connect().await;
    let proxy = bus.proxy().await;

    // Subscribed the way the agent subscribes: on the published proxy, which
    // matches on `sender=com.jacopobriccola.Porthole`.
    let mut closes = proxy.receive_rule_closed().await.expect("a subscription");

    // A record the firewall does not have. `close --all` sweeps before it
    // acts, drops the record, and announces the drop -- an announcement that
    // needs only a *read* of a firewall, which is why it can run here.
    seed(
        &bus.state_path(),
        recorded(5173, "a rule the firewall lost"),
    );
    let (closed, _) = proxy.close_all().await.expect("close --all");
    assert!(closed.is_empty(), "the sweep had already dropped it");

    let first = tokio::time::timeout(WITHIN, closes.next())
        .await
        .expect("the first announcement never arrived")
        .expect("the stream ended");
    let args = first.args().expect("a readable body");
    assert_eq!(args.rule.port, 5173);
    assert_eq!(args.reason, CloseReason::Reconciled);
    let first_instance = owner_of(&client).await.expect("a helper");

    wait_until_the_helper_has_gone(&bus, &client).await;

    // Now the same thing again, from a process that did not exist when the
    // subscription above was made.
    seed(
        &bus.state_path(),
        recorded(8443, "another rule the firewall lost"),
    );
    let (closed, _) = proxy.close_all().await.expect("close --all re-activates");
    assert!(closed.is_empty());

    let second = tokio::time::timeout(WITHIN, closes.next())
        .await
        .expect("a fresh instance announced into a subscription that no longer heard it")
        .expect("the stream ended");
    let args = second.args().expect("a readable body");
    assert_eq!(
        args.rule.port, 8443,
        "the second announcement is the second rule's"
    );

    let second_instance = owner_of(&client).await.expect("a helper");
    assert_ne!(
        first_instance,
        second_instance,
        "one process served both, so no retirement was crossed and this test \
         proves nothing:\n{}",
        bus.log()
    );
    assert_eq!(bus.activations(), 2, "log:\n{}", bus.log());
}

/// The object path is not in any assertion above, and it is what every one of
/// them depends on: a helper serving somewhere else would fail them all with
/// a message about the bus rather than about the path.
#[test]
fn the_activation_file_names_the_service_this_workspace_actually_serves() {
    assert_eq!(SERVICE, "com.jacopobriccola.Porthole");
    assert_eq!(PATH, "/com/jacopobriccola/Porthole");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    not(debug_assertions),
    ignore = "`porthole-helper --session` and the grace override are debug-only"
)]
async fn a_request_that_races_the_decision_to_retire_is_refused_rather_than_served() {
    // The window this refusal exists for is the one between the helper
    // deciding to go and the bus acknowledging that it has given up the name:
    // sub-millisecond, and the only moment at which a request can still reach
    // an instance that is leaving. Everything arriving after it is routed to a
    // fresh instance instead (the test above), and everything arriving before
    // it is served normally.
    //
    // Rare is not never -- the spike measured four such requests in 6,600
    // calls across thirty crossings, and each one, served, would have been a
    // port opened with nothing announcing it. So this aims at the window
    // rather than waiting for it: the grace is as short as the loop can look,
    // and callers pause for about that long between calls, which puts each
    // call in the neighbourhood of a decision instead of at a fixed offset
    // from one.
    const CALLERS: usize = 3;
    const BUDGET: Duration = Duration::from_secs(25);

    let bus = Bus::start(30, 50);
    let deadline = Instant::now() + BUDGET;
    let mut tasks = Vec::new();
    for caller in 0..CALLERS {
        let proxy = bus.proxy().await;
        tasks.push(tokio::spawn(async move {
            let (mut calls, mut refusals, mut unanswered) = (0u64, 0u64, 0u64);
            let mut nap = 28 + caller as u64;
            while Instant::now() < deadline && refusals == 0 {
                calls += 1;
                match proxy.list().await {
                    Ok(rules) => assert!(rules.is_empty(), "nothing was ever opened"),
                    Err(zbus::Error::MethodError(name, detail, _))
                        if name.as_str() == RETIRING_ERROR =>
                    {
                        refusals += 1;
                        assert!(
                            detail.as_deref().is_some_and(|d| d.contains("ask again")),
                            "the refusal must name the remedy: {detail:?}"
                        );
                        // Exactly what `porthole-cli` does, and it must work.
                        assert!(proxy
                            .list()
                            .await
                            .expect("the retry after a refusal is served")
                            .is_empty());
                    }
                    // The residue the drain is meant to shrink and the client
                    // retry is meant to cover: a call the bus had already
                    // routed to an instance that then went before answering
                    // it. Counted rather than passed over, and reported below.
                    Err(zbus::Error::MethodError(name, _, _))
                        if name.as_str() == porthole_core::ipc::NO_REPLY_ERROR =>
                    {
                        unanswered += 1;
                        assert!(proxy
                            .list()
                            .await
                            .expect("the retry after an unanswered call is served")
                            .is_empty());
                    }
                    Err(other) => {
                        panic!("neither served nor a failure a client can act on: {other}")
                    }
                }
                // Sweeps across the decision rather than sitting at one offset
                // from it: 28-30 ms of nap against a 30 ms grace, walked by a
                // millisecond each time round.
                tokio::time::sleep(Duration::from_millis(nap)).await;
                nap = 26 + (nap + 1) % 8;
            }
            (calls, refusals, unanswered)
        }));
    }

    let mut calls = 0;
    let mut refusals = 0;
    let mut unanswered = 0;
    for task in tasks {
        let (c, r, u) = task.await.expect("a caller ran to completion");
        calls += c;
        refusals += r;
        unanswered += u;
    }

    eprintln!(
        "{calls} calls across {} helper instances: {refusals} met one that had already \
         decided to go, {unanswered} were left unanswered by one that went",
        bus.activations()
    );
    eprintln!("--- helper log ---\n{}", bus.log());
    // The control, and it is the only one needed: a refusal can only be sent
    // by an instance that had *decided* to retire, so one of them is proof
    // that a request really did meet that window rather than that the loop
    // ran and nothing happened. `unanswered` is reported and not asserted on
    // -- there is always a last instant, and the client retry above is what
    // covers it.
    assert!(
        refusals > 0,
        "{calls} calls across {} retirements and not one of them met the window \
         between the decision and the release. Either the window has closed for \
         a reason worth knowing, or this machine is fast enough that the aim \
         above no longer reaches it -- both are findings, and neither is a pass.",
        bus.activations()
    );
}
