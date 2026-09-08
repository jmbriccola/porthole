//! The milestone's headline claim, end to end: `porthole open` with no `sudo`
//! anywhere.
//!
//! A real `porthole-helper` runs as a child process on the session bus and the
//! real `porthole` binary drives it. What this proves and what it cannot is
//! written out in each test.
//!
//! # What this file asks of the firewall on the machine running it
//!
//! Nothing that would change it. No test here calls `open`; the one `close`
//! runs against a state file with no rules in it, so there is no record for
//! it to act on and no removal command it could build. What remains is
//! reading: `backend::detect` runs `firewall-cmd --version` and `--state`,
//! [`default_zone`] runs `--get-default-zone`, and starting the helper at all
//! -- for *every* test below -- runs its start-up sweep (`reconcile_at_startup`
//! in `porthole-helper`'s `main.rs`), which lists this machine's rules.
//!
//! An open the firewall really performs, and one it refuses, both live in
//! `crates/porthole-cli/tests/container.rs`, against a firewalld that goes
//! away with its container. So does the `close --id` of a rule the firewall
//! does not have, which is the only close that could reach a real removal
//! command. An earlier version of this file ran all three here, and one of
//! them left a rich rule in a developer's own firewall with nothing able to
//! close it: the polkit prompt appeared, a person answered it, and the open
//! the test expected to be refused succeeded instead.
//!
//! The start-up sweep is the one thing left here that could still act, and
//! only on a backend that can prove ownership:
//!
//! - On firewalld, the sweep can never remove a rule it did not create --
//!   rich rules carry no marker, so `Ownership::Unprovable` skips that half
//!   of reconciliation outright, on every account, privileged or not.
//! - On ufw or nftables, the sweep *can* prove ownership and does remove an
//!   orphan it finds, straight through `ufw`/`nft` rather than through
//!   firewalld's D-Bus/polkit path -- so this suite's `--session`
//!   `AlwaysAllow` authorizer (which stands in for polkit here) has no
//!   bearing on it at all. The only thing standing between that sweep and a
//!   real rule on either of those backends is the OS's own root check on
//!   `ufw`/`nft` themselves.
//!
//! So the condition this suite's safety still depends on is: this process
//! is not genuinely root, or the detected backend is one whose sweep cannot
//! remove anything (firewalld). `start_helper` below checks exactly that and
//! refuses to start the helper otherwise, rather than let a start-up sweep
//! mutate a real firewall on the machine running the tests.

use porthole_core::backend::{self, BackendId};
use porthole_core::command::RealRunner;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;

/// Kills the helper however the test ends, including on a failed assertion.
struct Helper(Child);

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Every test below spawns a helper claiming the *same* well-known name on
/// the *same* session bus, and `cargo test` runs the `#[test]` functions in
/// one process on separate threads by default. Two helpers racing for that
/// one name — or one test's `Drop` killing its helper while another test's
/// request to "the" helper is still in flight — produced real, reproducible
/// `Remote peer disconnected` failures during development, unrelated to
/// anything any single test claims to prove. This makes the file behave as if
/// `--test-threads=1` had been passed, without depending on how `cargo test`
/// happens to be invoked. `unwrap_or_else` recovers from a lock poisoned by an
/// earlier test's panic, so one real failure does not cascade into every
/// other test in the file failing too.
static HELPER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_helper() -> std::sync::MutexGuard<'static, ()> {
    HELPER_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The backend whose start-up reconciliation sweep could remove a real rule
/// from this machine's real firewall if the helper were started right now --
/// see the module docs for why this is the condition this suite's safety
/// actually depends on, not "the helper talks to firewalld".
///
/// Two things have to hold at once: this process is genuinely root (not
/// merely authorized by this suite's own `--session` `AlwaysAllow`, which the
/// sweep bypasses entirely -- it runs before the bus is even served), and the
/// backend `backend::detect` finds on this real machine is one whose sweep
/// can prove ownership (`Ufw` or `Nftables`; firewalld's rich rules cannot be
/// marked, so its half of reconciliation that removes an orphan never runs at
/// all, on any account). `detect` failing outright -- no firewall installed
/// on this machine at all -- is the same as firewalld for this purpose:
/// nothing for the sweep to touch either way, so that case returns `None`
/// too.
fn unsafe_startup_sweep_backend() -> Option<BackendId> {
    if !is_root() {
        return None;
    }
    match backend::detect(&RealRunner).map(|b| b.id()) {
        Ok(id @ (BackendId::Ufw | BackendId::Nftables)) => Some(id),
        _ => None,
    }
}

/// `CARGO_BIN_EXE_<name>` only ever resolves for a binary target in the *same*
/// package as the integration test — verified empirically, since it is easy
/// to assume (as this test once did) that it reaches across the workspace to
/// a sibling package's binary the way `cargo`'s own dependency resolution
/// does. It does not: `env!("CARGO_BIN_EXE_porthole-helper")` fails to
/// compile here even with `porthole-helper` added as a dev-dependency of
/// `porthole-cli`, and even under `cargo test --workspace`. What *is*
/// guaranteed is that every binary in a workspace lands in the same
/// `target/<profile>/` directory, so the porthole-helper binary is found as a
/// sibling of the one binary this package's own `CARGO_BIN_EXE_porthole` is
/// guaranteed to name.
fn helper_bin() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_BIN_EXE_porthole")).with_file_name("porthole-helper")
}

/// Every reason [`start_helper`] can fail to hand back a running helper, each
/// carrying enough to say *which* it was rather than one blanket "skipped"
/// that hides all four behind the same sentence — which is exactly how a
/// missing `porthole` at `/usr/bin` and `/usr/local/bin` made every test below
/// silently skip while `cargo test` still reported the suite `ok`.
///
/// A missing `porthole-helper` binary is not among them any more: it is an
/// assertion in [`start_helper`], because `return`ing out of a test is
/// counted by libtest as a pass, and `cargo test -p porthole-cli` — which
/// never builds a sibling package's binary — used to report all of these
/// green in half a second without running one of them.
enum StartFailure {
    /// `--session` is debug-only; nothing to run under `--release`.
    ReleaseBuild,
    /// The helper process ended before it ever claimed the bus name — most
    /// likely `resolve_cli` refusing to start. Carries its stderr so the
    /// reason is visible rather than guessed at.
    HelperExited(String),
    /// The process is still alive, but never showed up on the session bus
    /// within the timeout — a missing session bus, or `busctl` unavailable.
    NeverAppearedOnTheBus,
    /// Starting the helper here, right now, would let its start-up
    /// reconciliation sweep run as genuine root against a backend whose
    /// orphan removal can actually prove ownership — see the module docs.
    /// Refused rather than risk a real rule on the machine running the
    /// suite: there is no way to let the sweep run without also letting it
    /// act.
    UnsafeStartupSweep(BackendId),
}

impl StartFailure {
    fn message(&self) -> String {
        match self {
            StartFailure::ReleaseBuild => {
                "release build (--session is debug-only, so this suite cannot \
                 run under `cargo test --release`)"
                    .to_string()
            }
            StartFailure::HelperExited(stderr) => format!(
                "the helper process exited before it started serving \
                 (most likely `resolve_cli` refusing to start) — its stderr: {stderr}"
            ),
            StartFailure::NeverAppearedOnTheBus => {
                "the helper is still running but never appeared on the session \
                 bus within 5s — no session bus reachable, or `busctl` unavailable"
                    .to_string()
            }
            StartFailure::UnsafeStartupSweep(id) => format!(
                "running as root with {id} detected — starting the helper would let its \
                 start-up reconciliation sweep remove a real {id} rule this machine may \
                 actually be enforcing, with no polkit and no authorization step in the \
                 way. Skipped rather than risk it; run this suite as an ordinary user \
                 instead"
            ),
        }
    }
}

fn start_helper(state: &std::path::Path) -> Result<Helper, StartFailure> {
    // --session is debug-only, so this test cannot run under --release.
    if !cfg!(debug_assertions) {
        return Err(StartFailure::ReleaseBuild);
    }

    // C2: refuse before ever spawning the helper -- see the module docs and
    // `unsafe_startup_sweep_backend`'s own doc comment for exactly what this
    // guards against. Checked here, once, rather than in each test: every
    // single test below goes through this function, and the start-up sweep
    // this guards against runs unconditionally the moment the helper starts,
    // whether or not the test that started it ever calls `open` or `close`.
    if let Some(id) = unsafe_startup_sweep_backend() {
        return Err(StartFailure::UnsafeStartupSweep(id));
    }

    // Asserted, not skipped: `return`ing here is counted by libtest as a
    // pass, and that is exactly how every test in this file once reported
    // success in half a second under `cargo test -p porthole-cli`, which
    // never builds a sibling package's binary. A missing helper is a broken
    // invocation, and the message says how to fix it.
    let bin = helper_bin();
    assert!(
        bin.exists(),
        "porthole-helper is not at {} — these tests need the whole workspace \
         built, e.g. `cargo test` rather than `cargo test -p porthole-cli`",
        bin.display()
    );

    let mut child = Command::new(&bin)
        .arg("--session")
        .env("PORTHOLE_STATE_FILE", state)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{} exists but would not run: {e}", bin.display()));

    // Wait for the name to appear rather than sleeping a fixed time. A
    // transient `busctl` failure is not the helper's fault, so it retries
    // rather than bailing out via `?` — which, caught by `clippy::
    // zombie_processes`, used to return `None` here without ever killing
    // `child`, leaking a live `porthole-helper --session` process that
    // nothing would ever reap. Every exit from this function below either
    // hands `child` to `Helper` (whose `Drop` kills and waits it) or kills
    // and waits it here first.
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));

        // If the helper already exited, it never will appear on the bus, and
        // its own stderr says why (most likely `resolve_cli` refusing).
        if let Ok(Some(_status)) = child.try_wait() {
            let mut text = String::new();
            if let Some(mut err) = child.stderr.take() {
                use std::io::Read;
                let _ = err.read_to_string(&mut text);
            }
            let _ = child.wait();
            return Err(StartFailure::HelperExited(text));
        }

        let Ok(out) = Command::new("busctl")
            .args(["--user", "list", "--no-legend"])
            .output()
        else {
            continue;
        };
        if listing_names_the_helper(&String::from_utf8_lossy(&out.stdout)) {
            return Ok(Helper(child));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(StartFailure::NeverAppearedOnTheBus)
}

/// Does this `busctl --user list --no-legend` listing show the helper's own
/// well-known name?
///
/// Each row is a name, space-padded, followed by the pid and the rest, so the
/// name is the row's first field and is compared whole.
///
/// [`start_helper`] used to ask `listing.contains("com.jacopobriccola.Porthole")`
/// instead, and `com.jacopobriccola.PortholeAgent` contains that string. The
/// notification agent owns that name on the session bus of every machine
/// where porthole is installed and someone has logged in, so the probe was
/// answered by a service that implements none of the calls these tests go on
/// to make: it returned on its first pass, before the helper had claimed
/// anything at all. [`the_readiness_probe_is_not_satisfied_by_the_notification_agent`]
/// is that exact case, pinned.
///
/// [`porthole_core::ipc::SERVICE`] rather than a literal, so this is the same
/// string the helper requests rather than a second copy of it.
fn listing_names_the_helper(listing: &str) -> bool {
    listing
        .lines()
        .any(|row| row.split_whitespace().next() == Some(porthole_core::ipc::SERVICE))
}

#[test]
fn the_readiness_probe_is_not_satisfied_by_the_notification_agent() {
    // Real `busctl --user list --no-legend` output from the machine this was
    // found on, with porthole-agent running and no helper anywhere.
    let agent_only = "\
:1.48                              5145 porthole-agent  jmbriccola :1.48 user@1000.service - -
com.jacopobriccola.PortholeAgent   5145 porthole-agent  jmbriccola :1.48 user@1000.service - -
";
    assert!(
        agent_only.contains(porthole_core::ipc::SERVICE),
        "the agent's name contains the helper's, which is why a substring \
         check passed on it -- if this ever stops holding, the case below \
         stops being the one worth pinning"
    );
    assert!(
        !listing_names_the_helper(agent_only),
        "a probe waiting for the helper must not be satisfied by the agent"
    );

    // And it still says yes to the thing it is actually waiting for.
    let with_helper = format!(
        "{agent_only}{}   6001 porthole-helper jmbriccola :1.49 - - -\n",
        porthole_core::ipc::SERVICE
    );
    assert!(
        listing_names_the_helper(&with_helper),
        "the helper's own row must satisfy it: {with_helper}"
    );

    // A name is a whole field, never part of one: the unique-name rows above
    // carry `porthole-agent` in a later column, and a row for some future
    // `com.jacopobriccola.PortholeSomethingElse` must not count either.
    assert!(
        !listing_names_the_helper("com.jacopobriccola.PortholeSomethingElse 7 x y :1.50 - - -\n"),
        "only the exact name counts"
    );
}

/// Starts the helper or reports precisely why not, then returns from the
/// calling test. A macro, not a function, because a function cannot `return`
/// out of its caller.
macro_rules! start_or_skip {
    ($state:expr) => {
        match start_helper($state) {
            Ok(helper) => helper,
            Err(failure) => {
                eprintln!("skipped: {}", failure.message());
                return;
            }
        }
    };
}

fn cli(state: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut all = vec!["--session"];
    all.extend_from_slice(args);
    Command::new(env!("CARGO_BIN_EXE_porthole"))
        .args(all)
        .env("PORTHOLE_STATE_FILE", state)
        .output()
        .expect("the porthole binary runs")
}

/// The zone `firewall-cmd` would act on by default on *this* machine — read,
/// never written, so the seeded-rule test below can build a syntactically
/// valid handle without hardcoding a zone name that only exists on one
/// developer's laptop.
fn default_zone() -> String {
    Command::new("firewall-cmd")
        .args(["--get-default-zone"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[test]
fn the_cli_reaches_the_helper_with_no_sudo_anywhere() {
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");
    let _helper = start_or_skip!(&state);

    // list goes over the bus and answers. No sudo, no root, no prompt.
    let out = cli(&state, &["list", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(json["rules"].as_array().unwrap().len(), 0);
}

#[test]
fn the_helper_refuses_an_over_long_duration_itself() {
    // The CLI validates too, but this proves the *helper* does — a client that
    // skipped its own checks still cannot ask for nine hours.
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");
    let _helper = start_or_skip!(&state);

    // Call the helper directly over the bus, bypassing the CLI's own
    // validation entirely — the same proxy type `porthole-cli` itself uses to
    // talk to the helper, not the CLI's own request path.
    //
    // This was originally a `busctl call`, asserting that its stderr named
    // the D-Bus error. It does not, on this machine: `busctl` (systemd 259)
    // prints only `Call failed: <message>` on error, in every output mode
    // (default, `--verbose`, `-j`) — verified by hand — never the error name
    // itself. Calling through zbus instead recovers the actual typed error
    // name from the protocol layer rather than scraping a CLI tool's stderr
    // formatting, which is a strictly more precise version of the same claim,
    // not a weaker one.
    let result: Result<porthole_core::ipc::WireRule, zbus::Error> =
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(async {
                let conn = zbus::Connection::session().await.expect("session bus");
                let proxy = porthole_core::ipc::PortholeProxy::new(&conn)
                    .await
                    .expect("bind the helper's interface");
                proxy.open(5173, "tcp", "subnet", 28801).await
            });

    let err = result.expect_err("the helper must refuse 8h+1s");
    match &err {
        zbus::Error::MethodError(name, detail, _) => {
            assert!(
                name.as_str().ends_with("InvalidArgument"),
                "expected a typed refusal, got: {name} ({detail:?})"
            );
        }
        other => panic!("expected a typed refusal, got: {other}"),
    }
}

#[test]
fn closing_something_that_is_not_open_round_trips_its_exit_code() {
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");
    let _helper = start_or_skip!(&state);

    let out = cli(&state, &["close", "5173"]);
    // 7 is what milestone 1 documented for "no rule matches", and it must be
    // the same whether the CLI did the work or the helper did.
    assert_eq!(
        out.status.code(),
        Some(7),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_helper_reconciles_at_startup_with_no_client_request_at_all() {
    // Fix round 2, item 1: the spec's mandatory acceptance test is "open a
    // port on ufw, reboot, verify it is closed". Nothing but a start-up
    // sweep can make that true -- the helper is D-Bus activated, so nothing
    // runs between a reboot and the first client request, and that request
    // may never come before the machine reboots again. This seeds a phantom
    // state entry (same shape as the one above) and starts the helper --
    // and only the helper, no client call of any kind -- to prove the entry
    // is pruned by start-up alone.
    //
    // No sleep needed to give the sweep time to run: `start_or_skip!` only
    // returns once the helper's name appears on the bus, which happens in
    // `main` strictly after the start-up sweep -- both run sequentially,
    // before the bus connection is even opened. By the time this test can
    // see the helper on the bus at all, the sweep has already finished.
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");

    const RULE_ID: &str = "startup-phantom";
    const PORT: u16 = 25199;
    const CIDR: &str = "203.0.113.0/24"; // TEST-NET-3: never a real subnet.
    let zone = default_zone();
    let rich_rule = format!(
        r#"rule family="ipv4" source address="{CIDR}" port port="{PORT}" protocol="tcp" accept"#
    );
    let seeded = serde_json::json!({
        "schema_version": 1,
        "rules": [{
            "id": RULE_ID,
            "port": PORT,
            "protocol": "tcp",
            "target": {"kind": "network", "cidr": CIDR},
            "backend": "firewalld",
            "opened_at": 1_757_000_000_u64,
            "expires_at": null,
            "uid": 999_999,
            "handle": {"backend": "firewalld", "zone": zone, "rich_rule": rich_rule},
        }]
    });
    std::fs::write(&state, serde_json::to_string_pretty(&seeded).unwrap())
        .expect("seed the state file");

    let mut helper = start_or_skip!(&state);
    let _ = helper.0.kill();
    let _ = helper.0.wait();

    let state_text = std::fs::read_to_string(&state).expect("the state file still exists");
    assert!(
        !state_text.contains(RULE_ID),
        "start-up reconciliation must prune a phantom entry even with no \
         client request ever made: {state_text}"
    );
}
