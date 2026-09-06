//! The milestone's headline claim, end to end: `porthole open` with no `sudo`
//! anywhere.
//!
//! A real `porthole-helper` runs as a child process on the session bus and the
//! real `porthole` binary drives it. What this proves and what it cannot is
//! written out in each test — the helper talks to the real firewalld, whose own
//! polkit policy requires an admin password for config actions, so an ordinary
//! user cannot change the firewall through it. That makes this safe to run, and
//! it means the "firewalld agrees" half belongs to the human checklist.

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

/// All five tests below spawn a helper claiming the *same* well-known name on
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
enum StartFailure {
    /// `--session` is debug-only; nothing to run under `--release`.
    ReleaseBuild,
    /// `cargo test -p porthole-cli` alone never builds `porthole-helper`.
    MissingBinary(std::path::PathBuf),
    /// The helper process ended before it ever claimed the bus name — most
    /// likely `resolve_cli` refusing to start. Carries its stderr so the
    /// reason is visible rather than guessed at.
    HelperExited(String),
    /// The process is still alive, but never showed up on the session bus
    /// within the timeout — a missing session bus, or `busctl` unavailable.
    NeverAppearedOnTheBus,
}

impl StartFailure {
    fn message(&self) -> String {
        match self {
            StartFailure::ReleaseBuild => {
                "release build (--session is debug-only, so this suite cannot \
                 run under `cargo test --release`)"
                    .to_string()
            }
            StartFailure::MissingBinary(path) => format!(
                "porthole-helper binary not found at {} — these tests need the \
                 whole workspace built, e.g. `cargo test` rather than \
                 `cargo test -p porthole-cli`",
                path.display()
            ),
            StartFailure::HelperExited(stderr) => format!(
                "the helper process exited before it started serving \
                 (most likely `resolve_cli` refusing to start) — its stderr: {stderr}"
            ),
            StartFailure::NeverAppearedOnTheBus => {
                "the helper is still running but never appeared on the session \
                 bus within 5s — no session bus reachable, or `busctl` unavailable"
                    .to_string()
            }
        }
    }
}

fn start_helper(state: &std::path::Path) -> Result<Helper, StartFailure> {
    // --session is debug-only, so this test cannot run under --release.
    if !cfg!(debug_assertions) {
        return Err(StartFailure::ReleaseBuild);
    }

    let bin = helper_bin();
    if !bin.exists() {
        return Err(StartFailure::MissingBinary(bin));
    }

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
        if String::from_utf8_lossy(&out.stdout).contains("com.jacopobriccola.Porthole") {
            return Ok(Helper(child));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(StartFailure::NeverAppearedOnTheBus)
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

fn rich_rules() -> String {
    // An info action: `yes` in firewalld's policy, so this works unprivileged.
    Command::new("firewall-cmd")
        .args(["--list-rich-rules"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
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
fn an_open_reaches_the_firewall_and_changes_nothing_when_refused() {
    // The whole chain, up to the point where the real system says no: CLI →
    // bus → porthole's authorization → the helper's validation → the engine →
    // firewall-cmd → firewalld's own polkit, which requires an admin password
    // for config actions. What happens when firewalld agrees is on the human
    // acceptance checklist; it needs root.
    //
    // That assumption is only true when this test itself is unprivileged: as
    // root, firewalld's polkit would not refuse this, the open would really
    // succeed, and the temp state directory vanishing at the end of the test
    // would leave a real rule in the firewall with nothing able to close it.
    // `cli.rs` already guards its own real-firewall tests the same way.
    if is_root() {
        eprintln!("skipped: running as root, where firewalld would not refuse this open");
        return;
    }
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");
    let _helper = start_or_skip!(&state);

    let before = rich_rules();
    let out = cli(&state, &["open", "15173", "--for", "5m"]);

    assert!(
        !out.status.success(),
        "an unprivileged helper cannot change the firewall, so this must fail"
    );
    assert_eq!(
        rich_rules(),
        before,
        "nothing may have been added to the firewall"
    );
    assert!(
        !state.exists()
            || std::fs::read_to_string(&state)
                .unwrap()
                .contains(r#""rules": []"#),
        "a failed open must leave no rule recorded"
    );
}

#[test]
fn closing_a_seeded_phantom_rule_is_pruned_by_reconciliation_not_falsely_reported_open() {
    // I6: the previous version of this test claimed to prove the audit trail
    // names the requesting uid, but called `close 5173` (which fails
    // `RuleNotFound` before `log_close` is ever reached) and `list` (which
    // never touches the bus at all), then asserted only that stderr held the
    // startup banner — true even with every line of `log_close` deleted.
    //
    // To reach `log_close` at all, a rule has to exist for `close_by_id` to
    // find, so one is seeded directly into the state file (needing no
    // firewall access to set up) rather than opened for real. Its target and
    // port are deliberately outside anything a real network would ever use
    // (TEST-NET-3, RFC 5737, and a high port), and its firewalld handle names
    // this machine's own default zone but a rich rule that was never actually
    // added.
    //
    // Before reconciliation (milestone 3, task 5) existed, that made
    // `close --id` reach a real, unauthorized `firewall-cmd
    // --remove-rich-rule` call, which -- with no polkit agent registered to
    // answer firewalld's own internal authorization check -- hung for
    // firewalld's own ~25s reply timeout before failing. This test used to
    // assert exactly that slow failure, and skip itself entirely when run as
    // root (where the removal would have gone through for real instead).
    //
    // Reconciliation changes the outcome, and makes it strictly better:
    // `Engine::close_by_id` now reconciles state against the firewall first
    // (see `porthole_core::reconcile`), which lists this machine's real rich
    // rules -- a read, needing no authorization at all -- and finds that the
    // seeded rule's rich rule genuinely is not among them. It is dropped
    // from state as stale *before* `close_by_id`'s own lookup ever runs, so
    // the close fails fast with "no rule matches" instead of hanging for 25
    // seconds attempting a removal that could only ever fail. There is no
    // longer a privileged-vs-unprivileged split to guard against either: the
    // removal this test used to worry about as root never happens for this
    // rule now, on any account, because reconciliation prunes it first.
    //
    // What this test proves end to end: reconciliation reaches the real
    // backend (a real `firewall-cmd --list-rich-rules` against this
    // machine's own zone, not a fake one), correctly decides the seeded rule
    // is not there, and prunes it -- quickly, and without ever attempting
    // the doomed removal the old version of this test had to wait out.
    //
    // `log_close`'s audit-line format is proven separately and directly:
    // `porthole_helper::service::tests::the_close_line_names_both_uids_when_they_differ`
    // calls `format_close_log` and checks both uids appear in it. This test
    // does not reach `log_close` -- reconciliation prunes the rule before
    // `close_by_id` gets far enough to call it -- and does not claim to.
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");

    const RULE_ID: &str = "i6-seeded-rule";
    const PORT: u16 = 25198;
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
    let started = std::time::Instant::now();
    let out = cli(&state, &["close", "--id", RULE_ID]);
    let elapsed = started.elapsed();

    let _ = helper.0.kill();
    let _ = helper.0.wait();

    assert_eq!(
        out.status.code(),
        Some(7),
        "reconciliation must prune the phantom rule before close_by_id's own \
         lookup runs, so this must report RuleNotFound, not any other \
         outcome; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "reconciliation only reads the real rich rules, which needs no \
         authorization; taking anywhere near the old ~25s polkit timeout \
         would mean it did not prune the rule first, got {elapsed:?}"
    );

    let state_text = std::fs::read_to_string(&state).expect("the state file still exists");
    assert!(
        !state_text.contains(RULE_ID),
        "the phantom rule must be pruned from state, not left behind claiming \
         a port is open that never really was: {state_text}"
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
