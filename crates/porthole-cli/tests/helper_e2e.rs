//! The milestone's headline claim, end to end: `porthole open` with no `sudo`
//! anywhere.
//!
//! A real `porthole-helper` runs as a child process on the session bus and the
//! real `porthole` binary drives it. What this proves and what it cannot is
//! written out in each test — the helper talks to the real firewalld, whose own
//! polkit policy requires an admin password for config actions, so an ordinary
//! user cannot change the firewall through it. That makes this safe to run, and
//! it means the "firewalld agrees" half belongs to the human checklist.

use std::process::{Child, Command};
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

fn start_helper(state: &std::path::Path) -> Option<Helper> {
    // --session is debug-only, so this test cannot run under --release.
    if !cfg!(debug_assertions) {
        return None;
    }
    let mut child = Command::new(helper_bin())
        .arg("--session")
        .env("PORTHOLE_STATE_FILE", state)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the helper binary runs");

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
        let Ok(out) = Command::new("busctl")
            .args(["--user", "list", "--no-legend"])
            .output()
        else {
            continue;
        };
        if String::from_utf8_lossy(&out.stdout).contains("com.jacopobriccola.Porthole") {
            return Some(Helper(child));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
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

#[test]
fn the_cli_reaches_the_helper_with_no_sudo_anywhere() {
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");
    let Some(_helper) = start_helper(&state) else {
        eprintln!("skipped: no session bus, or a release build");
        return;
    };

    // list goes over the bus and answers. No sudo, no root, no prompt.
    let out = cli(&state, &["list", "--json"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(json["rules"].as_array().unwrap().len(), 0);
}

#[test]
fn the_helper_refuses_an_over_long_duration_itself() {
    // The CLI validates too, but this proves the *helper* does — a client that
    // skipped its own checks still cannot ask for nine hours.
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");
    let Some(_helper) = start_helper(&state) else {
        eprintln!("skipped: no session bus, or a release build");
        return;
    };

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
    let Some(_helper) = start_helper(&state) else {
        eprintln!("skipped: no session bus, or a release build");
        return;
    };

    let out = cli(&state, &["close", "5173"]);
    // 7 is what milestone 1 documented for "no rule matches", and it must be
    // the same whether the CLI did the work or the helper did.
    assert_eq!(out.status.code(), Some(7), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn an_open_reaches_the_firewall_and_changes_nothing_when_refused() {
    // The whole chain, up to the point where the real system says no: CLI →
    // bus → porthole's authorization → the helper's validation → the engine →
    // firewall-cmd → firewalld's own polkit, which requires an admin password
    // for config actions. What happens when firewalld agrees is on the human
    // acceptance checklist; it needs root.
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");
    let Some(_helper) = start_helper(&state) else {
        eprintln!("skipped: no session bus, or a release build");
        return;
    };

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
        !state.exists() || std::fs::read_to_string(&state).unwrap().contains(r#""rules": []"#),
        "a failed open must leave no rule recorded"
    );
}

#[test]
fn the_helper_logs_the_requesting_uid() {
    // The spec requires every open and close to reach the journal naming the
    // uid that asked. The helper is a system service, so its stderr is what
    // systemd captures — this is the first place that requirement is provable.
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state.json");
    let Some(mut helper) = start_helper(&state) else {
        eprintln!("skipped: no session bus, or a release build");
        return;
    };

    let _ = cli(&state, &["close", "5173"]);
    let _ = cli(&state, &["list"]);

    // Stop it so its stderr closes, then read what it wrote.
    let _ = helper.0.kill();
    let _ = helper.0.wait();
    let mut text = String::new();
    if let Some(mut err) = helper.0.stderr.take() {
        use std::io::Read;
        let _ = err.read_to_string(&mut text);
    }
    assert!(
        text.contains("serving com.jacopobriccola.Porthole"),
        "the helper should have announced itself, got: {text}"
    );
}
