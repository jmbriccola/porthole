//! End-to-end tests against the built binary.
//!
//! Everything here runs unprivileged. Tests that would need root, or a
//! firewall that is not installed, skip themselves rather than fail: this file
//! has to be runnable on a developer laptop and in a bare CI container alike.

use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn porthole(args: &[&str], state: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_porthole"))
        .args(args)
        .env("PORTHOLE_STATE_FILE", state)
        .output()
        .expect("porthole binary runs")
}

fn code(out: &Output) -> i32 {
    out.status
        .code()
        .expect("process was not killed by a signal")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn have(program: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn state_path(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("state.json")
}

#[test]
fn help_and_version_work() {
    let dir = TempDir::new().unwrap();

    // clap shows `about` for -h and `long_about` for --help, and they do not
    // share wording. Both must say what porthole is for rather than just
    // listing flags, so pin a distinctive phrase from each.
    let out = porthole(&["-h"], &state_path(&dir));
    assert_eq!(code(&out), 0);
    assert!(
        stdout(&out).contains("temporarily"),
        "got: {}",
        stdout(&out)
    );

    let out = porthole(&["--help"], &state_path(&dir));
    assert_eq!(code(&out), 0);
    assert!(
        stdout(&out).contains("bounded amount of time"),
        "got: {}",
        stdout(&out)
    );

    let out = porthole(&["--version"], &state_path(&dir));
    assert_eq!(code(&out), 0);
}

#[test]
fn an_out_of_range_port_exits_two_and_says_the_range() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "99999"], &state_path(&dir));
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("1-65535"), "got: {}", stderr(&out));
}

#[test]
fn a_duration_over_eight_hours_exits_two_and_points_at_until_reboot() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "5173", "--for", "24h"], &state_path(&dir));
    assert_eq!(code(&out), 2);
    let message = stderr(&out);
    assert!(message.contains("8 hours"), "got: {message}");
    assert!(message.contains("--until-reboot"), "got: {message}");
}

#[test]
fn an_ipv6_target_exits_two_and_says_ipv6_is_out_of_scope() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "5173", "--to", "fe80::1"], &state_path(&dir));
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("IPv6"), "got: {}", stderr(&out));
}

#[test]
fn for_and_until_reboot_cannot_be_combined() {
    let dir = TempDir::new().unwrap();
    let out = porthole(
        &["open", "5173", "--for", "1h", "--until-reboot"],
        &state_path(&dir),
    );
    assert_eq!(code(&out), 2);
}

#[test]
fn errors_are_reported_as_json_when_asked() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "99999", "--json"], &state_path(&dir));
    assert_eq!(code(&out), 2);
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json["error"]["code"], 2);
    assert_eq!(json["error"]["kind"], "invalid_argument");
}

#[test]
fn an_empty_list_is_an_empty_array() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["list", "--json"], &state_path(&dir));
    assert_eq!(code(&out), 0);
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(json["schema"], 1);
    assert_eq!(json["rules"].as_array().unwrap().len(), 0);
}

#[test]
fn opening_without_privileges_exits_not_authorized() {
    if is_root() {
        eprintln!("skipped: running as root");
        return;
    }
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "5173"], &state_path(&dir));
    assert_eq!(code(&out), 4);
    assert!(stderr(&out).contains("--dry-run"), "got: {}", stderr(&out));
}

#[test]
fn dry_run_needs_no_privileges_and_changes_nothing() {
    if !have("firewall-cmd") || !have("ip") {
        eprintln!("skipped: needs firewall-cmd and ip");
        return;
    }
    let dir = TempDir::new().unwrap();
    let path = state_path(&dir);

    let out = porthole(&["open", "5173", "--for", "30m", "--dry-run"], &path);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let text = stdout(&out);
    assert!(text.contains("--add-rich-rule"), "got: {text}");
    assert!(text.contains("port=\"5173\""), "got: {text}");
    assert!(text.contains("protocol=\"tcp\""), "got: {text}");
    assert!(text.contains("systemd-run"), "got: {text}");
    assert!(text.contains("--on-active=1800s"), "got: {text}");
    assert!(
        !text.contains("--permanent"),
        "porthole must never propose a permanent rule: {text}"
    );
    assert!(text.contains("Nothing was changed"), "got: {text}");

    assert!(!path.exists(), "dry-run must not write the state file");

    // The audit trail must not claim an opening that never happened.
    assert!(!stderr(&out).contains("opened"), "got: {}", stderr(&out));
}

#[test]
fn dry_run_json_lists_the_commands_it_would_run() {
    if !have("firewall-cmd") || !have("ip") {
        eprintln!("skipped: needs firewall-cmd and ip");
        return;
    }
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "5173", "--dry-run", "--json"], &state_path(&dir));
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json["dry_run"], true);
    assert_eq!(json["rule"]["port"], 5173);
    assert_eq!(json["rule"]["protocol"], "tcp");
    // The default duration is one hour.
    assert_eq!(json["rule"]["expires_in_seconds"], 3600);
    let commands = json["commands"].as_array().unwrap();
    assert!(commands
        .iter()
        .any(|c| c.as_str().unwrap().contains("--add-rich-rule")));
}

#[test]
fn the_default_scope_is_the_current_subnet_never_anywhere() {
    if !have("firewall-cmd") || !have("ip") {
        eprintln!("skipped: needs firewall-cmd and ip");
        return;
    }
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "5173", "--dry-run", "--json"], &state_path(&dir));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        json["rule"]["scope"], "network",
        "the default must never be `anywhere`"
    );
    assert!(
        json["rule"]["target"].as_str().unwrap().contains('/'),
        "the default target must be a CIDR"
    );
}

#[test]
fn close_without_a_target_says_what_is_missing() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close"], &state_path(&dir));
    assert_eq!(code(&out), 2);
    let message = stderr(&out);
    assert!(message.contains("--all"), "got: {message}");
}

#[test]
fn close_rejects_conflicting_targets() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close", "5173", "--all"], &state_path(&dir));
    assert_eq!(code(&out), 2);
}

#[test]
fn closing_without_privileges_exits_not_authorized() {
    if is_root() {
        eprintln!("skipped: running as root");
        return;
    }
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close", "5173"], &state_path(&dir));
    assert_eq!(code(&out), 4);
}

#[test]
fn closing_a_port_that_is_not_open_exits_rule_not_found() {
    if !have("firewall-cmd") || !have("ip") {
        eprintln!("skipped: needs firewall-cmd and ip");
        return;
    }
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close", "5173", "--dry-run"], &state_path(&dir));
    assert_eq!(code(&out), 7, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("5173/tcp"), "got: {}", stderr(&out));
}

#[test]
fn close_all_on_an_empty_state_succeeds_quietly() {
    if !have("firewall-cmd") || !have("ip") {
        eprintln!("skipped: needs firewall-cmd and ip");
        return;
    }
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close", "--all", "--dry-run"], &state_path(&dir));
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("Nothing to close"),
        "got: {}",
        stdout(&out)
    );
}

#[test]
fn close_all_json_on_an_empty_state_is_an_empty_array() {
    if !have("firewall-cmd") || !have("ip") {
        eprintln!("skipped: needs firewall-cmd and ip");
        return;
    }
    let dir = TempDir::new().unwrap();
    let out = porthole(
        &["close", "--all", "--dry-run", "--json"],
        &state_path(&dir),
    );
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(json["closed"].as_array().unwrap().len(), 0);
}

#[test]
fn a_dry_run_works_without_a_writable_state_directory() {
    // Every other test points PORTHOLE_STATE_FILE at a temp path, so none of
    // them touches the real /run/porthole — which does not exist until
    // something privileged creates it. A dry run must still work there,
    // because --dry-run needs no privileges. Taking the state lock would try
    // to create that directory and fail.
    if is_root() {
        eprintln!("skipped: running as root");
        return;
    }
    if !have("firewall-cmd") || !have("ip") {
        eprintln!("skipped: needs firewall-cmd and ip");
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_porthole"))
        .args(["open", "5173", "--dry-run", "--json"])
        .env_remove("PORTHOLE_STATE_FILE")
        .output()
        .expect("porthole binary runs");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn status_works_without_a_writable_state_directory() {
    // The same directory-creation problem that broke a dry-run `open` above
    // also broke `status`: it went through the same `make_engine`, and the
    // README promises `porthole status` needs no privileges, with no
    // `--dry-run` exception — it is a query, not an operation. This is a
    // second, independent regression that a single `for_write` gate on
    // `--dry-run` alone would not have caught, since `status` never writes
    // regardless of that flag.
    if is_root() {
        eprintln!("skipped: running as root");
        return;
    }
    if !have("firewall-cmd") || !have("ip") {
        eprintln!("skipped: needs firewall-cmd and ip");
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_porthole"))
        .args(["status", "--json"])
        .env_remove("PORTHOLE_STATE_FILE")
        .output()
        .expect("porthole binary runs");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_default_scope_is_declared_as_subnet_in_the_help() {
    // The dry-run test that proves the default resolves to a real CIDR skips
    // itself where there is no firewall. This one cannot: it reads --help and
    // nothing else, so the guard on `--to`'s default survives on a bare CI
    // container.
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "--help"], &state_path(&dir));
    assert_eq!(code(&out), 0);
    assert!(
        stdout(&out).contains("[default: subnet]"),
        "got: {}",
        stdout(&out)
    );
}

#[test]
fn from_timer_is_hidden_from_the_help() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close", "--help"], &state_path(&dir));
    assert_eq!(code(&out), 0);
    assert!(
        !stdout(&out).contains("--from-timer"),
        "an internal flag has no business in the help"
    );
}
