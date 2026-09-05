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
    let out = porthole(&["--help"], &state_path(&dir));
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("temporarily"));

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
