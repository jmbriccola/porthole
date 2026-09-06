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
fn opening_without_a_helper_says_the_helper_is_missing() {
    // Milestone 2 removed the root requirement: the CLI holds no privilege at
    // all now. Without a helper on the bus there is nothing to ask, which is
    // "no usable backend" (3), not "not authorized" (4).
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "5173"], &state_path(&dir));
    assert_eq!(code(&out), 3, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("doctor"), "got: {}", stderr(&out));
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
fn forget_without_an_id_is_rejected_even_alongside_a_port() {
    // clap's own `#[arg(requires = "id")]` on `--forget` does not catch
    // `close <port> --forget` by itself -- verified by hand: `--id` also
    // `conflicts_with_all(["port", ...])`, and clap does not treat that
    // three-way combination as unsatisfiable. Without `run.rs`'s own
    // explicit check, `close <port> --forget` would silently perform an
    // ordinary close and ignore `--forget` entirely, which is exactly the
    // implicit forgetting the flag must never allow.
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close", "5173", "--forget"], &state_path(&dir));
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("--id"), "got: {}", stderr(&out));
}

#[test]
fn forget_without_an_id_at_all_is_rejected() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close", "--forget"], &state_path(&dir));
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
}

#[test]
fn closing_without_a_helper_says_the_helper_is_missing() {
    // Same change as `open`, and for the same reason: without a helper on the
    // bus there is no one to authorize or deny the request, so this is
    // "no usable backend" (3), not "not authorized" (4).
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close", "5173"], &state_path(&dir));
    assert_eq!(code(&out), 3, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("doctor"), "got: {}", stderr(&out));
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

#[test]
fn doctor_runs_unprivileged_and_says_something_about_every_check() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["doctor"], &state_path(&dir));
    // 0 when everything passes, 1 when something needs attention. Either is a
    // successful run of doctor itself.
    assert!(
        code(&out) == 0 || code(&out) == 1,
        "doctor should report, not crash: {} / {}",
        code(&out),
        stderr(&out)
    );
    let json = porthole(&["doctor", "--json"], &state_path(&dir));
    let json: serde_json::Value = serde_json::from_str(&stdout(&json)).expect("valid JSON");
    let names: Vec<&str> = json["checks"]
        .as_array()
        .expect("a checks array")
        .iter()
        .map(|c| c["name"].as_str().expect("a name"))
        .collect();
    // The full ordered list, not just containment: docs/json-schema.md
    // documents this exact order, and a check inserted anywhere but the end
    // (as `Expiry timer` was) must fail this test until the doc is updated
    // too, rather than passing silently because every name still appears
    // somewhere.
    assert_eq!(
        names,
        vec![
            "Firewall",
            "Helper",
            "Expiry timer",
            "polkit",
            "State",
            "Network",
            "Docker",
            "IPv6",
        ],
        "doctor's check order drifted from what docs/json-schema.md promises"
    );
}

#[test]
fn every_failing_check_says_what_to_do_about_it() {
    // A diagnostic that reports a problem without a remedy has done half the
    // job, and it is the half a stuck user cannot supply themselves.
    let dir = TempDir::new().unwrap();
    let out = porthole(&["doctor", "--json"], &state_path(&dir));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json["schema"], 1);
    let checks = json["checks"].as_array().expect("a checks array");
    assert!(!checks.is_empty());
    for check in checks {
        assert!(check["name"].is_string(), "got: {check}");
        assert!(check["ok"].is_boolean(), "got: {check}");
        assert!(
            !check["detail"].as_str().unwrap().is_empty(),
            "got: {check}"
        );
        if !check["ok"].as_bool().unwrap() {
            assert!(
                !check["remedy"].as_str().unwrap().is_empty(),
                "a failing check must say what to do: {check}"
            );
        }
    }
}

#[test]
fn doctor_notices_docker_on_a_machine_that_has_it() {
    // This machine runs Docker, and Docker publishes container ports below
    // the firewall — porthole cannot close what it never opened.
    if !std::path::Path::new("/sys/class/net/docker0").exists() {
        eprintln!("skipped: no docker0 on this machine");
        return;
    }
    let dir = TempDir::new().unwrap();
    let out = porthole(&["doctor", "--json"], &state_path(&dir));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let docker = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "Docker")
        .expect("a Docker check");
    assert!(
        docker["detail"].as_str().unwrap().contains("0.0.0.0")
            || docker["detail"].as_str().unwrap().contains("publish"),
        "the Docker check must explain the consequence, got: {docker}"
    );
}

#[test]
fn doctor_says_the_helper_is_missing_when_it_is() {
    // No helper is running in the test environment, so this check must fail —
    // and its remedy must name both things that could be missing.
    let dir = TempDir::new().unwrap();
    let out = porthole(&["doctor", "--json"], &state_path(&dir));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let helper = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "Helper")
        .expect("a Helper check");
    assert_eq!(helper["ok"], false);
    let remedy = helper["remedy"].as_str().unwrap();
    assert!(
        remedy.contains("/usr/libexec/porthole-helper"),
        "got: {remedy}"
    );
    assert!(remedy.contains("dbus"), "got: {remedy}");
}

#[test]
fn doctor_names_all_three_backends_when_none_is_found() {
    // Milestone 3 made this message drift: the Firewall check used to say
    // "porthole 0.1 manages firewalld only... wait for the ufw and nftables
    // backends", which became false the moment those two backends shipped.
    // Forcing the real "nothing found" path through the built binary --
    // rather than only the library's own `backend::detect` unit test --
    // catches drift in whatever doctor.rs wraps around that message, not
    // just in the message itself. Hiding every firewall CLI by pointing PATH
    // somewhere empty is the only way to reach this deterministically without
    // uninstalling firewalld from the machine running the test suite.
    let dir = TempDir::new().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_porthole"))
        .args(["doctor", "--json"])
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PATH", "/nonexistent-porthole-test-path")
        .output()
        .expect("porthole binary runs");
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let firewall = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "Firewall")
        .expect("a Firewall check");
    assert_eq!(firewall["ok"], false);
    let detail = firewall["detail"].as_str().unwrap();
    for name in ["firewalld", "ufw", "nftables"] {
        assert!(detail.contains(name), "must name {name}: {detail}");
    }
    let remedy = firewall["remedy"].as_str().unwrap();
    assert!(
        !remedy.to_lowercase().contains("wait for"),
        "must not tell someone to wait for a backend that already shipped: {remedy}"
    );
}
