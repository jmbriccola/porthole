//! End-to-end tests against the built binary.
//!
//! Everything here runs unprivileged, and nothing here skips itself.
//!
//! This file has to be runnable on a developer laptop and in a bare CI
//! container alike, and for a while the way it did that was
//! `if !have("firewall-cmd") { eprintln!("skipped: ..."); return; }` -- which
//! libtest counts as `ok`. Measured: on a `PATH` with no `firewall-cmd` and
//! no `ip`, twelve tests printed `skipped:` and the run reported
//! `49 passed; 0 failed`. Among them was the whole of the host-level `--as`
//! coverage and the coverage of a Critical fixed on this same branch.
//!
//! The cure is [`stub_firewalld_and_ip`], not a louder failure: a suite that
//! goes red on a ufw laptop is a different way of not being run. Every
//! command porthole issues to those two programs is a read of a handful of
//! fixed shapes, so a test can carry its own. Same `PATH`, after: 49 passed,
//! nothing skipped.
//!
//! # Why every process started here is given a bus of its own
//!
//! `porthole open` and `porthole close` change no firewall themselves. They
//! send a D-Bus request to the privileged helper on the system bus, and the
//! helper runs `firewall-cmd` in its own process. On a machine with the
//! porthole package installed, three tests below — each written to assert
//! that there is no helper to ask — reached the real one: `porthole open
//! 5173` sat on a polkit password prompt for over eight minutes, the person
//! who eventually answered it authorized the open, and a rich rule was left
//! on that machine's firewall. A `PATH` shim counting `firewall-cmd`
//! invocations recorded none of it, because the process that runs
//! `firewall-cmd` is the helper, not anything this file starts.
//!
//! So [`isolation`] starts one private `dbus-run-session` daemon for this
//! test binary, and every porthole process below is given
//! `DBUS_SYSTEM_BUS_ADDRESS` and `DBUS_SESSION_BUS_ADDRESS` pointing at it.
//! Nothing owns `com.jacopobriccola.Porthole` on that daemon, and the
//! helper's activation file is a *system*-bus one, which a session daemon
//! does not read — so a request for the helper comes back as
//! `ServiceUnknown`, which is what a machine without porthole installed
//! answers and what these tests were written against.
//! [`the_bus_redirection_is_what_the_binary_actually_reads`] is the negative
//! control: it names the address it sets and fails on any machine, with a
//! helper or without one, if that address stops being the one the binary
//! reads.
//!
//! `firewall-cmd` reaches firewalld over that same variable. Redirecting it
//! process-wide was measured making `firewall-cmd --state` print "Waiting on
//! dbus connection..." for eleven seconds and then "not running", with
//! `porthole open --dry-run --json` still running after thirty. So the
//! `firewall-cmd` first on these processes' `PATH` is [a shim](shimmed_path)
//! that unsets both variables and execs the real one: firewalld is reached,
//! the helper is not.
//!
//! # Nothing here waits
//!
//! Every porthole process started below is killed at [`DEADLINE`] and its
//! test fails. The two runs described above hung for more than five hundred
//! seconds each, on a machine whose owner was somewhere else.
//!
//! # Twelve tests that a release build must not run, and what enforces it
//!
//! `PORTHOLE_STATE_FILE` and `PORTHOLE_DEVICES_FILE` are honoured only where
//! `cfg!(debug_assertions)` holds, deliberately: a release binary runs
//! privileged and must not take the location of its state or its address book
//! from the environment. Twelve tests below depend on being honoured, so they
//! carry `#[cfg_attr(not(debug_assertions), ignore = ...)]` and a
//! `cargo test --release` reports them as `ignored`, **by name**, with the
//! reason attached. That is the arrangement `helper_e2e.rs` already had for
//! the same shape of problem; this file did not, and a release run of it was
//! simply red: 42 passed, 7 failed.
//!
//! **The attribute is not the enforcement**, because forgetting an attribute
//! is exactly what happened. [`refuse_a_release_build_the_address_book`] and
//! [`refuse_a_release_build_the_state_file`] are called from the two helpers
//! that seed a book and a state file, so a test that reaches for either
//! without the attribute fails in `cargo test --release` at its own setup,
//! before it can start a process. Read those two functions for why that is an
//! assertion and not a comment.
//!
//! In short: under `--release` the override is not lost, the **real** file is
//! used instead.
//! `the_picker_hides_containers_and_shows_a_name_where_the_resolver_has_one`
//! drives `porthole devices add` to a save, and on two occasions it saved this
//! file's fabricated `router` fixture into a real person's
//! `~/.config/porthole/devices.toml`.
//! `devices_rm_of_something_that_is_not_there_fails_rather_than_reporting_success`
//! is the same hazard unfired: `devices rm phone` against a real book that
//! holds a `phone` is a delete. Five of the twelve used to *pass* under
//! `--release` while reading that real book, their own setup inert -- which is
//! a green tick for a premise that never held.
//!
//! What is *not* claimed. This does not stop a release run reading the real
//! state file: nearly every test here sets `PORTHOLE_STATE_FILE` through
//! [`porthole`], and under `--release` all of them read
//! `/run/porthole/state.json` -- most simply do not care what is in it, which
//! is why they pass, and why the assertion is not in [`porthole`]. Nor does it
//! cover a test that writes a state file with `std::fs::write` rather than
//! [`write_state`]. What the twelve ignores remove is every release assertion
//! that depended on the override, and both writes.

use std::ffi::OsString;
use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// How long a porthole process started here may run before it is killed and
/// its test fails. Long enough that a loaded machine running the whole
/// workspace's tests in parallel is not what trips it.
const DEADLINE: Duration = Duration::from_secs(60);

/// The bus every porthole process below talks to, and the `PATH` that keeps
/// `firewall-cmd` off it.
struct Isolation {
    /// `dbus-run-session`, alive for as long as the pipe its inner shell
    /// reads stays open. This process exiting closes that pipe, the shell
    /// exits, and the daemon goes down with it — so nothing is left behind
    /// even though this value is never dropped.
    _daemon: Child,
    address: String,
    path: OsString,
}

fn isolation() -> &'static Isolation {
    static ISOLATION: OnceLock<Isolation> = OnceLock::new();
    ISOLATION.get_or_init(|| {
        // Asserted, not skipped. A test that cannot get its own bus must
        // fail rather than quietly run against this machine's.
        let mut daemon = Command::new("dbus-run-session")
            .args([
                "--",
                "sh",
                "-c",
                r#"echo "$DBUS_SESSION_BUS_ADDRESS"; exec cat >/dev/null"#,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-run-session is installed");
        let mut address = String::new();
        std::io::BufReader::new(daemon.stdout.take().expect("stdout was piped"))
            .read_line(&mut address)
            .expect("the private bus prints its address");
        let address = address.trim().to_string();
        assert!(!address.is_empty(), "dbus-run-session printed no address");
        Isolation {
            _daemon: daemon,
            address,
            path: shimmed_path(),
        }
    })
}

/// A `PATH` whose `firewall-cmd` still reaches this machine's real firewalld.
///
/// firewalld is spoken to over `DBUS_SYSTEM_BUS_ADDRESS`, the same variable
/// that points every porthole process here at a bus with no helper on it.
/// The shim written here unsets it and execs the real binary, so the two
/// uses of one variable stop fighting: the tests that assert firewalld's own
/// `--add-rich-rule` wording get firewalld, and no porthole process gets a
/// helper.
///
/// The directory is beside the test binary rather than in a temporary one,
/// so nothing outlives `cargo clean`, and the shim is renamed into place so
/// a concurrently starting test binary never reads a half-written file.
fn shimmed_path() -> OsString {
    let dir = PathBuf::from(env!("CARGO_BIN_EXE_porthole")).with_file_name("cli-test-path");
    std::fs::create_dir_all(&dir).expect("the build directory is writable");
    if let Some(real) = which("firewall-cmd") {
        let staging = dir.join(format!("firewall-cmd.{}", std::process::id()));
        std::fs::write(
            &staging,
            format!(
                "#!/bin/sh\n\
                 # Written by `shimmed_path` in crates/porthole-cli/tests/cli.rs.\n\
                 unset DBUS_SYSTEM_BUS_ADDRESS\n\
                 unset DBUS_SESSION_BUS_ADDRESS\n\
                 exec {} \"$@\"\n",
                real.display()
            ),
        )
        .expect("the build directory is writable");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))
            .expect("the shim can be made executable");
        std::fs::rename(&staging, dir.join("firewall-cmd")).expect("the shim can be put in place");
    }
    let mut path = dir.into_os_string();
    if let Some(inherited) = std::env::var_os("PATH") {
        path.push(":");
        path.push(inherited);
    }
    path
}

/// Where `program` is, on the `PATH` this test binary itself inherited.
fn which(program: &str) -> Option<PathBuf> {
    let out = Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let found = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!found.is_empty()).then(|| PathBuf::from(found))
}

/// A `porthole` invocation pointed at the private bus. A caller that needs a
/// `PATH` of its own sets one afterwards, which replaces the one set here;
/// the bus stays redirected either way.
fn porthole_command(args: &[&str]) -> Command {
    let isolation = isolation();
    let mut command = Command::new(env!("CARGO_BIN_EXE_porthole"));
    command
        .args(args)
        .env("DBUS_SYSTEM_BUS_ADDRESS", &isolation.address)
        .env("DBUS_SESSION_BUS_ADDRESS", &isolation.address)
        .env_remove("DBUS_STARTER_ADDRESS")
        .env_remove("DBUS_STARTER_BUS_TYPE")
        .env("PATH", &isolation.path);
    command
}

/// Runs `command` to completion, killing it at [`DEADLINE`]. `stdin`, when
/// given, is written and the pipe closed before the wait begins.
///
/// The two pipes are drained on threads of their own rather than after the
/// wait, so a child that fills one cannot deadlock against the deadline that
/// is supposed to be watching it.
fn run(mut command: Command, stdin: Option<&[u8]>) -> Output {
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("porthole binary runs");
    if let Some(bytes) = stdin {
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(bytes)
            .expect("the child reads its input");
    }
    let mut out = child.stdout.take().expect("stdout was piped");
    let mut err = child.stderr.take().expect("stderr was piped");
    let out = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = out.read_to_end(&mut buffer);
        buffer
    });
    let err = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = err.read_to_end(&mut buffer);
        buffer
    });

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("the child is waitable") {
            break status;
        }
        if started.elapsed() >= DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "a porthole process was still running after {} seconds and was killed. \
                 Nothing started by this file may wait for anything; reaching a real \
                 helper, and through it a polkit prompt, is how that has happened before.",
                DEADLINE.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    Output {
        status,
        stdout: out.join().expect("the stdout reader finishes"),
        stderr: err.join().expect("the stderr reader finishes"),
    }
}

fn porthole(args: &[&str], state: &Path) -> Output {
    let mut command = porthole_command(args);
    command.env("PORTHOLE_STATE_FILE", state);
    run(command, None)
}

/// `porthole` with the address book pointed at a file of this test's own.
fn porthole_with_devices(args: &[&str], state: &Path, devices: &Path) -> Output {
    refuse_a_release_build_the_address_book();
    let mut command = porthole_command(args);
    command
        .env("PORTHOLE_STATE_FILE", state)
        .env("PORTHOLE_DEVICES_FILE", devices);
    run(command, None)
}

/// A book with one device in it, written straight to disk -- `devices add`
/// is an interactive prompt and cannot be driven from here.
fn write_book(path: &Path, body: &str) {
    refuse_a_release_build_the_address_book();
    std::fs::write(path, body).expect("the temp dir is writable");
}

/// Stop a release build here, before it can reach the invoking user's own
/// address book.
///
/// `PORTHOLE_DEVICES_FILE` is honoured only where `cfg!(debug_assertions)`
/// holds (`porthole_core::devices::default_path_from`), deliberately: a
/// release binary runs privileged and must not take a config path from its
/// environment. What that means for a test is not that the override is
/// *lost* -- it is that the real book is used instead, and the real book is
/// `$XDG_CONFIG_HOME/porthole/devices.toml` or `~/.config/porthole/devices.toml`
/// belonging to whoever ran `cargo test`.
///
/// **That is not hypothetical.** It happened twice on the developer's own
/// machine, in the audit's release run and in the run that measured it for
/// this change: `the_picker_hides_containers_and_shows_a_name_where_the_
/// resolver_has_one` drives `porthole devices add` to a save, and it saved
/// this file's fabricated `router` fixture -- MAC `50:e6:36:51:42:fd`,
/// which appears nowhere but in test sources -- into that person's real
/// address book, where it remains, resolving to nothing.
/// `devices_rm_of_something_that_is_not_there_fails_rather_than_reporting_success`
/// is the same hazard waiting: it runs `devices rm phone`, and on a real book
/// that happens to hold a device called `phone`, that is a delete.
///
/// So this is an assertion and not a comment. Every test that seeds or reads
/// a book of its own carries
/// `#[cfg_attr(not(debug_assertions), ignore = ...)]`, and this is what makes
/// forgetting one a red test rather than a write into somebody's home
/// directory.
/// `#[cfg]` on the statement rather than `assert!(cfg!(debug_assertions))`,
/// which clippy rejects as an assertion on a constant -- and it is right that
/// it is one. The condition is a compile-time fact, so the honest spelling is
/// code that exists only in the build it is about.
fn refuse_a_release_build_the_address_book() {
    #[cfg(not(debug_assertions))]
    panic!(
        "PORTHOLE_DEVICES_FILE is honoured in debug builds only, so this release \
         build would ignore the book this test set up and use the invoking user's \
         own ~/.config/porthole/devices.toml instead -- reading it, and on any \
         path that saves or forgets a device, writing it. This test needs \
         `#[cfg_attr(not(debug_assertions), ignore = ...)]`. See this function's \
         own comment for the two occasions it was needed and did not exist."
    );
}

/// The same refusal for the state file: `PORTHOLE_STATE_FILE` is honoured
/// only where `cfg!(debug_assertions)` holds
/// (`porthole_core::state::state_path_from`), so a release build reads
/// `/run/porthole/state.json` -- the machine's real one -- instead of what a
/// test wrote.
///
/// Called from [`write_state`] and not from [`porthole`], and the difference
/// is the whole point. Nearly every test in this file goes through
/// [`porthole`] to check an exit code or a refusal that never touches the
/// state file at all; asserting there would claim those tests depend on the
/// override, which is false, and would put the forty-odd of them back to
/// failing under `--release`. Seeding state and then expecting the binary to
/// read it back is what [`write_state`] means, and that is what depends on it.
///
/// **The limit, stated rather than left to be discovered**: a test that writes
/// a state file with `std::fs::write` instead of [`write_state`] is not
/// covered by this.
/// Spelled with `#[cfg]` for the reason
/// [`refuse_a_release_build_the_address_book`] gives.
fn refuse_a_release_build_the_state_file() {
    #[cfg(not(debug_assertions))]
    panic!(
        "PORTHOLE_STATE_FILE is honoured in debug builds only, so this release \
         build would ignore the state file this test just wrote and read \
         /run/porthole/state.json -- the machine's real one -- instead. This test \
         needs `#[cfg_attr(not(debug_assertions), ignore = ...)]`."
    );
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

/// The refusal names the ceiling and the lifetime beyond it.
///
/// "until reboot" and not "`--until-reboot`": the same `porthole-core`
/// message is shown in the GUI's custom-duration field, where a flag is an
/// instruction the reader has no command line to type it on. The flag is
/// still what this surface takes, and `porthole open --help` is where it is
/// spelled.
#[test]
fn a_duration_over_eight_hours_exits_two_and_points_at_until_reboot() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "5173", "--for", "24h"], &state_path(&dir));
    assert_eq!(code(&out), 2);
    let message = stderr(&out);
    assert!(message.contains("8 hours"), "got: {message}");
    assert!(message.contains("until reboot"), "got: {message}");
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

/// The negative control for [`porthole_command`]'s bus redirection.
///
/// Three tests below assert that no helper answers. They are only worth
/// anything if the bus they reach is the one this file chose; on the machine
/// where this defect was found, all three had quietly started asserting
/// something else against a live system helper, and one of them opened a
/// port to prove it.
///
/// So this points `DBUS_SYSTEM_BUS_ADDRESS` at a socket that does not exist
/// and requires `doctor` to name *that address* in what it says about the
/// Helper check. A binary that read the variable can only say this; a binary
/// that ignored it says "answering" where a helper is installed, "not
/// answering on the bus" where one is not, and names the system socket in
/// neither case. Nothing about this machine makes it pass.
#[test]
fn the_bus_redirection_is_what_the_binary_actually_reads() {
    let dir = TempDir::new().unwrap();
    let absent = format!("unix:path={}", dir.path().join("no-bus-here").display());
    let mut command = porthole_command(&["doctor", "--json"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("DBUS_SYSTEM_BUS_ADDRESS", &absent)
        .env("DBUS_SESSION_BUS_ADDRESS", &absent);
    let out = run(command, None);

    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let helper = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "Helper")
        .expect("a Helper check");
    assert_eq!(helper["ok"], false, "got: {helper}");
    let detail = helper["detail"].as_str().unwrap();
    assert!(
        detail.contains(&absent),
        "the binary went somewhere other than the address it was given: {detail}"
    );
}

#[test]
fn opening_without_a_helper_says_the_helper_is_missing() {
    // Milestone 2 removed the root requirement: the CLI holds no privilege at
    // all now. Without a helper on the bus there is nothing to ask, which is
    // "no usable backend" (3), not "not authorized" (4).
    //
    // `porthole open 5173` is a real request, not a rehearsal: it is what
    // this test runs and there is no flag that makes it less than that. What
    // keeps it from reaching a helper is the bus `porthole` below is pointed
    // at -- see this file's module doc, and the control test above.
    let dir = TempDir::new().unwrap();
    let out = porthole(&["open", "5173"], &state_path(&dir));
    assert_eq!(code(&out), 3, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("doctor"), "got: {}", stderr(&out));
}

#[test]
fn dry_run_needs_no_privileges_and_changes_nothing() {
    let dir = TempDir::new().unwrap();
    let path = state_path(&dir);

    let out = porthole_with_a_firewall(
        &["open", "5173", "--for", "30m", "--dry-run"],
        &path,
        &bin_dir(&dir),
    );
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
    let dir = TempDir::new().unwrap();
    let out = porthole_with_a_firewall(
        &["open", "5173", "--dry-run", "--json"],
        &state_path(&dir),
        &bin_dir(&dir),
    );
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
    let dir = TempDir::new().unwrap();
    let out = porthole_with_a_firewall(
        &["open", "5173", "--dry-run", "--json"],
        &state_path(&dir),
        &bin_dir(&dir),
    );
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
    //
    // And, as with `open`, this is a real close of whatever the helper it
    // reaches has: `com.jacopobriccola.Porthole.close` carries no polkit
    // prompt, so nothing would have stopped it on the machine where this was
    // found. The bus is what stops it.
    let dir = TempDir::new().unwrap();
    let out = porthole(&["close", "5173"], &state_path(&dir));
    assert_eq!(code(&out), 3, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("doctor"), "got: {}", stderr(&out));
}

#[test]
fn closing_a_port_that_is_not_open_exits_rule_not_found() {
    let dir = TempDir::new().unwrap();
    let out = porthole_with_a_firewall(
        &["close", "5173", "--dry-run"],
        &state_path(&dir),
        &bin_dir(&dir),
    );
    assert_eq!(code(&out), 7, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("5173/tcp"), "got: {}", stderr(&out));
}

#[test]
fn close_all_on_an_empty_state_succeeds_quietly() {
    let dir = TempDir::new().unwrap();
    let out = porthole_with_a_firewall(
        &["close", "--all", "--dry-run"],
        &state_path(&dir),
        &bin_dir(&dir),
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("Nothing to close"),
        "got: {}",
        stdout(&out)
    );
}

#[test]
fn close_all_json_on_an_empty_state_is_an_empty_array() {
    let dir = TempDir::new().unwrap();
    let out = porthole_with_a_firewall(
        &["close", "--all", "--dry-run", "--json"],
        &state_path(&dir),
        &bin_dir(&dir),
    );
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(json["closed"].as_array().unwrap().len(), 0);
}

#[test]
fn a_dry_run_works_without_a_writable_state_directory() {
    // Every other test points PORTHOLE_STATE_FILE at a temp path, so none of
    // them touches the real /run/porthole — which does not exist until
    // something privileged creates it. A dry run must still work there,
    // because `open --dry-run` needs no privileges. (`forward --dry-run` is
    // the one that does -- it reads Docker's chain itself -- which is why
    // this test names `open`.) Taking the state lock would try
    // to create that directory and fail.
    assert!(
        !is_root(),
        "this test is about a directory an unprivileged process cannot create, \
         so as root it would assert nothing. The suite is never run as root -- \
         porthole's own rule is that nothing here needs `sudo`."
    );
    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    stub_firewalld_and_ip(&bin);
    let mut command = porthole_command(&["open", "5173", "--dry-run", "--json"]);
    command
        .env_remove("PORTHOLE_STATE_FILE")
        .env("PATH", path_ahead_of(&bin));
    let out = run(command, None);
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
    assert!(
        !is_root(),
        "as above: as root there is no unwritable directory to test against, \
         and the suite is never run as root."
    );
    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    stub_firewalld_and_ip(&bin);
    let mut command = porthole_command(&["status", "--json"]);
    command
        .env_remove("PORTHOLE_STATE_FILE")
        .env("PATH", path_ahead_of(&bin));
    let out = run(command, None);
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
fn doctor_always_reports_a_docker_check_and_explains_it_where_docker_is() {
    // `check_docker` reads `/sys/class/net/docker0`, which no `PATH` stub can
    // answer for, so this is the one test in this file whose subject really
    // is the machine it runs on. It used to skip itself when that directory
    // was absent -- and libtest counts a skip as `ok`.
    //
    // Split instead. The half that holds everywhere is asserted everywhere:
    // the check is always present and is always `ok`, because Docker is a
    // warning and never a failure. The half that needs Docker is an extra
    // assertion on a machine that has it, not the whole test.
    let dir = TempDir::new().unwrap();
    let out = porthole(&["doctor", "--json"], &state_path(&dir));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let docker = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "Docker")
        .expect("a Docker check, on every machine");
    assert_eq!(
        docker["ok"], true,
        "Docker is a warning, never a failed check: {docker}"
    );

    if std::path::Path::new("/sys/class/net/docker0").exists() {
        // Docker publishes container ports below the firewall, so porthole
        // cannot close what it never opened, and the check has to say so.
        assert!(
            docker["detail"].as_str().unwrap().contains("0.0.0.0")
                || docker["detail"].as_str().unwrap().contains("publish"),
            "the Docker check must explain the consequence, got: {docker}"
        );
    } else {
        assert_eq!(
            docker["detail"], "not present",
            "and must say plainly that it found nothing, rather than warning \
             about a Docker this machine does not run: {docker}"
        );
    }
}

#[test]
fn doctor_says_the_helper_is_missing_when_it_is() {
    // The bus this doctor is pointed at is up and owns no helper name, so
    // this check must fail with the "not answering on the bus" verdict
    // rather than the "cannot reach a bus" one — and its remedy must name
    // both things that could be missing. Whether a helper is installed on
    // the machine running this makes no difference to which bus is asked.
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
    let mut command = porthole_command(&["doctor", "--json"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PATH", "/nonexistent-porthole-test-path");
    let out = run(command, None);
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

// --- saved devices, through the real binary -------------------------------
//
// `porthole_core::devices::resolve` has its own tests. What these cover is
// the layer above it: which branch `--to` lands in, and what `open` does
// with each -- none of which had a test at all.

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, so a --release binary reads the invoking user's own address book instead of this test's"
)]
fn open_towards_an_unknown_device_says_so_and_lists_what_exists() {
    let dir = TempDir::new().unwrap();
    let book = dir.path().join("devices.toml");
    write_book(
        &book,
        "[[device]]\nname = \"phone\"\nmac = \"bc:24:11:5e:1c:6e\"\n",
    );

    let out = porthole_with_devices(
        &["open", "5173", "--to", "tablet"],
        &state_path(&dir),
        &book,
    );

    // Invalid arguments, not "device unreachable": the name is wrong, not
    // the device absent.
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    let text = stderr(&out);
    assert!(text.contains("tablet"), "name the device asked for: {text}");
    assert!(text.contains("phone"), "and say what does exist: {text}");
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, so a --release binary reads the invoking user's own address book instead of this test's"
)]
fn open_towards_a_saved_device_that_is_absent_exits_device_unreachable() {
    // Resolution shells out to `ip -4 neigh show`. This used to `return` on
    // a machine without `ip` -- without even printing why, and libtest
    // counted it `ok`. The stub answers that read with an empty table, which
    // is the situation under test: a saved device nothing on this network
    // answers for.
    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    stub_firewalld_and_ip(&bin);
    let book = dir.path().join("devices.toml");
    // A MAC from the reserved documentation range, which will not be in any
    // real neighbour table either.
    write_book(
        &book,
        "[[device]]\nname = \"ghost\"\nmac = \"00:00:5e:00:53:01\"\n",
    );

    let mut command = porthole_command(&["open", "5173", "--to", "ghost"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PORTHOLE_DEVICES_FILE", &book)
        .env("PATH", path_ahead_of(&bin));
    let out = run(command, None);

    assert_eq!(code(&out), 6, "{}", stderr(&out));
    assert!(stderr(&out).contains("ghost"), "{}", stderr(&out));
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, so a --release binary reads the invoking user's own address book instead of this test's"
)]
fn a_to_that_looks_like_a_failed_network_keeps_the_network_error() {
    let dir = TempDir::new().unwrap();
    let book = dir.path().join("devices.toml");
    write_book(&book, "");

    // An IPv6 address must be answered as IPv6-unsupported, never as "no
    // such device" -- the distinction `cli::parse_to` exists to keep.
    let out = porthole_with_devices(
        &["open", "5173", "--to", "fe80::1"],
        &state_path(&dir),
        &book,
    );
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    let text = stderr(&out).to_lowercase();
    assert!(text.contains("ipv6"), "got: {text}");
    assert!(
        !text.contains("saved device"),
        "must not be reported as a device lookup: {text}"
    );
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, so a --release binary reads the invoking user's own address book instead of this test's"
)]
fn a_bad_duration_is_refused_before_a_device_is_resolved() {
    // Resolution shells out; `--for 999h` is refusable without doing that.
    // What this pins is the ordering: the duration error, not a device one.
    let dir = TempDir::new().unwrap();
    let book = dir.path().join("devices.toml");
    write_book(
        &book,
        "[[device]]\nname = \"ghost\"\nmac = \"00:00:5e:00:53:01\"\n",
    );

    let out = porthole_with_devices(
        &["open", "5173", "--to", "ghost", "--for", "999h"],
        &state_path(&dir),
        &book,
    );

    assert_eq!(code(&out), 2, "{}", stderr(&out));
    let text = stderr(&out);
    assert!(
        !text.contains("not on this network"),
        "the device must never have been resolved: {text}"
    );
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, so a --release binary reads the invoking user's own address book instead of this test's"
)]
fn a_hand_edited_book_with_an_unusable_name_fails_naming_it() {
    let dir = TempDir::new().unwrap();
    let book = dir.path().join("devices.toml");
    write_book(
        &book,
        "[[device]]\nname = \"office:pc\"\nmac = \"bc:24:11:5e:1c:6e\"\n",
    );

    // `devices list` is enough to reach `Book::load`.
    let out = porthole_with_devices(&["devices", "list"], &state_path(&dir), &book);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("office:pc"), "{}", stderr(&out));
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, so a --release binary reads the invoking user's own address book instead of this test's"
)]
fn devices_rm_honours_json_and_reports_what_it_forgot() {
    let dir = TempDir::new().unwrap();
    let book = dir.path().join("devices.toml");
    write_book(
        &book,
        "[[device]]\nname = \"phone\"\nmac = \"bc:24:11:5e:1c:6e\"\n",
    );

    let out = porthole_with_devices(
        &["--json", "devices", "rm", "phone"],
        &state_path(&dir),
        &book,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let json: serde_json::Value =
        serde_json::from_str(&stdout(&out)).unwrap_or_else(|e| panic!("{e}: {}", stdout(&out)));
    assert_eq!(json["schema"], 1);
    assert_eq!(json["action"], "forgotten");
    assert_eq!(json["device"]["name"], "phone");

    // And it really is gone.
    let out = porthole_with_devices(&["--json", "devices", "list"], &state_path(&dir), &book);
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json["devices"].as_array().unwrap().len(), 0);
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, and this test runs `devices rm`: against the invoking user's own address book that is a delete, not a no-op"
)]
fn devices_rm_of_something_that_is_not_there_fails_rather_than_reporting_success() {
    let dir = TempDir::new().unwrap();
    let book = dir.path().join("devices.toml");
    write_book(&book, "");

    let out = porthole_with_devices(&["devices", "rm", "phone"], &state_path(&dir), &book);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("phone"), "{}", stderr(&out));
}

/// `devices add` refuses an empty neighbour table, and that refusal has to
/// honour `--json` like every other one: `docs/json-schema.md` promises the
/// object on stdout for *every* failure, and this path used to exit non-zero
/// with stdout empty and prose on stderr.
///
/// Driven with a stub `ip` on `PATH` rather than by waiting for a quiet
/// network: `net::neighbours` runs `ip -4 neigh show`, so an `ip` that
/// prints nothing and succeeds is exactly an empty table, deterministically
/// and without touching this machine's own. `devices add` reads its book and
/// asks `ip` before it prompts for anything, so nothing here needs stdin.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, so a --release binary reads the invoking user's own address book instead of this test's"
)]
fn devices_add_with_nothing_to_offer_honours_json_and_exits_nine() {
    let dir = TempDir::new().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let ip = bin.join("ip");
    std::fs::write(&ip, "#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&ip, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let book = dir.path().join("devices.toml");
    write_book(&book, "");

    let mut command = porthole_command(&["--json", "devices", "add"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PORTHOLE_DEVICES_FILE", &book)
        .env("PATH", &bin);
    let out = run(command, None);

    assert_eq!(code(&out), 9, "{}", stderr(&out));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out))
        .unwrap_or_else(|e| panic!("stdout must be the error object, got {e}: {}", stdout(&out)));
    assert_eq!(json["schema"], 1);
    assert_eq!(json["error"]["code"], 9);
    assert_eq!(json["error"]["kind"], "nothing_to_offer");
    assert!(
        json["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("nothing seen on this network"),
        "{}",
        stdout(&out)
    );
}

/// The same refusal without `--json`: the message still goes to stderr, and
/// the exit code is the specific one rather than 1, which the README
/// documents as "unexpected failure" and this is not.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, so a --release binary reads the invoking user's own address book instead of this test's"
)]
fn devices_add_with_nothing_to_offer_is_not_reported_as_an_unexpected_failure() {
    let dir = TempDir::new().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let ip = bin.join("ip");
    std::fs::write(&ip, "#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&ip, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let book = dir.path().join("devices.toml");
    write_book(&book, "");

    let mut command = porthole_command(&["devices", "add"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PORTHOLE_DEVICES_FILE", &book)
        .env("PATH", &bin);
    let out = run(command, None);

    assert_eq!(code(&out), 9, "{}", stderr(&out));
    assert!(stdout(&out).is_empty(), "got: {}", stdout(&out));
    assert!(
        stderr(&out).contains("nothing seen on this network"),
        "{}",
        stderr(&out)
    );
}

/// Puts an executable `name` in `bin`, running `body`.
fn stub(bin: &Path, name: &str, body: &str) {
    let path = bin.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A directory of this test's own, for stubs, inside its `TempDir`.
fn bin_dir(dir: &TempDir) -> PathBuf {
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).expect("the temp dir is writable");
    bin
}

/// A `firewall-cmd` and an `ip` that answer the reads porthole makes of
/// them, so a test that needs a firewall does not need *this machine* to
/// have one.
///
/// # Why every test that needs a firewall stubs one
///
/// These tests used to open with
///
/// ```ignore
/// if !have("firewall-cmd") || !have("ip") {
///     eprintln!("skipped: needs firewall-cmd and ip");
///     return;
/// }
/// ```
///
/// which libtest counts as `ok`. `tests/container.rs`'s own
/// `require_environment!` documents that exact construct as the defect it
/// exists to remove -- and this file kept producing new instances of it, in
/// the same branch, including the whole of the host-level `--as` coverage
/// and the coverage of a Critical fixed on the way. On any machine without
/// firewalld -- which is every ufw and nftables machine `docs/backends.md`
/// is written for, and every CI runner without it -- twelve tests here
/// reported success having executed nothing.
///
/// The cure is not to fail loudly instead: a suite that goes red on a ufw
/// laptop is a different way of not being run. It is to stop needing the
/// machine to have a firewall. Every command porthole issues to these two
/// programs is a *read* of a handful of fixed shapes, and the answers below
/// are the ones `porthole-core`'s own unit fixtures use, so what these tests
/// assert -- the rule porthole composes, the exit code it leaves, the JSON
/// it prints -- is decided by porthole either way.
///
/// What this does not test is `backend::detect` against a real firewalld.
/// That was never what these tests were for, and it has a home of its own:
/// `tests/container.rs` runs the real binary against a real firewalld, a
/// real ufw and a real nftables, and fails rather than skips when it cannot.
fn stub_firewalld_and_ip(bin: &Path) {
    // `--version` and `--state` are `Firewalld::health`; `--get-default-zone`
    // is `managed_zone`; `--list-rich-rules` is the read-back
    // `add_rich_rule` makes around its own write. Nothing else is read, and
    // an unrecognised argument exits non-zero rather than answering, so a
    // read this stub has not been taught about surfaces as a failure instead
    // of as an empty string.
    stub(
        bin,
        "firewall-cmd",
        "for arg in \"$@\"; do\n\
         case \"$arg\" in\n\
         --version) echo '2.4.4'; exit 0 ;;\n\
         --state) echo 'running'; exit 0 ;;\n\
         --get-default-zone) echo 'FedoraWorkstation'; exit 0 ;;\n\
         --list-rich-rules) exit 0 ;;\n\
         esac\n\
         done\n\
         echo \"cli-test stub firewall-cmd: unhandled $*\" >&2\n\
         exit 2",
    );
    // The two reads `net::current_network` makes, and the one
    // `net::present_networks` makes, answering with the same 10.10.10.119/24
    // `porthole-core`'s own `ROUTE_JSON`/`ADDR_JSON` fixtures use.
    stub(
        bin,
        "ip",
        "case \"$*\" in\n\
         *'route show default'*)\n\
         echo '[{\"dst\":\"default\",\"dev\":\"wlo1\",\"metric\":600}]' ;;\n\
         *'addr show'*)\n\
         echo '[{\"ifindex\":2,\"ifname\":\"wlo1\",\"addr_info\":[{\"family\":\"inet\",\
         \"local\":\"10.10.10.119\",\"prefixlen\":24,\"scope\":\"global\"}]}]' ;;\n\
         *'neigh show'*) : ;;\n\
         *) echo \"cli-test stub ip: unhandled $*\" >&2; exit 2 ;;\n\
         esac",
    );
}

/// `porthole` with a stub firewall and network ahead of everything on
/// `PATH`, and its state file in this test's own directory.
fn porthole_with_a_firewall(args: &[&str], state: &Path, bin: &Path) -> Output {
    stub_firewalld_and_ip(bin);
    let mut command = porthole_command(args);
    command
        .env("PORTHOLE_STATE_FILE", state)
        .env("PATH", path_ahead_of(bin));
    run(command, None)
}

/// The whole picker, end to end, on the table that produced both defects:
/// two Docker containers on a user-created bridge and two real devices on
/// wifi.
///
/// Driven by stub `ip` and `getent` on `PATH`, for the reason the
/// nothing-to-offer tests above give: a real neighbour table and a real
/// resolver are neither deterministic nor this machine's to depend on. The
/// stub `getent` answers for one address and not the other, so both halves
/// of "show a name where one can be found" are exercised in one run.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_DEVICES_FILE is honoured in debug builds only, and this test saves a device: a --release binary writes to the invoking user's own address book"
)]
fn the_picker_hides_containers_and_shows_a_name_where_the_resolver_has_one() {
    let dir = TempDir::new().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    // `PATH` is this directory alone, so every stub uses shell builtins
    // only: nothing else is reachable, which is the point.
    stub(
        &bin,
        "ip",
        "echo '172.18.0.2 dev br-5b772196d2da lladdr 6a:df:71:ff:3c:e4 STALE'\n\
         echo '10.10.10.1 dev wlo1 lladdr 50:e6:36:51:42:fd REACHABLE'\n\
         echo '172.18.0.3 dev br-5b772196d2da lladdr 8e:3a:fc:5b:5c:dc STALE'\n\
         echo '10.10.10.245 dev wlo1 lladdr bc:24:11:5e:1c:6e REACHABLE'",
    );
    // Answers for the gateway and knows nothing about the phone -- exit 2
    // with nothing on stdout is what `getent hosts` really does for an
    // address it cannot find.
    stub(
        &bin,
        "getent",
        "case \"$2\" in\n\
         10.10.10.1) echo '10.10.10.1 router.example';;\n\
         *) exit 2;;\n\
         esac",
    );

    let book = dir.path().join("devices.toml");
    write_book(&book, "");

    let mut command = porthole_command(&["devices", "add"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PORTHOLE_DEVICES_FILE", &book)
        .env("PATH", &bin);
    // Pick row 1 and name it. Row 1 is the gateway only because the two
    // container rows are gone; before the filter it was `172.18.0.2`.
    let out = run(command, Some(b"1\nrouter\n"));
    let prompt = stderr(&out);

    assert_eq!(code(&out), 0, "{prompt}");
    assert!(
        !prompt.contains("br-5b772196d2da")
            && !prompt.contains("172.18.0.2")
            && !prompt.contains("6a:df:71:ff:3c:e4"),
        "a Docker container is not a device to open a firewall port towards: {prompt}"
    );
    assert!(
        prompt.contains("1) 50:e6:36:51:42:fd  10.10.10.1  (wlo1)  router.example"),
        "the row carries the name the resolver answered: {prompt}"
    );
    assert!(
        prompt.contains("2) bc:24:11:5e:1c:6e  10.10.10.245  (wlo1)\n"),
        "an address with no answer gets no name and no stand-in: {prompt}"
    );
    assert!(
        !prompt.contains("unknown") && !prompt.contains("Unknown"),
        "nothing is invented for a device the resolver had no answer for: {prompt}"
    );
    // The MAC is the identity, and it is what the save records -- the name
    // shown beside it is not stored and not matched.
    assert!(
        stdout(&out).contains("Saved `router` as 50:e6:36:51:42:fd"),
        "{}",
        stdout(&out)
    );
    let saved = std::fs::read_to_string(&book).unwrap();
    assert!(saved.contains("50:e6:36:51:42:fd"), "{saved}");
    assert!(
        !saved.contains("router.example"),
        "the resolver's answer must not reach the address book: {saved}"
    );
}

// ---------------------------------------------------------------------------
// `porthole forward`
// ---------------------------------------------------------------------------

/// A state file holding `rules`, written by hand.
///
/// `porthole list` reads the state file and touches nothing else, so a rule
/// can be put in front of it without a firewall, a helper, Docker or any
/// privileged process at all -- which is what lets the rendering of a
/// forward be asserted on every machine this suite runs on.
fn write_state(path: &Path, rules: &str) {
    refuse_a_release_build_the_state_file();
    std::fs::write(path, format!(r#"{{"schema_version":1,"rules":[{rules}]}}"#))
        .expect("the temp dir is writable");
}

/// A recorded ordinary open: no `forward` member at all, which is what every
/// rule written before forwards existed looks like on disk.
fn recorded_open() -> String {
    r#"{"id":"11111111-0000-4000-8000-000000000001","port":5173,"protocol":"tcp",
        "target":{"kind":"network","cidr":"10.10.10.0/24"},"backend":"firewalld",
        "opened_at":1757000000,"expires_at":9999999999,"uid":1000,
        "handle":{"backend":"firewalld","zone":"public","rich_rule":"permit"}}"#
        .to_string()
}

/// A recorded forward: 8443 on the network reaching a container's own
/// `172.17.0.9:80`, which Docker published on this machine as 3000.
fn recorded_forward() -> String {
    r#"{"id":"11111111-0000-4000-8000-000000000002","port":8443,"protocol":"tcp",
        "target":{"kind":"network","cidr":"10.10.10.0/24"},"backend":"firewalld",
        "opened_at":1757000000,"expires_at":9999999999,"uid":1000,
        "handle":{"backend":"firewalld","zone":"public","rich_rule":"redirect"},
        "forward":{"container_addr":"172.17.0.9","container_port":80,
                   "published_port":3000,"protocol":"tcp"}}"#
        .to_string()
}

/// A `PATH` with `bin` in front of the one [`porthole_command`] sets, so a
/// stub can shadow one program without losing the `firewall-cmd` shim that
/// keeps firewalld off the private bus.
fn path_ahead_of(bin: &Path) -> OsString {
    let mut path = OsString::from(bin);
    path.push(":");
    path.push(&isolation().path);
    path
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_STATE_FILE is honoured in debug builds only, so a --release binary reads /run/porthole/state.json instead of this test's"
)]
fn a_forwards_row_says_both_ports_and_where_it_goes() {
    // The defect this exists against: a forward rendered as an open tells a
    // user the port permits traffic when it redirects it, and says nothing
    // about which port the traffic actually reaches.
    let dir = TempDir::new().unwrap();
    let path = state_path(&dir);
    write_state(
        &path,
        &format!("{},{}", recorded_open(), recorded_forward()),
    );

    let out = porthole(&["list"], &path);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let text = stdout(&out);

    let row = text
        .lines()
        .find(|l| l.starts_with("8443/tcp"))
        .unwrap_or_else(|| panic!("no row for the forward: {text}"));
    assert!(
        row.contains("172.17.0.9:80"),
        "the row must say where the traffic actually goes: {text}"
    );
    assert!(
        row.contains("3000"),
        "the row must name the published port the user knows this service by: {text}"
    );

    // The ordinary open is still an ordinary open, and says nothing about a
    // container.
    let open = text
        .lines()
        .find(|l| l.starts_with("5173/tcp"))
        .unwrap_or_else(|| panic!("no row for the open: {text}"));
    assert!(
        !open.contains("172.17.0.9"),
        "an open redirects nothing: {text}"
    );
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "PORTHOLE_STATE_FILE is honoured in debug builds only, so a --release binary reads /run/porthole/state.json instead of this test's"
)]
fn list_json_carries_a_forward_and_says_nothing_for_an_open() {
    let dir = TempDir::new().unwrap();
    let path = state_path(&dir);
    write_state(
        &path,
        &format!("{},{}", recorded_open(), recorded_forward()),
    );

    let out = porthole(&["list", "--json"], &path);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let rules = json["rules"].as_array().expect("an array");

    let open = rules.iter().find(|r| r["port"] == 5173).expect("the open");
    assert_eq!(
        open["forward"],
        serde_json::Value::Null,
        "a rule that only permits carries no forward"
    );

    let fwd = rules
        .iter()
        .find(|r| r["port"] == 8443)
        .expect("the forward");
    assert_eq!(fwd["forward"]["container_addr"], "172.17.0.9");
    assert_eq!(fwd["forward"]["container_port"], 80);
    assert_eq!(fwd["forward"]["published_port"], 3000);
}

#[test]
fn forward_defaults_the_external_port_to_the_published_one() {
    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    stub_firewalld_and_ip(&bin);
    // Docker's own DNAT rules, as `porthole_core::docker::published` reads
    // them. A stub because this machine's real chain needs root to read and
    // is nobody's to depend on; published on loopback because that is the
    // only shape a forward is for.
    stub(
        &bin,
        "iptables",
        "echo '-N DOCKER'\n\
         echo '-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 34567 \
         -j DNAT --to-destination 172.17.0.9:80'",
    );

    let mut command = porthole_command(&["forward", "34567", "--dry-run", "--json"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PATH", path_ahead_of(&bin));
    let out = run(command, None);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(
        json["rule"]["port"], 34567,
        "with no --as, the local network sees the published port"
    );
    assert_eq!(json["rule"]["forward"]["published_port"], 34567);
    assert_eq!(json["rule"]["forward"]["container_addr"], "172.17.0.9");
    assert_eq!(json["rule"]["forward"]["container_port"], 80);
}

#[test]
fn forward_takes_a_different_external_port() {
    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    stub_firewalld_and_ip(&bin);
    stub(
        &bin,
        "iptables",
        "echo '-N DOCKER'\n\
         echo '-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 34567 \
         -j DNAT --to-destination 172.17.0.9:80'",
    );

    let mut command =
        porthole_command(&["forward", "34567", "--as", "34568", "--dry-run", "--json"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PATH", path_ahead_of(&bin));
    let out = run(command, None);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(
        json["rule"]["port"], 34568,
        "--as is what the local network sees"
    );
    assert_eq!(
        json["rule"]["forward"]["published_port"], 34567,
        "the number typed is the port `porthole listen` shows"
    );
}

#[test]
fn a_forward_out_of_range_is_refused_before_anything_is_asked() {
    let dir = TempDir::new().unwrap();
    for args in [
        vec!["forward", "99999"],
        vec!["forward", "3000", "--as", "99999"],
    ] {
        let out = porthole(&args, &state_path(&dir));
        assert_eq!(code(&out), 2, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("1-65535"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn a_forward_uses_opens_own_duration_ceiling_and_scope_grammar() {
    let dir = TempDir::new().unwrap();

    let out = porthole(&["forward", "3000", "--for", "24h"], &state_path(&dir));
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("8 hours"), "got: {}", stderr(&out));

    let out = porthole(&["forward", "3000", "--to", "fe80::1"], &state_path(&dir));
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(
        stderr(&out).to_lowercase().contains("ipv6"),
        "got: {}",
        stderr(&out)
    );
}

#[test]
fn forwarding_without_a_helper_says_the_helper_is_missing() {
    // A real request, on the private bus this file starts -- see the module
    // doc. Nothing owns the helper's name there, so this is what a machine
    // without porthole installed answers: no usable backend (3), not "not
    // authorized" (4).
    let dir = TempDir::new().unwrap();
    let out = porthole(&["forward", "3000"], &state_path(&dir));
    assert_eq!(code(&out), 3, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("doctor"), "got: {}", stderr(&out));
}

/// Every refusal `forward` can reach from this command line, with the exit
/// code and the `kind` slug a script reads.
///
/// The point is not the refusals themselves -- they belong to
/// `Engine::forward`, which has its own tests for each -- but that each one
/// arrives at the process boundary as its own number. All of them used to
/// come out as exit 1 and `"unexpected"`, and a table of exit codes nothing
/// emits is worse than no table.
///
/// Driven by a stub `iptables`, so what Docker "publishes" is whatever the
/// case says and this machine's own containers are neither read nor touched.
#[test]
fn each_refusal_a_forward_can_reach_has_its_own_exit_code() {
    let published_on_loopback = "echo '-N DOCKER'\n\
         echo '-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 34567 \
         -j DNAT --to-destination 172.17.0.9:80'";

    let cases: [(&str, &str, i64, &str); 3] = [
        // Docker answered, no container publishes the port, and nothing on
        // this machine is on it either -- the narrower of the two answers
        // that share exit 10. Its counterpart, a port something *is* on, is
        // driven below by a listener this test binds itself, because it is
        // the only one of the pair that cannot be arranged with a stub.
        ("nothing on it", "echo '-N DOCKER'", 10, "nothing_listening"),
        // Docker could not be asked at all -- the same exit code as above and
        // a different kind, which is the only thing that tells them apart.
        (
            "unreadable",
            "echo 'iptables: Permission denied' >&2\nexit 2",
            10,
            "docker_unreadable",
        ),
        // Published on every interface: already reachable, and porthole
        // cannot close what Docker opened.
        (
            "reachable",
            "echo '-N DOCKER'\n\
             echo '-A DOCKER ! -i docker0 -p tcp -m tcp --dport 34567 \
             -j DNAT --to-destination 172.17.0.9:80'",
            14,
            "already_reachable",
        ),
    ];

    for (name, chain, expected_code, expected_kind) in cases {
        let dir = TempDir::new().unwrap();
        let bin = bin_dir(&dir);
        stub_firewalld_and_ip(&bin);
        stub(&bin, "iptables", chain);

        let mut command = porthole_command(&["forward", "34567", "--dry-run", "--json"]);
        command
            .env("PORTHOLE_STATE_FILE", state_path(&dir))
            .env("PATH", path_ahead_of(&bin));
        let out = run(command, None);

        assert_eq!(
            code(&out) as i64,
            expected_code,
            "{name}: stdout {} stderr {}",
            stdout(&out),
            stderr(&out)
        );
        let json: serde_json::Value =
            serde_json::from_str(&stdout(&out)).expect("the failure object is on stdout");
        assert_eq!(json["error"]["code"], expected_code, "{name}");
        assert_eq!(json["error"]["kind"], expected_kind, "{name}");
    }

    // The other half of exit 10, and it needs a real socket: a port nothing
    // publishes but something is listening on. The refusal is the same `no`
    // as the "nothing on it" case above, and the two used to arrive with one
    // message and one slug -- so a person told to check the number was told
    // it about a port they could see was in use, and a person whose service
    // simply was not running was told to stop trying.
    //
    // Bound on loopback deliberately: that is the shape that matters here
    // (`631` on the machine this was reported from), and it is also the one
    // the external-port check further down does *not* refuse, so a pass here
    // cannot be the external-port refusal wearing this one's number.
    let mine = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let held = mine.local_addr().unwrap().port().to_string();

    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    stub_firewalld_and_ip(&bin);
    stub(&bin, "iptables", "echo '-N DOCKER'");
    let mut command = porthole_command(&["forward", &held, "--dry-run", "--json"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PATH", path_ahead_of(&bin));
    let out = run(command, None);

    assert_eq!(code(&out), 10, "stderr: {}", stderr(&out));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(
        json["error"]["kind"],
        "not_published_by_container",
        "a port something is listening on is not a port nothing is on: {}",
        stdout(&out)
    );
    let message = json["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains(&held),
        "the refusal must name the port it is about: {message}"
    );
    assert!(
        !message.contains("nothing on this machine is listening"),
        "and must not say the port is idle while this test holds a socket on it: {message}"
    );

    // The external port already carries something the redirect would take
    // traffic from. A real listener of this test's own, on `0.0.0.0` --
    // which is the binding that makes the refusal right, and the one thing
    // this case has to control. It is bound and never accepted on, for as
    // long as one `--dry-run` takes.
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("a port on every interface");
    let taken = listener.local_addr().unwrap().port().to_string();

    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    stub_firewalld_and_ip(&bin);
    stub(&bin, "iptables", published_on_loopback);
    let mut command =
        porthole_command(&["forward", "34567", "--as", &taken, "--dry-run", "--json"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PATH", path_ahead_of(&bin));
    let out = run(command, None);

    assert_eq!(code(&out), 11, "stderr: {}", stderr(&out));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json["error"]["kind"], "external_port_in_use");
    let message = json["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains(&taken),
        "the refusal must name the port it is about: {}",
        stdout(&out)
    );
    assert!(
        message.contains("--as"),
        "and, since the same refusal fires on `forward <PORT>` with no `--as`, \
         say what to do about it: {}",
        stdout(&out)
    );
}

/// `porthole forward <PORT>` with no `--as`, against a container published on
/// `127.0.0.1` with something already listening there -- which is every
/// container this command exists for, on a default Docker install, because
/// Docker's userland proxy is on by default and holds
/// `127.0.0.1:<published>` itself.
///
/// This form returned exit 11 (`external_port_in_use`) until the check that
/// decides it started reading where a listener is bound. `forward <PORT>
/// --as <other>` was unaffected and passed throughout, which is why no test
/// here saw it: every other forward case either stubs an unlistened port or
/// passes `--as`.
#[test]
fn a_loopback_listener_on_the_published_port_does_not_refuse_the_ordinary_forward() {
    // Bound first, so the number is one nothing else on this machine can
    // take, and held for the whole run: this stands in for `docker-proxy`.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let port = listener.local_addr().unwrap().port();

    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    stub_firewalld_and_ip(&bin);
    stub(
        &bin,
        "iptables",
        &format!(
            "echo '-N DOCKER'\n\
             echo '-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport {port} \
             -j DNAT --to-destination 172.17.0.9:80'"
        ),
    );

    let number = port.to_string();
    let mut command = porthole_command(&["forward", &number, "--dry-run", "--json"]);
    command
        .env("PORTHOLE_STATE_FILE", state_path(&dir))
        .env("PATH", path_ahead_of(&bin));
    let out = run(command, None);

    assert_eq!(
        code(&out),
        0,
        "the ordinary form must not be refused: stdout {} stderr {}",
        stdout(&out),
        stderr(&out)
    );
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(
        json["rule"]["port"],
        port,
        "and the rule is the one that was asked for: {}",
        stdout(&out)
    );
    assert_eq!(
        json["rule"]["forward"]["container_port"],
        80,
        "towards the container the stub published: {}",
        stdout(&out)
    );
}

/// Which of `forward`'s two port numbers is which, read off `--help` the way
/// a person does: from the description printed under each one.
///
/// The name used to be the whole of the claim. `text.contains("--as")` and
/// four friends passed with the two descriptions swapped -- help that told a
/// user the positional port was the one the local network would see, which is
/// the single thing this command's surface has to get right. So each
/// description is now looked up under the argument it belongs to, and the two
/// are asserted apart.
#[test]
fn forward_help_says_which_number_is_which() {
    let dir = TempDir::new().unwrap();
    let out = porthole(&["forward", "--help"], &state_path(&dir));
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let text = stdout(&out);

    // clap's long help puts each argument on its own line and its
    // description on the next non-blank one.
    let described = |argument: &str| -> String {
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.trim() == argument)
            .unwrap_or_else(|| panic!("`{argument}` is not an argument line in: {text}"));
        lines[at + 1..]
            .iter()
            .find(|l| !l.trim().is_empty())
            .unwrap_or_else(|| panic!("nothing is said about `{argument}` in: {text}"))
            .trim()
            .to_string()
    };

    let positional = described("<PORT>");
    let as_port = described("--as <PORT>");

    assert!(
        positional.contains("Docker published") && positional.contains("porthole listen"),
        "the positional port is the one already on this machine: {positional}"
    );
    assert!(
        !positional.contains("local network"),
        "and it is not the one the local network sees: {positional}"
    );
    assert!(
        as_port.contains("local network"),
        "`--as` is the port the local network connects to: {as_port}"
    );
    assert!(
        !as_port.contains("Docker published"),
        "and not the one Docker published: {as_port}"
    );

    for expected in ["--to", "--for"] {
        assert!(text.contains(expected), "`{expected}` missing from: {text}");
    }

    // Why there is no `--proto` was written down in a Rust doc comment on
    // `ForwardArgs`, which clap never renders: the question a user asks after
    // `forward --proto udp` is refused had no answer anywhere they would look.
    assert!(
        text.contains("--proto") && text.contains("TCP"),
        "`--help` must say why there is no protocol to choose: {text}"
    );
}
