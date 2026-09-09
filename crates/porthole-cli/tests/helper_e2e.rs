//! The milestone's headline claim, end to end: `porthole open` with no `sudo`
//! anywhere.
//!
//! A real `porthole-helper` runs as a child process on a session bus of this
//! test binary's own ([`private_bus`]) and the real `porthole` binary drives
//! it. What this proves and what it cannot is written out in each test.
//!
//! # What this file asks of the firewall on the machine running it
//!
//! Nothing at all, and that is enforced rather than hoped for: every helper
//! and every CLI this file starts is given a `PATH` with [`stub_firewalld`]'s
//! own `firewall-cmd` and `ip` in front of it, so the firewall these
//! processes detect is one this file wrote and the machine's own is never
//! reached. `backend::detect`'s two reads, `managed_zone`'s zone lookup and
//! the start-up sweep's rich-rule listing all end in that stub.
//!
//! That is a change of kind, not of degree. It used to read the real
//! machine's firewall, which made two things true that are no longer:
//!
//! - The start-up sweep (`reconcile_at_startup` in `porthole-helper`'s
//!   `main.rs`) runs for *every* test below, before the bus is served and
//!   with this suite's `--session` `AlwaysAllow` nowhere in the path. On ufw
//!   or nftables that sweep can prove ownership and does remove an orphan it
//!   finds, straight through `ufw`/`nft`; the only thing between it and a
//!   real rule was the OS's own root check. `start_helper` used to refuse to
//!   start at all when this process was genuinely root and `detect` found one
//!   of those two -- and refusing meant `return`ing out of the test, which
//!   libtest counts as `ok`. Now the helper cannot reach ufw or nftables:
//!   the stub answers as firewalld, whose `Ownership::Unprovable` skips the
//!   orphan direction outright on every account, privileged or not. The
//!   hazard is gone structurally, so the guard that reported success in its
//!   name is gone too.
//! - `the_helper_reconciles_at_startup_with_no_client_request_at_all` needed
//!   the machine to have a firewall whose rule list this process could read.
//!   Measured in a Fedora build chroot: with no `firewall-cmd` the sweep
//!   cannot know whether the seeded rule exists, correctly refuses to prune
//!   it, and the test failed; with firewalld installed but no daemon running
//!   -- which is every build chroot, mock's and COPR's included -- the
//!   listing fails and it failed the same way. A stub removes the question.
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
//! # What this file asks of the session bus on the machine running it
//!
//! Nothing at all either, for the same reason and by the same means: it
//! starts a private `dbus-run-session` daemon of its own and every process
//! below is pointed at it. See [`private_bus`] for the failure that came of
//! not doing so.
//!
//! # Nothing here skips itself
//!
//! `start_helper` used to hand back one of four failures and the caller
//! printed `skipped: ...` and returned, which libtest counts as `ok` -- the
//! same defect `tests/cli.rs`'s module doc records twelve instances of. Three
//! of the four are now assertions: a helper that exits, a helper that never
//! reaches the bus, and (see above) the sweep guard that no longer has
//! anything to guard. The fourth is a compile-time fact rather than a runtime
//! one -- `porthole-helper --session` exists only in a debug build -- so it
//! is `#[cfg_attr(not(debug_assertions), ignore = ...)]` on each test, and a
//! `cargo test --release` reports these as `ignored`, by name.
//!
//! As **genuinely root** these tests cannot run at all, and now say so
//! instead of passing: `porthole_core::cli_path::resolve_cli` offers a root
//! helper only `/usr/bin/porthole` and `/usr/local/bin/porthole`, never the
//! CLI built beside it, so in a build chroot with porthole not yet installed
//! the helper exits before serving and the assertion carries its stderr. The
//! RPM's `%check` refuses to run as root for this reason -- see
//! `packaging/rpm/porthole.spec`.

use std::io::BufRead as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use tempfile::TempDir;

/// The one session bus every process this file starts is pointed at, and the
/// only bus any of them can reach.
///
/// `porthole-helper --session` claims [`porthole_core::ipc::SERVICE`], and
/// that string is *also* the GTK application id of `porthole-gui`. On the
/// ambient session bus of a developer who happens to have the GUI open the
/// name is therefore already taken, the helper exits with `NameTaken` before
/// it ever serves, and four of the five tests below fail. Measured on the
/// machine this was found on, with a GUI running:
///
/// ```text
/// $ busctl --user list | grep jacopobriccola
/// com.jacopobriccola.Porthole       1634084 porthole-gui
/// com.jacopobriccola.PortholeAgent  1629505 porthole-agent
/// ```
///
/// Nothing about that is a product defect — users never run two owners of the
/// name — but it makes this file pass or fail on whether a window is open,
/// which is not a property of the code under test. So this file does what
/// `tests/cli.rs`'s `isolation` does, for the same reason and by the same
/// means: one private `dbus-run-session` daemon per test binary, whose
/// address every helper, every CLI and the readiness probe are given.
///
/// The name is free on that daemon on every machine, GUI or no GUI: porthole
/// installs a *system*-bus activation file and no session one, so a private
/// session daemon reading the same `XDG_DATA_DIRS` has nothing porthole-shaped
/// to activate. Verified by hand under `dbus-run-session`: `busctl --user
/// list` there names 94 services and not one of them matches `jacopobriccola`,
/// against 251 on the ambient bus of the machine above.
///
/// One thing `cli.rs` needs that this file does not: a `PATH` shim keeping the
/// real `firewall-cmd` off the redirected system bus. Here `firewall-cmd` is
/// already [`stub_firewalld`]'s `/bin/sh` script, which speaks to no bus at
/// all.
struct PrivateBus {
    /// `dbus-run-session`, alive for as long as the pipe its inner shell
    /// reads stays open. This process exiting closes that pipe, the shell
    /// exits, and the daemon goes down with it — so nothing is left behind
    /// even though this value is never dropped.
    _daemon: Child,
    address: String,
}

fn private_bus() -> &'static PrivateBus {
    static BUS: OnceLock<PrivateBus> = OnceLock::new();
    BUS.get_or_init(|| {
        // Asserted, not skipped. A test that cannot get its own bus must fail
        // rather than quietly run against this machine's — which is the whole
        // of what this function exists to stop.
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
        PrivateBus {
            _daemon: daemon,
            address,
        }
    })
}

/// Points `command` at [`private_bus`], and at nothing else.
///
/// `DBUS_SYSTEM_BUS_ADDRESS` as well as the session one, though everything
/// here is started with `--session` and so should never open the system bus:
/// the machine running this may be a developer's own, where the *real*
/// `porthole-helper` is on the real system bus behind a polkit prompt, and
/// `cli.rs`'s module docs record what a test that reached it once cost. A
/// process that ignores `--session`, or a future path that opens the system
/// bus regardless, must find no helper rather than find that one.
fn on_private_bus(command: &mut Command) -> &mut Command {
    let bus = private_bus();
    command
        .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
        .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.address)
        .env_remove("DBUS_STARTER_ADDRESS")
        .env_remove("DBUS_STARTER_BUS_TYPE")
}

/// Kills the helper however the test ends, including on a failed assertion.
struct Helper(Child);

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Every test below spawns a helper claiming the *same* well-known name on
/// the *same* bus — [`private_bus`] is one daemon shared by the whole test
/// binary, exactly as `cli.rs`'s is — and `cargo test` runs the `#[test]`
/// functions in one process on separate threads by default. Two helpers
/// racing for that
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

/// The zone the stub `firewall-cmd` answers with. Named here rather than
/// read off the machine: `default_zone()` used to run a real
/// `firewall-cmd --get-default-zone` so the seeded handle below would name a
/// zone that exists on *this* developer's laptop, and answered with an empty
/// string wherever firewalld was absent or stopped.
const STUB_ZONE: &str = "FedoraWorkstation";

/// A `#!/bin/sh` stub named `name`, executable, in `dir`.
fn stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("the temp dir is writable");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the stub can be made executable");
}

/// A directory of this test's own, for stubs, inside its `TempDir`.
fn bin_dir(dir: &TempDir) -> std::path::PathBuf {
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).expect("the temp dir is writable");
    stub_firewalld(&bin);
    bin
}

/// A `firewall-cmd` and an `ip` that answer the reads the helper and the CLI
/// make of them, with the same fixtures `tests/cli.rs`'s
/// `stub_firewalld_and_ip` and `porthole-core`'s own unit tests use.
///
/// `--version` and `--state` are `Firewalld::health`, which is what
/// `backend::detect` selects on; `--get-zone-of-interface=` falls through to
/// `--get-default-zone`, which is `managed_zone`; `--list-rich-rules` is what
/// the start-up sweep compares porthole's records against, and it is
/// deliberately empty. An argument this stub has not been taught about exits
/// non-zero rather than answering, so a read it does not know surfaces as a
/// failure instead of as an empty string -- and, more to the point here, a
/// *mutation* the helper should never have issued cannot be mistaken for
/// having worked.
fn stub_firewalld(bin: &Path) {
    stub(
        bin,
        "firewall-cmd",
        &format!(
            "for arg in \"$@\"; do\n\
             case \"$arg\" in\n\
             --version) echo '2.4.4'; exit 0 ;;\n\
             --state) echo 'running'; exit 0 ;;\n\
             --get-default-zone) echo '{STUB_ZONE}'; exit 0 ;;\n\
             --list-rich-rules) exit 0 ;;\n\
             esac\n\
             done\n\
             echo \"helper-e2e stub firewall-cmd: unhandled $*\" >&2\n\
             exit 2"
        ),
    );
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
         *) echo \"helper-e2e stub ip: unhandled $*\" >&2; exit 2 ;;\n\
         esac",
    );
}

/// `bin` ahead of the inherited `PATH`, so the stubs win and everything else
/// -- `busctl`, `systemd-run` -- is still reachable.
fn path_ahead_of(bin: &Path) -> std::ffi::OsString {
    let mut path = std::ffi::OsString::from(bin);
    if let Some(existing) = std::env::var_os("PATH") {
        path.push(":");
        path.push(existing);
    }
    path
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

/// Start `porthole-helper --session` on [`private_bus`], with `bin` ahead of
/// its `PATH`, and hand back a handle that kills it on drop.
///
/// Every way this can fail is an assertion, and each says which one it was
/// rather than hiding all of them behind one blanket "skipped" — which is
/// exactly how a missing `porthole` at `/usr/bin` and `/usr/local/bin` made
/// every test below silently pass while `cargo test` reported the suite `ok`.
/// `return`ing out of a test is counted by libtest as a pass; a helper that
/// will not start is a broken invocation, not a reason to report success.
///
/// The one condition that is not an assertion is `--session` being
/// debug-only: that is known at compile time, so each test carries
/// `#[cfg_attr(not(debug_assertions), ignore = ...)]` and a `--release` run
/// reports them as `ignored` by name rather than as a skip counted `ok`. A
/// test added here without that attribute does not slip through silently
/// either -- a release `porthole-helper` rejects `--session` outright, so it
/// exits before serving and the assertion below carries clap's own refusal.
fn start_helper(state: &Path, bin: &Path) -> Helper {
    // Asserted, not skipped: `return`ing here is counted by libtest as a
    // pass, and that is exactly how every test in this file once reported
    // success in half a second under `cargo test -p porthole-cli`, which
    // never builds a sibling package's binary. A missing helper is a broken
    // invocation, and the message says how to fix it.
    let helper = helper_bin();
    assert!(
        helper.exists(),
        "porthole-helper is not at {} — these tests need the whole workspace \
         built, e.g. `cargo test` rather than `cargo test -p porthole-cli`",
        helper.display()
    );

    let mut command = Command::new(&helper);
    // The bus this helper serves on, and the only one it can reach — which is
    // what keeps it off the name a developer's own `porthole-gui` may already
    // hold. See [`private_bus`].
    on_private_bus(&mut command)
        .arg("--session")
        .env("PORTHOLE_STATE_FILE", state)
        // The firewall this helper detects, and the only one it can reach.
        // See the module docs: this is what keeps its start-up sweep off the
        // machine's own firewall, and what lets the sweep answer at all in a
        // chroot with no firewalld daemon.
        .env("PATH", path_ahead_of(bin))
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .unwrap_or_else(|e| panic!("{} exists but would not run: {e}", helper.display()));
    let helper_pid = child.id();

    // Wait for the name to appear rather than sleeping a fixed time. A
    // transient `busctl` failure is not the helper's fault, so it retries
    // rather than bailing out via `?` — which, caught by `clippy::
    // zombie_processes`, used to return `None` here without ever killing
    // `child`, leaking a live `porthole-helper --session` process that
    // nothing would ever reap. Every exit from this function below either
    // hands `child` to `Helper` (whose `Drop` kills and waits it) or kills
    // and waits it here first.
    //
    // `--address=` rather than `--user`: `busctl --user` does honour
    // `DBUS_SESSION_BUS_ADDRESS` (verified by hand), but honouring it is a
    // fallback chain, and the end of that chain is the developer's own bus —
    // where a running `porthole-gui` owns the very name this loop waits for.
    // A probe that can be answered by the ambient bus is a probe that can
    // report success without the helper having started. `--address` has no
    // fallback: a bus it cannot reach is a connection error, not an answer.
    let address = format!("--address={}", private_bus().address);

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
            panic!(
                "the helper process exited before it started serving, so nothing \
                 below could have run — its stderr: {text}\n\
                 As genuinely root this is expected and is not a reason to report \
                 success: `porthole_core::cli_path::resolve_cli` offers a root \
                 helper only /usr/bin/porthole and /usr/local/bin/porthole, never \
                 the CLI built beside it. Run this suite as an ordinary user."
            );
        }

        let Ok(out) = Command::new("busctl")
            .args([address.as_str(), "list", "--no-legend"])
            .output()
        else {
            continue;
        };
        if listing_names_the_helper(&String::from_utf8_lossy(&out.stdout), helper_pid) {
            return Helper(child);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!(
        "the helper is still running but never appeared on {address} within \
         5s — the private bus this file started is not answering, or `busctl` \
         is unavailable. Both are broken invocations rather than reasons to \
         report success: systemd's `busctl` and `dbus-run-session` are what \
         this file needs installed."
    );
}

/// Does this `busctl list --no-legend` listing show the helper's own
/// well-known name, owned by process `pid`?
///
/// Each row is a name, space-padded, followed by the pid and the rest, so the
/// name is the row's first field and the pid its second, and both are
/// compared whole.
///
/// [`start_helper`] used to ask `listing.contains("com.jacopobriccola.Porthole")`
/// instead, and `com.jacopobriccola.PortholeAgent` contains that string. The
/// notification agent owns that name on the session bus of every machine
/// where porthole is installed and someone has logged in, so the probe was
/// answered by a service that implements none of the calls these tests go on
/// to make: it returned on its first pass, before the helper had claimed
/// anything at all. [`the_readiness_probe_is_not_satisfied_by_the_notification_agent`]
/// is that exact case, pinned. The agent is no longer on the bus this probe
/// reads — [`private_bus`] has neither agent nor GUI on it — so that is now a
/// guard rather than a live hazard, and it is kept because the cost of it
/// being wrong was every test in this file reporting success having proved
/// nothing.
///
/// `pid` is what closes the one race a *shared* private bus still leaves: the
/// tests are serialised ([`HELPER_LOCK`]) and each kills its helper on the way
/// out, but the row a `busctl` listing shows is the row the daemon has got
/// round to forgetting, not the row the kernel has. Waiting for the name is
/// not the same as waiting for *this* helper to own it; waiting for the name
/// beside this child's own pid is.
///
/// [`porthole_core::ipc::SERVICE`] rather than a literal, so this is the same
/// string the helper requests rather than a second copy of it.
fn listing_names_the_helper(listing: &str, pid: u32) -> bool {
    let pid = pid.to_string();
    listing.lines().any(|row| {
        let mut fields = row.split_whitespace();
        fields.next() == Some(porthole_core::ipc::SERVICE) && fields.next() == Some(pid.as_str())
    })
}

#[test]
fn the_readiness_probe_is_not_satisfied_by_the_notification_agent() {
    // Real `busctl --user list --no-legend` output from the machine this was
    // found on, with porthole-agent running and no helper anywhere.
    let agent_only = "\
:1.48                              5145 porthole-agent  jmbriccola :1.48 user@1000.service - -
com.jacopobriccola.PortholeAgent   5145 porthole-agent  jmbriccola :1.48 user@1000.service - -
";
    const HELPER_PID: u32 = 6001;

    assert!(
        agent_only.contains(porthole_core::ipc::SERVICE),
        "the agent's name contains the helper's, which is why a substring \
         check passed on it -- if this ever stops holding, the case below \
         stops being the one worth pinning"
    );
    assert!(
        !listing_names_the_helper(agent_only, HELPER_PID),
        "a probe waiting for the helper must not be satisfied by the agent"
    );

    // And it still says yes to the thing it is actually waiting for.
    let with_helper = format!(
        "{agent_only}{}   {HELPER_PID} porthole-helper jmbriccola :1.49 - - -\n",
        porthole_core::ipc::SERVICE
    );
    assert!(
        listing_names_the_helper(&with_helper, HELPER_PID),
        "the helper's own row must satisfy it: {with_helper}"
    );

    // The right name held by the wrong process is not this test's helper: on
    // the shared private bus that is the previous test's helper, killed but
    // not yet forgotten by the daemon, and returning on it would hand back a
    // child that owns nothing.
    assert!(
        !listing_names_the_helper(&with_helper, HELPER_PID + 1),
        "the name alone must not satisfy it -- the pid must be this helper's"
    );

    // A name is a whole field, never part of one: the unique-name rows above
    // carry `porthole-agent` in a later column, and a row for some future
    // `com.jacopobriccola.PortholeSomethingElse` must not count either --
    // not even when the pid beside it is the one being waited for.
    assert!(
        !listing_names_the_helper(
            "com.jacopobriccola.PortholeSomethingElse 7 x y :1.50 - - -\n",
            7
        ),
        "only the exact name counts"
    );
}

/// The CLI, on the same [`private_bus`] and with the same stub firewall on
/// its `PATH` as the helper it talks to — so the two find each other and
/// agree on which backend this machine has, and neither can reach the real
/// one of either kind.
fn cli(state: &Path, bin: &Path, args: &[&str]) -> std::process::Output {
    let mut all = vec!["--session"];
    all.extend_from_slice(args);
    let mut command = Command::new(env!("CARGO_BIN_EXE_porthole"));
    on_private_bus(&mut command)
        .args(all)
        .env("PORTHOLE_STATE_FILE", state)
        .env("PATH", path_ahead_of(bin));
    command.output().expect("the porthole binary runs")
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "porthole-helper --session is debug-only, so a --release build has no helper to drive"
)]
fn the_cli_reaches_the_helper_with_no_sudo_anywhere() {
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    let state = dir.path().join("state.json");
    let _helper = start_helper(&state, &bin);

    // list goes over the bus and answers. No sudo, no root, no prompt.
    let out = cli(&state, &bin, &["list", "--json"]);
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
#[cfg_attr(
    not(debug_assertions),
    ignore = "porthole-helper --session is debug-only, so a --release build has no helper to drive"
)]
fn the_helper_refuses_an_over_long_duration_itself() {
    // The CLI validates too, but this proves the *helper* does — a client that
    // skipped its own checks still cannot ask for nine hours.
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    let state = dir.path().join("state.json");
    let _helper = start_helper(&state, &bin);

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
                // Addressed, not `Connection::session()`: that reads this
                // *test process's* own `DBUS_SESSION_BUS_ADDRESS`, which is
                // the developer's ambient bus — every other process here is
                // redirected by its environment, but this one call is made
                // in-process, where there is no child environment to set.
                // Setting one for the whole test binary is not an option
                // either: `std::env::set_var` is unsound with other tests'
                // threads running.
                let conn = zbus::connection::Builder::address(private_bus().address.as_str())
                    .expect("the private bus address parses")
                    .build()
                    .await
                    .expect("the private session bus");
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
#[cfg_attr(
    not(debug_assertions),
    ignore = "porthole-helper --session is debug-only, so a --release build has no helper to drive"
)]
fn closing_something_that_is_not_open_round_trips_its_exit_code() {
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    let state = dir.path().join("state.json");
    let _helper = start_helper(&state, &bin);

    let out = cli(&state, &bin, &["close", "5173"]);
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
#[cfg_attr(
    not(debug_assertions),
    ignore = "porthole-helper --session is debug-only, so a --release build has no helper to drive"
)]
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
    // No sleep needed to give the sweep time to run: `start_helper` only
    // returns once the helper's name appears on the bus, which happens in
    // `main` strictly after the start-up sweep -- both run sequentially,
    // before the bus connection is even opened. By the time this test can
    // see the helper on the bus at all, the sweep has already finished.
    //
    // The zone is [`STUB_ZONE`] rather than whatever this machine's real
    // firewalld would answer, and that is the whole of what makes this test
    // portable: the sweep compares porthole's records against the backend's
    // own rule listing, so it needs a backend that *answers*, which is a
    // different thing from one being installed. Measured in a Fedora build
    // chroot: with `firewall-cmd` absent the sweep correctly refuses to prune
    // a record it cannot check, and with firewalld installed but no daemon
    // running the listing fails and it refuses just the same. Both are right,
    // and neither is this test's subject.
    let _guard = lock_helper();
    let dir = TempDir::new().unwrap();
    let bin = bin_dir(&dir);
    let state = dir.path().join("state.json");

    const RULE_ID: &str = "startup-phantom";
    const PORT: u16 = 25199;
    const CIDR: &str = "203.0.113.0/24"; // TEST-NET-3: never a real subnet.
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
            "handle": {"backend": "firewalld", "zone": STUB_ZONE, "rich_rule": rich_rule},
        }]
    });
    std::fs::write(&state, serde_json::to_string_pretty(&seeded).unwrap())
        .expect("seed the state file");

    let mut helper = start_helper(&state, &bin);
    let _ = helper.0.kill();
    let _ = helper.0.wait();

    let state_text = std::fs::read_to_string(&state).expect("the state file still exists");
    assert!(
        !state_text.contains(RULE_ID),
        "start-up reconciliation must prune a phantom entry even with no \
         client request ever made: {state_text}"
    );
}
