//! Container integration tests: the three backends and `reconcile::sweep`
//! against a real ufw, a real firewalld and a real nftables, each mutating
//! only its own container's own network namespace. The host's real firewall
//! is never touched.
//!
//! # Why this file exists at all
//!
//! Every test everywhere else in this workspace proves its claim against
//! `FakeRunner` or `RecordingRunner` -- a fixture built from an understanding
//! of what `ufw status numbered`, `nft -j list chain` or `firewall-cmd`
//! print. Three real defects reached committed code in this milestone, and
//! not one of them was catchable that way, because each one lived exactly in
//! the gap between "what the format is understood to be" and "what the real
//! program actually does":
//!
//! 1. The `nft` command porthole emitted could not be parsed **at all** --
//!    `nft` re-lexes argv with its own grammar, in which an unquoted
//!    `porthole:<uuid>` is a syntax error. A fixture built from "what the
//!    shell would receive" rather than "what argv the program receives"
//!    would never have shown it.
//! 2. `owned_rules` failed to recognise porthole's own rules whenever the
//!    target was a subnet -- porthole's *default* scope -- because `nft -j`
//!    represents a subnet `ip saddr` match as a nested object, not the bare
//!    scalar a fixture composed from the schema documentation assumed.
//! 3. On ufw, a `/32` source is stored with an explicit prefix and rendered
//!    back bare (`10.10.10.42`, not `10.10.10.42/32`). Reconciliation compares
//!    handles structurally, so every host-scoped `porthole open` on ufw
//!    looked stale on the very next sweep -- and reconciliation then closed
//!    the port it had just opened and reported success for.
//!
//! Each of these is now a regression test in `backend/{nftables,ufw}.rs`
//! using a captured fixture -- but a captured fixture is still a fixture. The
//! tests here run the real programs, so a fourth bug of the same shape (an
//! `nft` or `ufw` release that changes its output again) has a chance of
//! being caught here even before anyone thinks to ask "was that measured or
//! reasoned?".
//!
//! # How a mutating `porthole open`/`close` runs here with no `sudo`
//!
//! `porthole open`/`close`, unless `--dry-run`, always cross D-Bus to
//! `porthole-helper` -- see `crates/porthole-cli/src/client.rs`. So every
//! mutating test here follows the same pattern `helper_e2e.rs` uses on the
//! host: a private D-Bus **session** bus (there is no system one without a
//! real init system, and none is needed -- `--session` is exactly the
//! test-only escape hatch `porthole-helper/src/main.rs` describes, forcing
//! its `AlwaysAllow` authorizer instead of polkit), `porthole-helper
//! --session` on it, and `porthole --session <command>` as the client. See
//! [`with_helper`].
//!
//! Only `--dry-run` needs none of this: `run.rs::open`/`close` never touch
//! the bus under `--dry-run`, so the dry-run tests below invoke `porthole`
//! directly.
//!
//! # One deliberate departure from a literal reading of the task brief
//!
//! **`--until-reboot`, not `--for 5m`, for the mutating opens.** A real
//! `--for <duration>` schedules its own close with `systemd-run`, and these
//! containers have no systemd PID 1 to serve it -- confirmed by running
//! exactly that and getting `No such file or directory`. `--until-reboot`
//! is a first-class, equally real porthole invocation that skips the timer
//! entirely (`Lifetime::UntilReboot` in `engine.rs`), and every test here
//! controls its own "reboot" directly rather than waiting one out, so
//! nothing about what is being proven needs a timer at all. The dry-run
//! tests do use `--for 5m` exactly as written: dry-run withholds the
//! `systemd-run` command too, so nothing ever tries to run it.
//!
//! # Why boot 2 of the ufw test can use plain `list`
//!
//! `porthole list` deliberately touches nothing but the state file (see
//! `run.rs`'s own comment on `Commands::List`) and never calls
//! `reconcile::sweep` itself -- in fact it never crosses the bus at all:
//! `run.rs` answers a `list` from the local state file directly, without
//! going through `client.rs`, which exposes no `list` method for it to call.
//! So `list` cannot be what "needs the helper to have already claimed the bus
//! name"; the harness itself does. What makes this test usable anyway is a
//! change that landed in `porthole-helper` after this file's first draft: the
//! helper now runs one `SweepMode::Apply` sweep at start-up, under the
//! exclusive lock, *before it ever opens a bus connection* (see
//! `porthole-helper/src/main.rs`'s `reconcile_at_startup`). [`with_helper`]'s
//! own readiness poll waits on `org.freedesktop.DBus.Peer.Ping`, which cannot
//! succeed until something owns the bus name -- and the helper claims that
//! name strictly after the start-up sweep has already run. So by the time the
//! poll succeeds and `body` runs at all, the sweep has already completed and
//! the orphan is already gone, regardless of what `body` itself asks for.
//! Using `list` rather than `close --all` here is what makes the assertion
//! mean something: `list` has no code path that could itself remove a rule,
//! so the orphan's disappearance can only be reconciliation, not "the command
//! this test happens to call also deletes marked rules it finds". Before
//! that start-up sweep existed, `close --all` was used instead, for the same
//! reason `list` could not be: the per-operation sweep (`Engine::reconcile`)
//! that `close --all` triggers was the only Apply-mode sweep available at
//! all -- but a test built on it could not distinguish reconciliation from
//! `close --all`'s own literal behaviour, which is exactly the gap this
//! rewrite closes.
//!
//! # Environment this file assumes
//!
//! - An explicit opt-in. Every test here is `#[ignore]`d, so a plain `cargo
//!   test` reports them as `ignored` by name rather than counting them
//!   passed; `tests/container/run.sh` passes `--ignored` and sets
//!   `PORTHOLE_CONTAINER_TESTS=1`. Nothing in this file skips.
//! - `podman`, rootless, reachable on `$PATH`. Once opted in, this is
//!   required, not merely hoped for: a broken `podman --version` panics.
//! - The musl binaries already built: `cargo build --target
//!   x86_64-unknown-linux-musl --bins`, and built recently enough to be
//!   newer than every source file that went into them. Both are checked, and
//!   both **panic** rather than skip if they do not hold. `--ignored` and
//!   the env var are the caller's statement of intent to actually run these
//!   tests, and once that statement has been made, a missing or stale
//!   prerequisite is a bug in the run, not a reason to report success
//!   anyway. This milestone already shipped the alternative once -- five
//!   end-to-end tests silently skipped while `cargo test` reported the suite
//!   green, and nobody noticed until an unrelated fix disabled them and the
//!   loss became visible. `cargo test --package <one-crate>` compounds the
//!   same hazard from another angle: it does not rebuild a sibling crate's
//!   binary at all, so a package-scoped run can silently exercise a stale
//!   `porthole-helper`.
//! - `--network=none` on every container: measured on this machine, a bare
//!   `podman run` with no `--network` shares -- via rootless podman's default
//!   `pasta` network mode -- an interface that mirrors the *host's* own
//!   default-route interface name and address into the container for
//!   outbound convenience. It is a private per-container netns underneath,
//!   not literally the host's, but there is no reason to depend on that
//!   subtlety when `--network=none` says the safer thing directly and these
//!   tests build their own addressing (a `dummy` interface, or a veth pair)
//!   when they need one at all.
//! - `--test-threads=1`: every test names its own containers and, in the ufw
//!   test, its own podman volume. Podman itself serialises `build`/`run`
//!   fine; the reason for `-1` is the same one `helper_e2e.rs` documents for
//!   its own single shared helper -- nothing here is safe to interleave with
//!   another instance of itself.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn container_tests_enabled() -> bool {
    std::env::var("PORTHOLE_CONTAINER_TESTS").is_ok()
}

/// `podman --version` succeeding is a cheap, specific signal that podman is
/// actually usable here, rather than merely present as an unusable shim (as
/// e.g. a Docker-compatibility symlink with no runtime behind it might be).
fn podman_available() -> bool {
    Command::new("podman")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Assert the environment these tests need. Nothing here skips: every test
/// in this file carries `#[ignore]`, so opting out is what `cargo test`
/// already does by default and reports as `ignored`, honestly and by name.
/// Once a caller has said `--ignored`, a missing prerequisite is a broken
/// invocation rather than a reason to report success -- the same asymmetry
/// `require_musl_binaries!` applies, for the same reason.
///
/// This is the shape the earlier version got wrong: it printed `skipped:`
/// and returned, and libtest counted the test `ok`. Ten of this workspace's
/// tests reported success without running, which is the same hazard as a
/// green gate that executed nothing -- and this file's own module doc calls
/// that out ("a test nobody can tell ran is not a test") a few lines above
/// where it used to happen.
macro_rules! require_environment {
    () => {
        assert!(
            container_tests_enabled(),
            "these tests are opted into with PORTHOLE_CONTAINER_TESTS=1, which \
             tests/container/run.sh sets for you along with everything else they need."
        );
        assert!(
            podman_available(),
            "PORTHOLE_CONTAINER_TESTS=1 was set, so a working `podman` is required, not \
             optional: `podman --version` failed. Install or fix podman rather than let \
             this test report success without ever having run."
        );
    };
}

/// The workspace root, found from this test binary's own manifest directory
/// rather than assumed to be the current directory -- `cargo test` can be
/// invoked from anywhere.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/porthole-cli has a parent")
        .parent()
        .expect("crates/ has a parent")
        .to_path_buf()
}

fn musl_dir() -> PathBuf {
    workspace_root().join("target/x86_64-unknown-linux-musl/debug")
}

fn container_dir() -> PathBuf {
    workspace_root().join("tests/container")
}

/// The newest modification time among every file that could affect the musl
/// build: each of the three crates' `src/`, recursively, plus the workspace
/// and each crate's own `Cargo.toml`, and the workspace's `Cargo.lock`. Not
/// exhaustive -- it does not follow a `build.rs` or vendored dependencies --
/// but cheap (a `stat` per file, nothing read or hashed), and enough to catch
/// the specific hazard this exists for: a source edit made after the last
/// `cargo build --target x86_64-unknown-linux-musl --bins`, which would
/// otherwise bind-mount a stale binary into every container silently. `None`
/// if nothing under any of these paths could even be read, in which case the
/// staleness check is skipped rather than panicking on a problem it was
/// never meant to detect -- `musl_binaries`'s own existence check already
/// covers the binaries themselves being entirely absent.
fn newest_source_mtime() -> Option<std::time::SystemTime> {
    fn newest_under(path: &Path) -> Option<std::time::SystemTime> {
        let meta = std::fs::metadata(path).ok()?;
        if meta.is_file() {
            return meta.modified().ok();
        }
        if !meta.is_dir() {
            return None;
        }
        std::fs::read_dir(path)
            .ok()?
            .flatten()
            .filter_map(|entry| newest_under(&entry.path()))
            .max()
    }

    let root = workspace_root();
    let mut candidates = vec![root.join("Cargo.toml"), root.join("Cargo.lock")];
    for crate_name in ["porthole-core", "porthole-cli", "porthole-helper"] {
        let crate_dir = root.join("crates").join(crate_name);
        candidates.push(crate_dir.join("src"));
        candidates.push(crate_dir.join("Cargo.toml"));
    }
    candidates.iter().filter_map(|p| newest_under(p)).max()
}

/// The two binaries every mutating test bind-mounts into its container.
///
/// Panics -- does not skip -- if they are missing, or if either looks older
/// than the newest source file that could have gone into it. Once a caller
/// has opted in with `PORTHOLE_CONTAINER_TESTS=1`, both are a broken
/// invocation, not a reason to report the suite green having tested a stale
/// or absent binary: see the module docs for why this milestone treats that
/// distinction as load-bearing rather than pedantic.
fn musl_binaries() -> (PathBuf, PathBuf) {
    let dir = musl_dir();
    let cli = dir.join("porthole");
    let helper = dir.join("porthole-helper");
    assert!(
        cli.is_file() && helper.is_file(),
        "PORTHOLE_CONTAINER_TESTS=1 was set, so the musl binaries are required, not \
         optional: build them first with `cargo build --target \
         x86_64-unknown-linux-musl --bins` (looked in {}).",
        dir.display()
    );

    if let Some(source_mtime) = newest_source_mtime() {
        for bin in [&cli, &helper] {
            let bin_mtime = std::fs::metadata(bin)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            assert!(
                bin_mtime >= source_mtime,
                "{} is older than the newest source file under crates/*/src -- rebuild \
                 with `cargo build --target x86_64-unknown-linux-musl --bins` before \
                 running these tests, or a stale binary is bind-mounted into every \
                 container silently. (`cargo test --package <one-crate>` does not \
                 rebuild a sibling crate's binary either, which is the same hazard \
                 from a different angle.)",
                bin.display()
            );
        }
    }

    (cli, helper)
}

/// A thin wrapper so every call site still reads `require_musl_binaries!()`,
/// matching `require_environment!()`'s naming -- the behaviour underneath is
/// no longer a skip, it is `musl_binaries`'s own panic.
macro_rules! require_musl_binaries {
    () => {
        musl_binaries()
    };
}

/// Build (or, on a cache hit, instantly reuse) one of the three test images.
/// Tagged distinctly from anything a developer building unrelated images on
/// the same machine might already have (`localhost/porthole-container-test-*`
/// rather than something generic like `pt-ufw`).
fn ensure_image(tag: &str, containerfile: &str) {
    let path = container_dir().join(containerfile);
    let status = Command::new("podman")
        .args(["build", "-q", "-t", tag, "-f"])
        .arg(&path)
        .arg(container_dir())
        .status()
        .unwrap_or_else(|e| panic!("could not run `podman build`: {e}"));
    assert!(
        status.success(),
        "`podman build -f {}` failed -- see podman's own output above",
        path.display()
    );
}

const DEBIAN_IMAGE: &str = "localhost/porthole-container-test-debian";
const FEDORA_IMAGE: &str = "localhost/porthole-container-test-fedora";
const ARCH_IMAGE: &str = "localhost/porthole-container-test-arch";
const DOCKER_IMAGE: &str = "localhost/porthole-container-test-docker";

/// A podman volume, removed again when the guard drops -- including on a
/// failed assertion via an unwinding panic, so a test that fails partway
/// through still leaves nothing behind for the next run to trip over.
///
/// `create` clears any same-named leftover first: a previous run that
/// panicked before its own `Volume` dropped (a hard process abort skips
/// `Drop` entirely) would otherwise make `podman volume create` fail on the
/// very next run with "volume already exists", which is a confusing way to
/// learn that an old volume never got cleaned up.
struct Volume(String);

impl Volume {
    fn create(name: &str) -> Self {
        let _ = Command::new("podman")
            .args(["volume", "rm", "-f", name])
            .status();
        let status = Command::new("podman")
            .args(["volume", "create", name])
            .status()
            .unwrap_or_else(|e| panic!("could not run `podman volume create`: {e}"));
        assert!(status.success(), "could not create podman volume {name}");
        Volume(name.to_string())
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        let status = Command::new("podman")
            .args(["volume", "rm", "-f", &self.0])
            .status();
        match status {
            Ok(s) if s.success() => eprintln!("cleaned up podman volume {}", self.0),
            other => eprintln!(
                "warning: could not remove podman volume {}: {other:?}",
                self.0
            ),
        }
    }
}

/// Run `script` as `bash -c` inside a fresh, `--rm`-ed, `--network=none`
/// container of `image`, with `extra_args` (capabilities, volumes, env vars)
/// inserted just before the image name. One process per call: there is no
/// containers-still-running cleanup to do afterwards beyond what `--rm`
/// already guarantees.
fn podman_run(image: &str, extra_args: &[String], script: &str) -> Output {
    Command::new("podman")
        .arg("run")
        .arg("--rm")
        .arg("--network=none")
        .args(extra_args)
        .arg(image)
        .arg("bash")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|e| panic!("could not run `podman run`: {e}"))
}

/// The capabilities the Docker image's container needs on top of the
/// `NET_ADMIN` the other three ask for. Everything past `SYS_PTRACE` is what
/// a container runtime wants of the runtime hosting it -- measured by
/// removing them one at a time until `dockerd` stopped starting.
///
/// `seccomp=unconfined` and `label=disable` are passed alongside for the same
/// reason: Docker's own runtime applies a seccomp profile and SELinux labels
/// to the containers *it* creates, and it cannot do either from inside a
/// podman container that is itself confined.
const DOCKER_CONTAINER_ARGS: [&str; 5] = [
    "--cap-add=NET_ADMIN,NET_RAW,SYS_ADMIN,SYS_PTRACE,MKNOD,AUDIT_WRITE,SYS_CHROOT,SETFCAP,DAC_OVERRIDE",
    "--security-opt",
    "seccomp=unconfined",
    "--security-opt",
    "label=disable",
];

/// A detached container running **systemd as PID 1**, `podman rm -f`'d when
/// the guard drops -- including through an unwinding panic, so a failed
/// assertion still leaves nothing behind.
///
/// Every other test in this file uses [`podman_run`], which is one
/// `--rm`-ed process and no lifecycle to manage. The forward tests cannot:
/// `porthole forward` has no `--until-reboot`, so every forward schedules a
/// close with `systemd-run`, and `Engine::record_and_schedule` rolls the
/// whole forward back if that fails -- there is no spelling of a forward that
/// skips the timer the way `open --until-reboot` skips it. Measured inside
/// this image: with systemd as PID 1, `systemd-run` creates a real transient
/// timer (`systemctl list-timers` names
/// `porthole-close-<id>.timer`), so what these tests exercise is the
/// production path rather than a stub standing in for it.
///
/// `start` clears any same-named leftover first, for the reason [`Volume`]
/// does: a hard abort skips `Drop`, and `podman run --name` would then fail
/// on the next run with "name already in use".
struct SystemdContainer(String);

impl SystemdContainer {
    fn start(name: &str, image: &str, extra_args: &[String]) -> Self {
        let _ = Command::new("podman").args(["rm", "-f", name]).status();
        let out = Command::new("podman")
            .args([
                "run",
                "-d",
                "--name",
                name,
                "--network=none",
                "--systemd=always",
            ])
            .args(DOCKER_CONTAINER_ARGS)
            .args(extra_args)
            .arg(image)
            .arg("/sbin/init")
            .output()
            .unwrap_or_else(|e| panic!("could not run `podman run -d`: {e}"));
        assert!(
            out.status.success(),
            "could not start the systemd container {name}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        let container = SystemdContainer(name.to_string());
        container.wait_for_systemd();
        container
    }

    /// Wait until PID 1 has finished starting, rather than sleeping a guessed
    /// fixed time. `degraded` is the expected steady state, not a problem:
    /// `dbus.socket` and `systemd-logind.service` fail in this image (no
    /// `dbus-broker` package, and no seat to manage), and neither is anything
    /// these tests use -- the system bus firewalld needs is started by hand
    /// by [`FIREWALLD_DAEMON_SETUP`], exactly as in the three non-systemd
    /// images.
    fn wait_for_systemd(&self) {
        for _ in 0..120 {
            let out = self.exec("systemctl is-system-running 2>&1 || true");
            let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if matches!(state.as_str(), "running" | "degraded" | "maintenance") {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        panic!(
            "systemd never finished starting in container {}; `podman logs` may say why",
            self.0
        );
    }

    fn exec(&self, script: &str) -> Output {
        Command::new("podman")
            .args(["exec", &self.0, "bash", "-c", script])
            .output()
            .unwrap_or_else(|e| panic!("could not run `podman exec`: {e}"))
    }
}

impl Drop for SystemdContainer {
    fn drop(&mut self) {
        let status = Command::new("podman").args(["rm", "-f", &self.0]).status();
        match status {
            Ok(s) if s.success() => eprintln!("cleaned up container {}", self.0),
            other => eprintln!("warning: could not remove container {}: {other:?}", self.0),
        }
    }
}

fn bind_ro(host: &Path, container_path: &str) -> [String; 2] {
    // `:Z` asks podman to relabel the bind mount for this one container under
    // SELinux (enforcing on this host, confirmed: a plain bind mount without
    // it is `Permission denied` inside the container even though the exact
    // same file is world-readable outside one). It also happens to be what
    // makes rootless podman's uid remapping line up: a host file owned by the
    // invoking user appears owned by *root* inside the container (container
    // uid 0 maps to the host's own calling uid in the default rootless
    // mapping), which is exactly what `porthole_core::cli_path::resolve_cli`
    // requires of the CLI binary the helper hands to the expiry timer.
    [
        "-v".to_string(),
        format!("{}:{container_path}:ro,Z", host.display()),
    ]
}

fn cli_mounts(cli: &Path, helper: &Path) -> Vec<String> {
    let mut args = Vec::new();
    args.extend(bind_ro(cli, "/usr/local/bin/porthole"));
    args.extend(bind_ro(helper, "/usr/local/bin/porthole-helper"));
    args
}

/// `porthole`'s default `--to subnet` scope needs a real default route on a
/// non-virtual-named interface to resolve which subnet "here" means (see
/// `porthole_core::net::default_route_interface`), and `--network=none`
/// leaves only loopback. A `dummy` netdevice satisfies the *shape* `ip -j
/// route`/`ip -j addr` are read for -- an interface, an address, a default
/// route -- with no real connectivity required, because nothing in these
/// tests ever needs the fabricated gateway to answer.
const FAKE_LAN_INTERFACE: &str = r#"
ip link add eth0 type dummy
ip addr add 10.10.10.50/24 dev eth0
ip link set eth0 up
ip route add default via 10.10.10.1 dev eth0
"#;

/// Wraps the porthole invocations in `body` with the boilerplate that starts
/// a private D-Bus session bus, starts `porthole-helper --session` on it
/// (bypassing polkit -- see the module docs), waits for it to actually be
/// reachable rather than sleeping a guessed-at fixed time, runs `body`, and
/// tears the helper down again.
///
/// The wait polls `org.freedesktop.DBus.Peer.Ping` -- every D-Bus object
/// answers it for free -- rather than `helper_e2e.rs`'s own `busctl --user
/// list`, because these minimal container images have no `systemd` package
/// and therefore no `busctl`; `dbus-send` is the one thing guaranteed to be
/// present alongside `dbus-daemon` on every one of the three distributions.
fn with_helper(body: &str) -> String {
    format!(
        r#"
cat > /tmp/porthole-inner.sh <<'PORTHOLE_INNER_EOF'
set -e
porthole-helper --session >/tmp/porthole-helper.log 2>&1 &
HPID=$!
ready=0
for i in $(seq 1 100); do
  if dbus-send --session --dest=com.jacopobriccola.Porthole --print-reply \
       /com/jacopobriccola/Porthole org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1
  then
    ready=1
    break
  fi
  sleep 0.1
done
if [ "$ready" != 1 ]; then
  echo "PORTHOLE_HELPER_NEVER_READY" >&2
  cat /tmp/porthole-helper.log >&2
  exit 97
fi
{body}
kill "$HPID" 2>/dev/null || true
wait "$HPID" 2>/dev/null || true
PORTHOLE_INNER_EOF
dbus-run-session -- bash /tmp/porthole-inner.sh
"#
    )
}

fn marker_block(name: &str, body: &str) -> String {
    format!("echo '===PH_{name}_START==='\n{body}\necho '===PH_{name}_END==='\n")
}

/// Pull the text between one `marker_block`'s start and end lines out of a
/// container's combined stdout. Panics with the full output on either marker
/// missing, rather than returning an empty string that could be misread as
/// "the command printed nothing" instead of "the marker was never reached at
/// all" (e.g. because an earlier `set -e` line failed).
fn extract_marker<'a>(stdout: &'a str, name: &str) -> &'a str {
    let start = format!("===PH_{name}_START===");
    let end = format!("===PH_{name}_END===");
    let after_start = stdout
        .split(&start)
        .nth(1)
        .unwrap_or_else(|| panic!("marker {name} never started; full output:\n{stdout}"));
    after_start
        .split(&end)
        .next()
        .unwrap_or_else(|| panic!("marker {name} never ended; full output:\n{stdout}"))
        .trim()
}

fn assert_container_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed (status {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

// ---------------------------------------------------------------------------
// Step 1: the mandatory acceptance test -- ufw across a reboot.
// ---------------------------------------------------------------------------

/// ufw rules are persistent: `ufw allow` writes `/etc/ufw/user.rules` and
/// `ufw.service` reloads them at boot, while porthole's state file lives on
/// tmpfs and does not survive. So after a reboot the firewall holds a rule
/// nobody remembers -- an open port with nothing left to close it.
/// Reconciliation removing that orphan is the only thing standing between
/// porthole and a permanently open port. The spec calls this the case that is
/// easiest to get wrong and worst to get wrong ("il caso in cui è più facile
/// sbagliare e più grave sbagliare").
///
/// The reboot is simulated with all three of what actually makes ufw's
/// persistence real: a fresh container (a new tmpfs, so the state file is
/// gone), the same `/etc/ufw` volume (so ufw's own rules persist as they
/// would on a real disk), and `/lib/ufw/ufw-init start` -- exactly what
/// `ufw.service` runs at boot. Skipping the third would make ufw report
/// `inactive` and the rule not enforced, and this test would then pass
/// against an implementation that does nothing at all. That is why boot 2
/// asserts the rule really is back *before* asserting porthole removes it:
/// without that assertion the test would still pass even if ufw had silently
/// lost the rule, and the whole point is that it does not.
///
/// What no unit test can catch that this does: `Ufw::owned_rules` and
/// `Ufw::list_rules` are proven against captured `ufw status numbered` text
/// in `backend/ufw.rs`, including the exact `/32`-rendered-bare shape that
/// made a host-scoped open compare unequal to itself after a round trip. That
/// proves the parser is right about a fixture. It cannot prove that a real
/// `ufw --force delete allow ...` issued against a real, persisted rule
/// actually removes it, or that a real `ufw-init start` really does reload
/// `/etc/ufw/user.rules` the way the module docs assert. Only running the
/// real binaries against a real, persisted `/etc/ufw` can.
///
/// Boot 1 also directly exercises the third bug named in this file's own
/// module doc comment -- the worst of the three, and the one this container
/// test existed to catch but originally did not: a **host-scoped** (`/32`)
/// open, immediately followed by a second open whose own pre-open sweep
/// (`Engine::open` calls `Engine::reconcile` first, `SweepMode::Apply`) runs
/// while the first rule is still live and still known to state. Every other
/// target in this file is a subnet, and a subnet's spec round-trips through
/// `ufw status numbered` unchanged -- only a bare, prefix-dropped `/32`
/// address ever exercised the bug, so a suite that never opens one cannot
/// catch it no matter how many sweeps it runs. Confirmed by reintroducing
/// the bug (reverting `Ufw::canonical_source` to the identity function, and
/// loosening `is_porthole_shape`'s address check to accept a bare
/// `Ipv4Addr`, matching the code exactly as it stood before both existed):
/// the second open's own pre-sweep then silently deleted the first,
/// still-open rule from ufw for real, flipping the "both rules survive"
/// assertion below from pass to fail. Reverted before committing; not left
/// behind as a second, permanently-skipped test, because a bug that can only
/// be seen by hand-editing the fix out of the tree is not covered by the
/// suite that ships.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn on_ufw_a_port_opened_before_a_reboot_is_closed_after_it() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(DEBIAN_IMAGE, "Containerfile.debian");

    let volume = Volume::create("porthole-container-test-ufw-etc");

    let mut args: Vec<String> = vec![
        "--cap-add=NET_ADMIN".to_string(),
        "-v".to_string(),
        format!("{}:/etc/ufw", volume.0),
    ];
    args.extend(cli_mounts(&cli, &helper));

    // --- Boot 1: enable ufw, add a rule of the user's own, then open two
    //     ports through porthole for real -- the first host-scoped (the /32
    //     self-close bug's target shape), the second anything else, so its
    //     own pre-open sweep is an Apply sweep running while the first rule
    //     is still live. ---
    let boot1_body = "\
porthole --session open 5173 --to 10.10.10.42 --until-reboot
porthole --session open 5174 --until-reboot";
    let boot1_script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n\
         ufw --force enable\n\
         # Unrelated to porthole, no porthole: comment -- must survive every\n\
         # sweep in this test untouched.\n\
         ufw allow 2222/tcp comment 'not-porthole'\n\
         {}\n\
         {}\n",
        with_helper(boot1_body),
        marker_block("BOOT1_STATUS", "ufw status numbered"),
    );

    eprintln!("== ufw reboot test: boot 1 (enable, then open) ==");
    let out1 = podman_run(DEBIAN_IMAGE, &args, &boot1_script);
    eprintln!("{}", String::from_utf8_lossy(&out1.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out1.stderr));
    assert_container_ok(&out1, "boot 1");

    let stdout1 = String::from_utf8_lossy(&out1.stdout).to_string();
    let boot1_status = extract_marker(&stdout1, "BOOT1_STATUS");
    assert!(
        boot1_status.contains("5173/tcp")
            && boot1_status.contains("10.10.10.42")
            && boot1_status.contains("porthole:"),
        "the host-scoped rule must survive the second open's own pre-sweep -- \
         the /32 self-close bug this test exists to catch would have removed \
         it right here: {boot1_status}"
    );
    assert!(
        boot1_status.contains("5174/tcp") && boot1_status.contains("10.10.10.0/24"),
        "the second, subnet-scoped rule must also be there: {boot1_status}"
    );
    assert!(
        boot1_status.contains("2222/tcp"),
        "the user's own rule must be present too: {boot1_status}"
    );

    // --- Boot 2: a fresh container (new tmpfs -- the state file is gone),
    //     the same /etc/ufw volume. ---
    let boot2_script = format!(
        "set -e\n\
         {}\n\
         # /lib/ufw/ufw-init start prints \"sysctl: permission denied on key\n\
         # ...\" under rootless podman -- it cannot write the host's real\n\
         # network sysctls, which it has no business doing from inside a\n\
         # container anyway. Harmless: the rules load regardless, checked by\n\
         # the very next line. Measured, not assumed -- see\n\
         # milestone-3-verified-facts.md.\n\
         /lib/ufw/ufw-init start || true\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block("BEFORE_INIT", "ufw status"),
        marker_block("AFTER_INIT", "ufw status numbered"),
        with_helper("porthole --session list --json"),
        marker_block("FINAL_STATUS", "ufw status numbered"),
    );

    eprintln!("== ufw reboot test: boot 2 (fresh container, same /etc/ufw) ==");
    let out2 = podman_run(DEBIAN_IMAGE, &args, &boot2_script);
    eprintln!("{}", String::from_utf8_lossy(&out2.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out2.stderr));
    assert_container_ok(&out2, "boot 2");

    let stdout2 = String::from_utf8_lossy(&out2.stdout).to_string();

    let before_init = extract_marker(&stdout2, "BEFORE_INIT");
    assert!(
        before_init.contains("inactive"),
        "a fresh container has no init and nothing has reloaded ufw yet -- \
         this is deliberately NOT the reboot trap yet, only the reason it \
         exists: {before_init}"
    );

    // The load-bearing assertion the brief calls out by name: without this,
    // the test would still pass even if ufw had silently lost the rule, and
    // the whole point of the test is that it does not.
    let after_init = extract_marker(&stdout2, "AFTER_INIT");
    assert!(
        after_init.contains("5173/tcp")
            && after_init.contains("5174/tcp")
            && after_init.contains("porthole:"),
        "`ufw-init start` -- exactly what ufw.service runs at boot -- must \
         bring both orphaned rules back before porthole ever runs, or this \
         test would pass against an implementation that does nothing: \
         {after_init}"
    );
    assert!(
        after_init.contains("2222/tcp"),
        "the user's rule must have reloaded too: {after_init}"
    );

    // `porthole --session list` never reconciles itself (see the module docs
    // on why it is used here anyway): by the time it gets an answer, the
    // helper it talked to has already run its start-up sweep, and `list`
    // itself has no code path that could have closed anything -- so if both
    // rules are gone below, only reconciliation can be why.
    let final_status = extract_marker(&stdout2, "FINAL_STATUS");
    assert!(
        !final_status.contains("porthole:"),
        "reconciliation must have removed both orphaned rules nobody \
         remembered: {final_status}"
    );
    assert!(
        final_status.contains("2222/tcp"),
        "the user's own rule must survive reconciliation untouched: {final_status}"
    );
}

// ---------------------------------------------------------------------------
// Step 2: the nftables reachability test.
// ---------------------------------------------------------------------------

/// Builds a default-drop `inet filter` ruleset, a peer network namespace
/// joined to the container's own by a veth pair (`ip netns` does not work in
/// rootless podman -- `mount --make-shared /run/netns` fails, measured -- so
/// this uses `unshare --net` plus `nsenter -t <pid> -n` instead), a listener
/// in the container's own namespace, and a `check_reachable` shell function
/// that connects from the peer.
const NFT_RULESET_AND_NETNS_SETUP: &str = r#"
set -e
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input iif lo accept
ip link set lo up

ip link add veth0 type veth peer name veth1
ip addr add 10.10.10.1/24 dev veth0
ip link set veth0 up

unshare --net sleep 300 &
PEER_PID=$!
sleep 0.3
ip link set veth1 netns "$PEER_PID"
nsenter -t "$PEER_PID" -n ip addr add 10.10.10.2/24 dev veth1
nsenter -t "$PEER_PID" -n ip link set veth1 up
nsenter -t "$PEER_PID" -n ip link set lo up

socat -T60 TCP-LISTEN:6001,reuseaddr,fork OPEN:/dev/null &
LISTENER_PID=$!
sleep 0.3

check_reachable() {
  nsenter -t "$PEER_PID" -n bash -c '
    if timeout 2 bash -c "exec 3<>/dev/tcp/10.10.10.1/6001" 2>/dev/null
    then echo REACHABLE
    else echo BLOCKED
    fi
  '
}
"#;

/// Asserts reachability, never rule presence. A test that greps `nft list
/// ruleset` for porthole's rule would pass against the design where porthole
/// keeps its own table at a higher hook priority -- and that design leaves
/// the port **blocked**, because in netfilter `accept` ends traversal of its
/// own chain but not of the hook: evaluation continues into the next base
/// chain registered at the same hook in priority order, and the user's
/// `policy drop` chain still runs. Measured with two real network namespaces,
/// a veth pair, a real listener and a real `connect(2)`: an isolated table at
/// `hook input priority -10` was BLOCKED; inserting into the user's own input
/// chain was REACHABLE. `backend/nftables.rs` is built around inserting into
/// the discovered chain for exactly this reason, and this is the test that
/// would have caught it had it been built the other way -- a rule-presence
/// check cannot distinguish the two designs, since both leave a
/// `porthole:`-commented rule sitting in *some* ruleset.
///
/// What no unit test can catch that this does: every nftables unit test
/// feeds `RecordingRunner` a captured `nft -j` fixture and never runs `nft`
/// for real, let alone tests whether the *kernel* actually enforces the
/// rule the way the JSON describes it. This is the only place in the whole
/// suite that opens a real listening socket and makes a real `connect(2)`
/// across a real veth to ask "is the port actually reachable", which is the
/// only question this backend exists to answer correctly.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn on_nftables_an_opened_port_is_actually_reachable() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(ARCH_IMAGE, "Containerfile.arch");

    let mut args: Vec<String> =
        vec!["--cap-add=NET_ADMIN,NET_RAW,SYS_ADMIN,SYS_PTRACE".to_string()];
    args.extend(cli_mounts(&cli, &helper));

    let script = format!(
        "{NFT_RULESET_AND_NETNS_SETUP}\n\
         {}\n\
         {}\n\
         {}\n\
         {}\n\
         {}\n\
         {}\n\
         kill \"$LISTENER_PID\" \"$PEER_PID\" 2>/dev/null || true\n",
        marker_block("PHASE1_BEFORE_OPEN", "check_reachable"),
        with_helper("porthole --session open 6001 --to 10.10.10.0/24 --until-reboot"),
        marker_block("PHASE2_AFTER_OPEN", "check_reachable"),
        with_helper("porthole --session close 6001"),
        marker_block("PHASE3_AFTER_CLOSE", "check_reachable"),
        marker_block("FINAL_RULESET", "nft -a list ruleset"),
    );

    eprintln!("== nftables reachability test ==");
    let out = podman_run(ARCH_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the nftables reachability container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    assert_eq!(
        extract_marker(&stdout, "PHASE1_BEFORE_OPEN"),
        "BLOCKED",
        "the default-drop ruleset must block the peer before porthole opens \
         anything -- otherwise phase 2's REACHABLE would prove nothing"
    );
    // The assertion the whole backend exists for.
    assert_eq!(
        extract_marker(&stdout, "PHASE2_AFTER_OPEN"),
        "REACHABLE",
        "porthole open must make the port actually reachable from the peer, \
         not merely add a rule that looks right"
    );
    assert_eq!(
        extract_marker(&stdout, "PHASE3_AFTER_CLOSE"),
        "BLOCKED",
        "porthole close must make the port unreachable again"
    );

    let final_ruleset = extract_marker(&stdout, "FINAL_RULESET");
    assert!(
        !final_ruleset.contains("porthole:"),
        "the rule must be gone from the ruleset after close, not merely \
         unreachable for some other reason: {final_ruleset}"
    );
    // Unlike firewalld, the orphan direction genuinely runs on nftables --
    // `Nftables::ownership()` is `Marked`, so reconciliation's orphan sweep
    // has a list to consume here. A sweep that flushed the whole chain (the
    // user's own rules included) would still leave phase 3 BLOCKED under
    // `policy drop` either way, so reachability alone cannot catch that --
    // only checking that the user's own rules are still there can.
    assert!(
        final_ruleset.contains("ct state established,related accept")
            && final_ruleset.contains(r#"iif "lo" accept"#),
        "the user's own rules -- not porthole's -- must survive reconciliation \
         untouched: {final_ruleset}"
    );
}

// ---------------------------------------------------------------------------
// Step 3: the firewalld test -- the user's rules survive.
// ---------------------------------------------------------------------------

/// Starts a private system D-Bus bus and `firewalld` itself in the
/// foreground -- there is no systemd PID 1 in a container to start either --
/// and waits for `firewall-cmd --state` to answer before returning control.
///
/// Measured: running everything as the container's own root is enough for
/// `firewall-cmd --add-rich-rule` to succeed with no polkit agent registered
/// anywhere -- and, measured in the same place, an unprivileged caller here
/// is refused every firewalld call rather than only the config ones, because
/// without systemd polkit cannot resolve a subject and firewalld falls back
/// to a uid check. Both halves of
/// `an_open_firewalld_agrees_to_lands_in_it_and_one_it_refuses_leaves_it_alone`
/// below rest on those two measurements.
const FIREWALLD_DAEMON_SETUP: &str = r#"
set -e
mkdir -p /run/dbus
dbus-daemon --system --fork
firewalld --nofork --nopid >/tmp/firewalld.log 2>&1 &
ready=0
for i in $(seq 1 150); do
  if firewall-cmd --state >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
if [ "$ready" != 1 ]; then
  echo "FIREWALLD_NEVER_READY" >&2
  cat /tmp/firewalld.log >&2
  exit 96
fi
"#;

/// The container-level counterpart of the unit test in task 5
/// (`reconcile::tests::on_firewalld_no_rule_is_ever_removed_from_the_firewall`),
/// and the one that would catch a reconciliation that learned to sweep
/// firewalld: firewalld's rich language has no comment element, so a rule
/// porthole wrote is textually indistinguishable from one the user wrote by
/// hand, and `Firewalld::owned_rules` returns `None` -- there is no list for
/// the orphan sweep to consume, by construction (see `backend/mod.rs`'s
/// `Ownership` and `reconcile.rs`'s own module docs on "the direction that
/// does not exist on firewalld").
///
/// What no unit test can catch that this does: the unit test proves
/// `sweep()` never *calls* `owned_rules` on a `Firewalld` backend. It cannot
/// prove that a real, hand-added rich rule survives several real porthole
/// commands issued against a real, running firewalld -- which is the actual
/// claim "firewalld's rules are safe from reconciliation" needs to cash out
/// as, and the only thing this container can prove that the unit test
/// cannot.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn firewalld_survives_several_sweeps_with_the_users_rule_intact() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(cli_mounts(&cli, &helper));

    let body = "\
porthole --session open 5173 --until-reboot
porthole --session list --json
porthole --session open 6000 --proto udp --until-reboot
porthole --session close 5173
porthole --session list --json
porthole --session close 6000 --proto udp";

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n\
         ZONE=$(firewall-cmd --get-default-zone)\n\
         # A rich rule porthole never created -- must survive every sweep\n\
         # below untouched, because firewalld cannot prove it is not\n\
         # porthole's own.\n\
         firewall-cmd --zone=\"$ZONE\" --add-rich-rule='rule family=\"ipv4\" \
source address=\"192.168.77.0/24\" port port=\"9999\" protocol=\"tcp\" accept'\n\
         {}\n\
         {}\n",
        with_helper(body),
        marker_block("FINAL_RICH_RULES", "firewall-cmd --list-rich-rules"),
    );

    eprintln!("== firewalld test: the user's rule survives several sweeps ==");
    let out = podman_run(FEDORA_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the firewalld container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let final_rules = extract_marker(&stdout, "FINAL_RICH_RULES");

    assert!(
        final_rules.contains("192.168.77.0/24") && final_rules.contains(r#"port="9999""#),
        "the user's own hand-written rich rule must still be there after \
         every porthole sweep: {final_rules}"
    );
    assert!(
        !final_rules.contains(r#"port="5173""#) && !final_rules.contains(r#"port="6000""#),
        "porthole's own rules must be gone after their closes: {final_rules}"
    );
}

/// The one place `Porthole::open` and every client-requested close are driven
/// all the way through to the signals they emit.
///
/// `crates/porthole-helper/tests/signals.rs` proves the declaration, the
/// payload and the subscribe-and-receive path, but it emits through
/// `announce_open`/`announce_close` directly: an `open` that gets far enough
/// to announce anything has to have changed a real firewall, which the
/// development host may not do. Here it can -- the container has its own
/// firewalld in its own network namespace -- so this is what would catch an
/// `open` or a client-requested `close` that stopped calling its
/// announcement, which no test on the host can. (The one announcement a host
/// test does reach from inside its own method is `announce_reconciled`, in
/// `crates/porthole-helper/tests/reconciled_signal.rs`: reconciliation only
/// reads the firewall, so a stub `firewall-cmd` is enough for it and is not
/// enough for these.)
///
/// `dbus-monitor` is the subscriber because it is the only one these images
/// have (`dbus-tools` on Fedora). A monitor connection is exempt from D-Bus
/// receive policy, so what this proves is that the signals are *emitted*,
/// not that any particular policy would deliver them -- that is
/// `signals.rs`'s `the_shipped_policy_is_what_lets_a_signal_reach_a_subscriber`,
/// which uses an ordinary client and its own `dbus-daemon`.
///
/// `stdbuf -oL`: `dbus-monitor`'s stdout is a file here, so libc would buffer
/// it in 4K blocks and the `kill` below would discard whatever had not
/// filled a block -- a test that reported "no signals" for a reason that has
/// nothing to do with porthole.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn signals_reach_a_subscriber_when_a_port_is_opened_and_closed() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(cli_mounts(&cli, &helper));

    let body = r#"
stdbuf -oL dbus-monitor --session "type='signal',interface='com.jacopobriccola.Porthole1'"   > /tmp/signals.txt 2>&1 &
MONPID=$!
# dbus-monitor prints its own NameAcquired the moment it is connected, so a
# non-empty file is a real readiness signal rather than a guessed-at sleep.
for i in $(seq 1 100); do
  if [ -s /tmp/signals.txt ]; then break; fi
  sleep 0.1
done
# One of each close a client can ask for, so every reason a *request* can
# produce is exercised against a real firewall: an ordinary close, the
# expiry timer's own `--from-timer` close, and `close --all`.
porthole --session open 5173 --until-reboot
porthole --session close 5173

ID=$(porthole --session open 6000 --until-reboot --json | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$ID" ]; then echo "NO_RULE_ID_IN_OPEN_JSON" >&2; exit 95; fi
porthole --session close --id "$ID" --from-timer

porthole --session open 7000 --until-reboot
porthole --session open 7001 --until-reboot
porthole --session close --all

sleep 1
kill "$MONPID" 2>/dev/null || true
"#;

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n{}\n{}\n",
        with_helper(body),
        marker_block("SIGNALS", "cat /tmp/signals.txt"),
    );

    eprintln!("== firewalld test: an open and a close reach a subscriber ==");
    let out = podman_run(FEDORA_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the firewalld signals container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let signals = extract_marker(&stdout, "SIGNALS");

    assert!(
        signals.contains("member=RuleOpened"),
        "a real `porthole open` announced nothing: {signals}"
    );
    assert!(
        signals.contains("member=RuleClosed"),
        "a real `porthole close` announced nothing: {signals}"
    );
    assert!(
        signals.contains(r#"string "requested""#),
        "the close a person asked for must carry that reason: {signals}"
    );
    assert!(
        signals.contains(r#"string "expired""#),
        "the expiry timer's own close must not read as one a person asked \
         for: {signals}"
    );
    for port in ["5173", "6000", "7000", "7001"] {
        assert!(
            signals.contains(&format!("uint16 {port}")),
            "the signals must name port {port}: {signals}"
        );
    }
    // Four opens, four closes, one signal each. A count rather than a
    // presence check, because the defect this task exists to prevent is a
    // close that announces nothing while its neighbours do -- which every
    // `contains` above would still pass.
    assert_eq!(
        signals.matches("member=RuleOpened").count(),
        4,
        "one RuleOpened per open: {signals}"
    );
    assert_eq!(
        signals.matches("member=RuleClosed").count(),
        4,
        "one RuleClosed per close, `close --all`'s two included: {signals}"
    );
    assert_eq!(
        signals.matches(r#"string "requested""#).count(),
        3,
        "the ordinary close and `close --all`'s two, and nothing else: \
         {signals}"
    );
    // `--to subnet` is the default, and the helper resolves it. The signal
    // carries what the helper decided, so the fabricated LAN's own CIDR is
    // what a subscriber sees -- never the word the client typed.
    assert!(
        signals.contains("10.10.10.0/24"),
        "the signals must carry the resolved subnet: {signals}"
    );
    // The removal spec stays on the privileged side. A firewalld handle would
    // show up here as the rich rule itself.
    assert!(
        !signals.contains("rule family"),
        "a rich rule rode the broadcast: {signals}"
    );
}

/// A record dropped by a *per-operation* sweep, with the helper never
/// restarting, reaches the bus as `CloseReason::Reconciled`.
///
/// The realistic trigger, and the one no restart-based test covers: a
/// `firewall-cmd --reload` while the helper is running. porthole's rules are
/// runtime-only, so the reload throws them away; the state file survives; and
/// the next operation's own reconciliation drops the record. That operation
/// here is a `porthole close`, which then **fails** -- the record it was
/// about to act on is the one that just went -- which is exactly the shape
/// that would hide the drop from a subscriber if the announcement were tied
/// to the operation succeeding.
///
/// The host-side counterpart
/// (`porthole-helper/tests/reconciled_signal.rs`'s
/// `a_record_the_firewall_no_longer_has_is_announced_by_the_operation_that_finds_it`)
/// synthesises the orphaned record and answers the firewall's reads from a
/// stub, so it runs anywhere; this one gets the record from a real reload of
/// a real firewalld.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn a_reload_under_a_running_helper_announces_the_records_it_orphaned() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(cli_mounts(&cli, &helper));

    let body = r#"
stdbuf -oL dbus-monitor --session "type='signal',interface='com.jacopobriccola.Porthole1'" \
  > /tmp/signals.txt 2>&1 &
MONPID=$!
for i in $(seq 1 100); do
  if [ -s /tmp/signals.txt ]; then break; fi
  sleep 0.1
done

porthole --session open 5173 --until-reboot

# The firewall forgets. The helper does not restart, and porthole's state
# file still has the record.
firewall-cmd --reload
echo '===PH_AFTER_RELOAD_START==='
firewall-cmd --list-rich-rules
echo '===PH_AFTER_RELOAD_END==='

# Fails: this operation's own sweep drops the record before the close can
# find it. The drop must be announced anyway.
porthole --session close 5173 || true
echo '===PH_AFTER_CLOSE_START==='
porthole --session list --json
echo '===PH_AFTER_CLOSE_END==='

sleep 1
kill "$MONPID" 2>/dev/null || true
"#;

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n{}\n{}\n",
        with_helper(body),
        marker_block("SIGNALS", "cat /tmp/signals.txt"),
    );

    eprintln!("== firewalld test: a reload under a running helper is announced ==");
    let out = podman_run(FEDORA_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the firewalld reload container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    let after_reload = extract_marker(&stdout, "AFTER_RELOAD");
    assert!(
        !after_reload.contains(r#"port="5173""#),
        "the reload was supposed to leave the firewall without porthole's \
         rule, so the next sweep has something to find: {after_reload}"
    );
    assert!(
        extract_marker(&stdout, "AFTER_CLOSE").contains(r#""rules":[]"#),
        "the record must be gone from state too: {}",
        extract_marker(&stdout, "AFTER_CLOSE")
    );

    let signals = extract_marker(&stdout, "SIGNALS");
    assert_eq!(
        signals.matches("member=RuleClosed").count(),
        1,
        "exactly one RuleClosed, for the record the sweep dropped: {signals}"
    );
    assert!(
        signals.contains(r#"string "reconciled""#),
        "porthole did not close this one -- it found a record of a rule the \
         firewall no longer had: {signals}"
    );
    assert!(
        !signals.contains(r#"string "requested""#),
        "the close failed, so nothing may claim a client asked for it: \
         {signals}"
    );
    assert!(
        signals.contains("uint16 5173"),
        "the signal must name the record that was dropped: {signals}"
    );
}

/// The start-up reconciliation sweep announces what it dropped, as
/// `CloseReason::Reconciled`.
///
/// The condition is built inside one container rather than across a reboot:
/// a rule opened, the helper stopped, `firewall-cmd --reload` throwing away
/// every runtime rule (porthole never writes a permanent one), and a second
/// helper started. That second helper's sweep is the one in
/// `porthole-helper/src/main.rs`'s `reconcile_at_startup`, and the rule it
/// finds in state and not in the firewall is exactly the "opened before the
/// reboot" case.
///
/// This is the only test anywhere that shows the announcement happening at
/// all: it is emitted after the bus name is claimed, from a code path with
/// no client and no request behind it, and nothing on the development host
/// can reach it. `dbus-monitor` is started before the second helper for the
/// same reason -- a subscriber that connects afterwards has already missed
/// it, which the emitting code says outright.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn the_start_up_sweep_announces_what_it_dropped() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(cli_mounts(&cli, &helper));

    // Not `with_helper`: this needs two helper lifetimes with a subscriber
    // started between them, which that wrapper's single start/stop cannot
    // express.
    let inner = r#"
set -e
start_helper() {
  porthole-helper --session >>/tmp/porthole-helper.log 2>&1 &
  HPID=$!
  for i in $(seq 1 100); do
    if dbus-send --session --dest=com.jacopobriccola.Porthole --print-reply \
         /com/jacopobriccola/Porthole org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1
    then
      return 0
    fi
    sleep 0.1
  done
  echo "PORTHOLE_HELPER_NEVER_READY" >&2
  cat /tmp/porthole-helper.log >&2
  exit 97
}

start_helper
porthole --session open 5173 --until-reboot
kill "$HPID" 2>/dev/null || true
wait "$HPID" 2>/dev/null || true

# firewalld drops every runtime rule on reload, and porthole never writes a
# permanent one -- so this is the firewall forgetting what porthole's state
# file still remembers, which is what a reboot does to ufw.
firewall-cmd --reload
echo '===PH_AFTER_RELOAD_START==='
firewall-cmd --list-rich-rules
echo '===PH_AFTER_RELOAD_END==='

stdbuf -oL dbus-monitor --session "type='signal',interface='com.jacopobriccola.Porthole1'" \
  > /tmp/signals.txt 2>&1 &
MONPID=$!
for i in $(seq 1 100); do
  if [ -s /tmp/signals.txt ]; then break; fi
  sleep 0.1
done

start_helper
sleep 1
kill "$MONPID" 2>/dev/null || true
kill "$HPID" 2>/dev/null || true
wait "$HPID" 2>/dev/null || true
"#;

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n\
         cat > /tmp/porthole-reconcile.sh <<'PORTHOLE_INNER_EOF'\n{inner}\n\
         PORTHOLE_INNER_EOF\n\
         dbus-run-session -- bash /tmp/porthole-reconcile.sh\n{}\n",
        marker_block("SIGNALS", "cat /tmp/signals.txt"),
    );

    eprintln!("== firewalld test: the start-up sweep announces what it dropped ==");
    let out = podman_run(FEDORA_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the firewalld reconciliation-signal container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    // Without this the test could pass for the wrong reason -- or fail
    // without saying which half broke.
    let after_reload = extract_marker(&stdout, "AFTER_RELOAD");
    assert!(
        !after_reload.contains(r#"port="5173""#),
        "the reload was supposed to leave the firewall without porthole's \
         rule, so the second helper's sweep has something to find: \
         {after_reload}"
    );

    let signals = extract_marker(&stdout, "SIGNALS");
    assert!(
        signals.contains("member=RuleClosed"),
        "the start-up sweep dropped a rule and announced nothing: {signals}"
    );
    assert!(
        signals.contains(r#"string "reconciled""#),
        "the sweep did not close anything itself, so the reason must say so \
         rather than claiming a close: {signals}"
    );
    assert!(
        signals.contains("uint16 5173"),
        "the signal must name the rule that was dropped: {signals}"
    );
}

/// The network watcher announces the change and the closes it caused.
///
/// `-e PORTHOLE_NETMON=1` is what lets the watcher run at all here. It does
/// not run under `--session` otherwise, because a `--session` helper started
/// on a developer's own machine would be closing rules in that machine's real
/// firewall off a timer; this container's firewall is its own and goes away
/// with it, which is what the variable asserts. See
/// `porthole_helper::netmon::should_run`.
///
/// Two waits of just over `netmon::POLL_INTERVAL` (60s), which is what makes
/// this test take well over two minutes: the poll is the only wake-up source
/// a container has -- `org.freedesktop.NetworkManager` is not on this bus --
/// and the interval is a production constant, not something a test may
/// shorten. Two polls are needed rather than one because `NetworkChanged`
/// compares a look against the *previous* look: the first poll only records
/// where the machine is, and it is the second, after the address has moved,
/// that has something to compare against.
///
/// Nothing on the development host can reach this code: `netmon` closes
/// rules in a real firewall, off its own timer, with no client involved.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn a_subnet_the_machine_left_is_announced_along_with_the_rules_it_closed() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let mut args: Vec<String> = vec![
        "--cap-add=NET_ADMIN".to_string(),
        "-e".to_string(),
        "PORTHOLE_NETMON=1".to_string(),
    ];
    args.extend(cli_mounts(&cli, &helper));

    let body = r#"
stdbuf -oL dbus-monitor --session "type='signal',interface='com.jacopobriccola.Porthole1'" \
  > /tmp/signals.txt 2>&1 &
MONPID=$!
for i in $(seq 1 100); do
  if [ -s /tmp/signals.txt ]; then break; fi
  sleep 0.1
done

porthole --session open 5173 --until-reboot

# Long enough for one poll to have looked and recorded 10.10.10.0/24 while
# the rule was still on it -- so nothing has closed yet, and there is a
# previous look for the next one to differ from.
sleep 70
echo '===PH_BEFORE_MOVE_START==='
porthole --session list --json
echo '===PH_BEFORE_MOVE_END==='

# The machine moves to a different subnet on the same interface: a new
# access point, or a fresh DHCP lease.
ip addr flush dev eth0
ip addr add 192.168.5.50/24 dev eth0
ip route add default via 192.168.5.1 dev eth0

sleep 70
echo '===PH_AFTER_MOVE_START==='
porthole --session list --json
echo '===PH_AFTER_MOVE_END==='
kill "$MONPID" 2>/dev/null || true
"#;

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n{}\n{}\n",
        with_helper(body),
        marker_block("SIGNALS", "cat /tmp/signals.txt"),
    );

    eprintln!("== firewalld test: leaving a subnet is announced (this one takes ~2.5 minutes) ==");
    let out = podman_run(FEDORA_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the firewalld network-change container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    // Both listings, so a failure says which half broke: a rule that was
    // never open in the first place would produce the same empty "after" as
    // one the watcher closed.
    assert!(
        extract_marker(&stdout, "BEFORE_MOVE").contains("5173"),
        "the rule must still be open while the machine is on its own subnet: {}",
        extract_marker(&stdout, "BEFORE_MOVE")
    );
    assert!(
        !extract_marker(&stdout, "AFTER_MOVE").contains("5173"),
        "the rule must be gone once the machine has left that subnet: {}",
        extract_marker(&stdout, "AFTER_MOVE")
    );

    let signals = extract_marker(&stdout, "SIGNALS");
    assert!(
        signals.contains("member=NetworkChanged"),
        "the machine changed subnet and nothing said so: {signals}"
    );
    assert!(
        signals.contains(r#"string "10.10.10.0/24""#)
            && signals.contains(r#"string "192.168.5.0/24""#),
        "NetworkChanged must name both the subnet left and the one arrived \
         on: {signals}"
    );
    assert!(
        signals.contains(r#"string "network-changed""#),
        "the close the move caused must carry that reason, not `requested`: \
         {signals}"
    );
}

/// The chain `helper_e2e.rs` used to drive against the developer's own
/// firewall, both ways round: an open firewalld performs, and one it refuses.
///
/// The refusing half is what used to live on the host, as
/// `an_open_reaches_the_firewall_and_changes_nothing_when_refused`. It could
/// only ever watch firewalld say no, because saying no is all an unprivileged
/// caller can make it do -- and it asked for that refusal by running a real
/// `porthole open` against a real desktop's real firewalld, which raised
/// firewalld's own polkit prompt on the person's screen every time the suite
/// ran. Once, someone typed the password: the open succeeded, the test that
/// asserts refusal failed, and the temporary state directory vanished at the
/// end of the run leaving a real rich rule in that firewall with nothing left
/// that could close it. Here the firewall goes away with the container.
///
/// **The half that was impossible on a development host.** Running as the
/// container's own root, firewalld agrees, so this can assert what no host
/// test could: the rich rule porthole says it added is really in
/// `firewall-cmd --list-rich-rules` while the rule is open, carries the
/// subnet the helper resolved rather than the word the client typed, is
/// named by `porthole list`, and is gone again after `porthole close` -- with
/// a rule the user added by hand still there on both sides of all of it.
/// That was on the human acceptance checklist for exactly the reason this
/// test now exists.
///
/// **What the refusing half proves here, and where it stops.** Measured
/// inside this container: there is no systemd, so polkit cannot resolve a
/// subject at all (`polkitd` logs `Error calling GetUnitByPIDFD` and denies
/// every check), and firewalld falls back to its own uid check -- it answers
/// an unprivileged caller `NotAuthorizedException: Not Authorized(uid)` for
/// *every* call, including the read-only ones its own policy grants everyone
/// on a machine that does have a session. So this half runs the same chain
/// the host test did -- CLI, bus, the helper's authorization, its validation,
/// `Engine::open`, `firewall-cmd` -- and stops one step earlier than the host
/// version did: `Engine::open`'s own `health.active` guard refuses on a
/// `--state` firewalld would not answer, rather than firewalld refusing the
/// `--add-rich-rule` that would have come next. The outcome asserted is the
/// one the host test asserted and the one that matters: the request fails,
/// the firewall's own rule listing is byte-identical across it, and no state
/// file is written. That a real `firewall-cmd` ran and was refused -- rather
/// than porthole quietly doing nothing -- is asserted from the helper's own
/// log, so this half cannot pass by never having run.
///
/// The one step it stops short of is the step the privileged half above goes
/// all the way through, on the same firewalld, in the same container.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn an_open_firewalld_agrees_to_lands_in_it_and_one_it_refuses_leaves_it_alone() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(cli_mounts(&cli, &helper));

    // The privileged half. `--until-reboot` rather than `--for`, for the
    // reason the module docs give: there is no systemd PID 1 here to serve a
    // `systemd-run` timer.
    let privileged = format!(
        "porthole --session open 5173 --until-reboot\n{}\n{}\nporthole --session close 5173\n",
        marker_block("RULES_WHILE_OPEN", "firewall-cmd --list-rich-rules"),
        marker_block("LIST_WHILE_OPEN", "porthole --session list --json"),
    );

    // The refusing half. Its own session bus, its own state file, and an
    // ordinary uid: `nobody` (65534) exists in the base image, so nothing
    // here has to create an account. `set +e` around the open alone, so its
    // failure is this script's subject rather than its end.
    let unprivileged = "\
set -e
porthole-helper --session >/tmp/unprivileged/helper.log 2>&1 &
HPID=$!
ready=0
for i in $(seq 1 100); do
  if dbus-send --session --dest=com.jacopobriccola.Porthole --print-reply \\
       /com/jacopobriccola/Porthole org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1
  then
    ready=1
    break
  fi
  sleep 0.1
done
if [ \"$ready\" != 1 ]; then
  echo \"PORTHOLE_HELPER_NEVER_READY\" >&2
  cat /tmp/unprivileged/helper.log >&2
  exit 97
fi
echo '===PH_REFUSED_START==='
set +e
porthole --session open 15173 --until-reboot
echo \"EXIT=$?\"
set -e
echo '===PH_REFUSED_END==='
kill \"$HPID\" 2>/dev/null || true
wait \"$HPID\" 2>/dev/null || true
";

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n\
         # A rich rule the user added by hand, so every before/after pair\n\
         # below compares two listings rather than two empty ones.\n\
         firewall-cmd --add-rich-rule='rule family=\"ipv4\" \
source address=\"192.168.77.0/24\" port port=\"9999\" protocol=\"tcp\" accept'\n\
         {}\n\
         {}\n\
         mkdir -p /tmp/unprivileged\n\
         chown 65534:65534 /tmp/unprivileged\n\
         cat > /tmp/porthole-unprivileged.sh <<'PORTHOLE_UNPRIVILEGED_EOF'\n\
         {}\n\
         PORTHOLE_UNPRIVILEGED_EOF\n\
         {}\n\
         setpriv --reuid=65534 --regid=65534 --clear-groups \
env HOME=/tmp/unprivileged PORTHOLE_STATE_FILE=/tmp/unprivileged/state.json \
dbus-run-session -- bash /tmp/porthole-unprivileged.sh\n\
         {}\n\
         {}\n\
         {}\n",
        with_helper(&privileged),
        marker_block("RULES_AFTER_CLOSE", "firewall-cmd --list-rich-rules"),
        unprivileged,
        marker_block("RULES_BEFORE_REFUSED", "firewall-cmd --list-rich-rules"),
        marker_block("RULES_AFTER_REFUSED", "firewall-cmd --list-rich-rules"),
        marker_block(
            "UNPRIVILEGED_STATE",
            "cat /tmp/unprivileged/state.json 2>/dev/null || echo '(no state file)'"
        ),
        marker_block("UNPRIVILEGED_LOG", "cat /tmp/unprivileged/helper.log"),
    );

    eprintln!("== firewalld test: an open it agrees to, and one it refuses ==");
    let out = podman_run(FEDORA_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the firewalld open-and-refusal container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    // --- what happens when firewalld agrees ---
    let while_open = extract_marker(&stdout, "RULES_WHILE_OPEN");
    assert!(
        while_open.contains(
            r#"rule family="ipv4" source address="10.10.10.0/24" port port="5173" protocol="tcp" accept"#
        ),
        "the open reported success, so firewalld itself must be holding the \
         rule: {while_open}"
    );
    assert!(
        while_open.contains(r#"port="9999""#),
        "the user's own rule must still be there: {while_open}"
    );

    let listed = extract_marker(&stdout, "LIST_WHILE_OPEN");
    assert!(
        listed.contains(r#""port":5173"#) && listed.contains(r#""target":"10.10.10.0/24""#),
        "porthole must name the rule it opened, resolved subnet and all: {listed}"
    );

    let after_close = extract_marker(&stdout, "RULES_AFTER_CLOSE");
    assert!(
        !after_close.contains(r#"port="5173""#),
        "the close must take the rule back out of firewalld: {after_close}"
    );
    assert!(
        after_close.contains(r#"port="9999""#),
        "and must leave the user's own rule where it was: {after_close}"
    );

    // --- what happens when it refuses ---
    let refused = extract_marker(&stdout, "REFUSED");
    assert!(
        !refused.contains("EXIT=0"),
        "an unprivileged porthole cannot change this firewall, so the open \
         must fail: {refused}"
    );
    assert_eq!(
        extract_marker(&stdout, "RULES_BEFORE_REFUSED"),
        extract_marker(&stdout, "RULES_AFTER_REFUSED"),
        "a refused open may leave nothing behind in the firewall"
    );
    let state = extract_marker(&stdout, "UNPRIVILEGED_STATE");
    assert!(
        state == "(no state file)" || !state.contains("15173"),
        "a refused open may record nothing: {state}"
    );
    // The control: without this, a run in which porthole never got as far as
    // the firewall at all would satisfy every assertion above.
    let log = extract_marker(&stdout, "UNPRIVILEGED_LOG");
    assert!(
        log.contains("firewall-cmd") && log.contains("Not Authorized"),
        "the refusal must be firewalld's, on a call porthole really made: {log}"
    );
}

/// `close --id` for a rule the firewall does not have reports it missing,
/// rather than issuing a removal for it.
///
/// This one also used to run on the host, where the record it seeds named the
/// developer's own default zone and a syntactically valid rich rule for it --
/// a removal spec aimed at their live firewall, held back only by
/// reconciliation deciding to prune the record first. The version of this
/// test before reconciliation existed asserted the opposite outcome: a real
/// `firewall-cmd --remove-rich-rule` that hung for firewalld's ~25s reply
/// timeout with no polkit agent to answer, which is what it then had to wait
/// out on every run.
///
/// The state file is seeded *after* the helper is already serving, so what
/// prunes the record is `Engine::close_by_id`'s own per-operation sweep and
/// not the start-up one -- the start-up sweep has its own test
/// (`the_start_up_sweep_announces_what_it_dropped`), and a seed written
/// before the helper started would be gone before this test's own close ever
/// ran.
///
/// **The control, which the host version could not have.** Exit 7 is only
/// evidence that reconciliation pruned the record first if a removal that
/// *was* attempted would have ended differently -- and it would: as root,
/// against a rule firewalld does not have, `--remove-rich-rule` answers
/// `NOT_ENABLED`, which `firewalld::is_already_absent` reads as "already
/// gone" and `close_by_id` reports as a successful close (exit 0). The
/// marker below runs exactly that removal and shows what firewalld says to
/// it, so the discriminator is measured here rather than asserted from
/// memory. On the host this test used elapsed time as the discriminator
/// instead, which only worked because an unauthorized removal hung.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn a_close_by_id_for_a_rule_the_firewall_lacks_reports_it_missing_and_removes_nothing() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(cli_mounts(&cli, &helper));

    const RULE_ID: &str = "seeded-phantom";
    const PORT: u16 = 25198;
    const CIDR: &str = "203.0.113.0/24"; // TEST-NET-3: never a real subnet.
    let rich_rule = format!(
        r#"rule family="ipv4" source address="{CIDR}" port port="{PORT}" protocol="tcp" accept"#
    );
    // `__ZONE__` rather than a literal: the zone has to be the one this
    // container's own firewalld would act on, which is only knowable inside
    // it. Built with `serde_json` rather than written out by hand so the
    // rich rule's own double quotes are escaped by the same code that will
    // read them back.
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
            "handle": {"backend": "firewalld", "zone": "__ZONE__", "rich_rule": rich_rule},
        }]
    });
    let seeded = serde_json::to_string(&seeded).expect("the seed serialises");

    let body = format!(
        "cat > \"$PORTHOLE_STATE_FILE\" <<'PORTHOLE_SEED_EOF'\n{seeded}\n\
         PORTHOLE_SEED_EOF\n\
         sed -i \"s/__ZONE__/$ZONE/\" \"$PORTHOLE_STATE_FILE\"\n\
         echo '===PH_CLOSE_START==='\n\
         set +e\n\
         porthole --session close --id {RULE_ID}\n\
         echo \"EXIT=$?\"\n\
         set -e\n\
         echo '===PH_CLOSE_END==='\n"
    );

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n\
         export ZONE=$(firewall-cmd --get-default-zone)\n\
         export PORTHOLE_STATE_FILE=/tmp/porthole-seeded.json\n\
         # A rich rule the user added by hand: the before/after listings must\n\
         # compare something, and this one must survive the close below.\n\
         firewall-cmd --zone=\"$ZONE\" --add-rich-rule='rule family=\"ipv4\" \
source address=\"192.168.77.0/24\" port port=\"9999\" protocol=\"tcp\" accept'\n\
         {}\n\
         {}\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block("RULES_BEFORE", "firewall-cmd --list-rich-rules"),
        with_helper(&body),
        marker_block("RULES_AFTER", "firewall-cmd --list-rich-rules"),
        marker_block("STATE_AFTER", "cat \"$PORTHOLE_STATE_FILE\""),
        marker_block(
            "ABSENT_REMOVAL",
            &format!(
                "firewall-cmd --zone=\"$ZONE\" --remove-rich-rule='{rich_rule}' \
                 2>&1; echo \"EXIT=$?\""
            )
        ),
    );

    eprintln!("== firewalld test: closing a rule the firewall does not have ==");
    let out = podman_run(FEDORA_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the firewalld phantom-close container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    let closed = extract_marker(&stdout, "CLOSE");
    assert!(
        closed.contains("EXIT=7"),
        "reconciliation must prune the record before `close_by_id`'s own \
         lookup runs, so this must report RuleNotFound: {closed}"
    );
    assert!(
        !extract_marker(&stdout, "STATE_AFTER").contains(RULE_ID),
        "the record must be pruned rather than left claiming a port is open \
         that never was: {}",
        extract_marker(&stdout, "STATE_AFTER")
    );
    assert_eq!(
        extract_marker(&stdout, "RULES_BEFORE"),
        extract_marker(&stdout, "RULES_AFTER"),
        "nothing about the firewall's own rules may change"
    );
    let absent = extract_marker(&stdout, "ABSENT_REMOVAL");
    assert!(
        absent.contains("NOT_ENABLED"),
        "this is what makes exit 7 above mean something: a removal that had \
         been attempted would have been reported as an already-absent rule, \
         and `close_by_id` would have exited 0. If firewalld stops answering \
         that way, the assertion above stops discriminating: {absent}"
    );
}

// ---------------------------------------------------------------------------
// Step 4: dry-run is byte-identical to reality, on all three backends.
// ---------------------------------------------------------------------------

/// Parses one `porthole --dry-run open --json` object out of `json_text` and
/// returns `(rule id, commands)`.
fn parse_dry_run_open(json_text: &str) -> (String, Vec<String>) {
    let json: serde_json::Value = serde_json::from_str(json_text)
        .unwrap_or_else(|e| panic!("not one JSON object: {e}\n{json_text}"));
    assert_eq!(
        json["dry_run"], true,
        "must report itself as a dry run: {json}"
    );
    let id = json["rule"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no rule.id in {json}"))
        .to_string();
    let commands = json["commands"]
        .as_array()
        .unwrap_or_else(|| panic!("no commands array in {json}"))
        .iter()
        .map(|c| c.as_str().unwrap_or_default().to_string())
        .collect();
    (id, commands)
}

/// A dry-run that prints a command different from the one the backend would
/// really run is worse than no dry-run at all, because it is trusted. Every
/// dry-run test below therefore checks two things porthole's own withheld
/// `--dry-run` machinery cannot check about itself: that the firewall's own
/// rule listing is byte-for-byte unchanged, and that the printed command is
/// the *exact* argv (as `Command::display()` renders it) the real backend
/// code in `backend/{ufw,firewalld,nftables}.rs` would have issued for this
/// same request -- reusing the same id `--dry-run` minted for the rule
/// itself as proof the two are talking about the same, single, would-be
/// mutation.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn dry_run_is_byte_identical_to_reality_on_ufw() {
    require_environment!();
    let (cli, _helper) = require_musl_binaries!();
    ensure_image(DEBIAN_IMAGE, "Containerfile.debian");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(bind_ro(&cli, "/usr/local/bin/porthole"));

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\nufw --force enable\n\
         # A pre-existing rule so BEFORE/AFTER compare something, not two\n\
         # empty listings -- an empty-to-empty comparison would pass even if\n\
         # --dry-run silently cleared the rule list.\n\
         ufw allow 2222/tcp comment 'not-porthole'\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block("BEFORE", "ufw status numbered"),
        marker_block(
            "DRYRUN_JSON",
            "porthole --dry-run open 5173 --for 5m --json"
        ),
        marker_block("AFTER", "ufw status numbered"),
    );

    eprintln!("== ufw dry-run test ==");
    let out = podman_run(DEBIAN_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the ufw dry-run container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let before = extract_marker(&stdout, "BEFORE");
    let after = extract_marker(&stdout, "AFTER");
    assert_eq!(
        before, after,
        "--dry-run must change nothing about ufw's own rule list"
    );

    let (id, commands) = parse_dry_run_open(extract_marker(&stdout, "DRYRUN_JSON"));
    assert_eq!(
        commands[0],
        format!("ufw allow from 10.10.10.0/24 to any port 5173 proto tcp comment porthole:{id}"),
        "the printed command must be exactly what Ufw::open_impl would run for real"
    );
}

#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn dry_run_is_byte_identical_to_reality_on_firewalld() {
    require_environment!();
    let (cli, _helper) = require_musl_binaries!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(bind_ro(&cli, "/usr/local/bin/porthole"));

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n\
         ZONE=$(firewall-cmd --get-default-zone)\n\
         {}\n\
         # A pre-existing rule so BEFORE/AFTER compare something, not two\n\
         # empty listings.\n\
         firewall-cmd --zone=\"$ZONE\" --add-rich-rule='rule family=\"ipv4\" \
source address=\"192.168.77.0/24\" port port=\"9999\" protocol=\"tcp\" accept'\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block("ZONE", "echo \"$ZONE\""),
        marker_block("BEFORE", "firewall-cmd --list-rich-rules"),
        marker_block(
            "DRYRUN_JSON",
            "porthole --dry-run open 5173 --for 5m --json"
        ),
        marker_block("AFTER", "firewall-cmd --list-rich-rules"),
    );

    eprintln!("== firewalld dry-run test ==");
    let out = podman_run(FEDORA_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the firewalld dry-run container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let zone = extract_marker(&stdout, "ZONE");
    let before = extract_marker(&stdout, "BEFORE");
    let after = extract_marker(&stdout, "AFTER");
    assert_eq!(
        before, after,
        "--dry-run must change nothing about firewalld's own rich rules"
    );

    let (_id, commands) = parse_dry_run_open(extract_marker(&stdout, "DRYRUN_JSON"));
    assert_eq!(
        commands[0],
        format!(
            "firewall-cmd --zone={zone} '--add-rich-rule=rule family=\"ipv4\" \
             source address=\"10.10.10.0/24\" port port=\"5173\" protocol=\"tcp\" accept'"
        ),
        "the printed command must be exactly what Firewalld::open would run for real"
    );
}

#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn dry_run_is_byte_identical_to_reality_on_nftables() {
    require_environment!();
    let (cli, _helper) = require_musl_binaries!();
    ensure_image(ARCH_IMAGE, "Containerfile.arch");

    let mut args: Vec<String> =
        vec!["--cap-add=NET_ADMIN,NET_RAW,SYS_ADMIN,SYS_PTRACE".to_string()];
    args.extend(bind_ro(&cli, "/usr/local/bin/porthole"));

    // Built as a joined `Vec<String>` rather than one `format!` template: the
    // nft chain literal below carries its own `{` `}`, and escaping them as
    // `{{`/`}}` inside a growing format! string is exactly the kind of thing
    // that is easy to get wrong silently (as `format!`'s own brace escaping
    // has no way to tell "a literal brace" from "a mistyped placeholder").
    let ruleset_setup = "\
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input iif lo accept";

    let script = [
        "set -e".to_string(),
        ruleset_setup.to_string(),
        marker_block("BEFORE", "nft -a list ruleset"),
        marker_block(
            "DRYRUN_JSON",
            "porthole --dry-run open 5173 --to 10.10.10.0/24 --for 5m --json",
        ),
        marker_block("AFTER", "nft -a list ruleset"),
        // Bug #1 of the three named in this file's own module doc comment
        // was an emitted `nft` command that could not be parsed *at all* --
        // and the hardcoded expected string asserted below, written by the
        // same author who wrote the code it is checked against, is a
        // restatement of an understanding, not independent evidence of
        // anything. Feed the actual printed command back through `nft -c`
        // (check mode: parses and validates against the real ruleset this
        // container already has, changes nothing) so a real parser, not this
        // test's author, is the one who says it is valid.
        "DRYRUN_TEXT=$(porthole --dry-run open 5173 --to 10.10.10.0/24 --for 5m)".to_string(),
        "NFT_LINE=$(echo \"$DRYRUN_TEXT\" | grep '^  nft ' | sed 's/^  //')".to_string(),
        "CHECK_LINE=$(echo \"$NFT_LINE\" | sed 's/^nft /nft -c /')".to_string(),
        marker_block(
            "NFT_CHECK",
            "eval \"$CHECK_LINE\" && echo PARSED || echo FAILED",
        ),
    ]
    .join("\n");

    eprintln!("== nftables dry-run test ==");
    let out = podman_run(ARCH_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the nftables dry-run container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let before = extract_marker(&stdout, "BEFORE");
    let after = extract_marker(&stdout, "AFTER");
    assert_eq!(
        before, after,
        "--dry-run must change nothing about the nftables ruleset, handles included"
    );

    let (id, commands) = parse_dry_run_open(extract_marker(&stdout, "DRYRUN_JSON"));
    assert_eq!(
        commands[0],
        format!(
            "nft insert rule inet filter input tcp dport 5173 ip saddr 10.10.10.0/24 \
             accept comment '\"porthole:{id}\"'"
        ),
        "the printed command must be exactly what Nftables::open_impl would run for \
         real, quotes included -- see the module docs on why the marker must carry \
         literal double-quote characters"
    );

    let nft_check = extract_marker(&stdout, "NFT_CHECK");
    assert_eq!(
        nft_check, "PARSED",
        "the printed nft command must parse under a real `nft -c`, not merely \
         match a hand-written expected string above: {nft_check}"
    );
}

// ---------------------------------------------------------------------------
// What firewalld makes of the rich rule a forward writes.
// ---------------------------------------------------------------------------

/// Every `chain <name> { ... }` block in one `nft list table` dump, as
/// `(name, body)`.
///
/// A chain's body ends at the first line that is a lone tab-indented `}` --
/// the shape `nft` prints for a table's direct children, and firewalld's
/// chains are all direct children of `table inet firewalld`.
fn nft_chains(ruleset: &str) -> Vec<(String, String)> {
    let mut chains = Vec::new();
    let mut rest = ruleset;
    while let Some(at) = rest.find("chain ") {
        let after = &rest[at + "chain ".len()..];
        let Some(brace) = after.find(" {") else { break };
        let name = after[..brace].trim().to_string();
        let body = &after[brace + 2..];
        let Some(end) = body.find("\n\t}") else { break };
        chains.push((name, body[..end].to_string()));
        rest = &body[end..];
    }
    chains
}

/// How a real firewalld renders the redirect rich rule porthole writes:
/// read out of the kernel's own ruleset, not out of the commands issued.
///
/// **This is not what keeps the permit from coming back.** It hand-issues
/// the redirect string and never calls `Firewalld::forward`, so reinstating
/// the permit inside that function leaves this passing. The guard for that
/// is `backend/firewalld.rs`'s
/// `a_forward_writes_no_accept_for_the_external_port`, which asserts the
/// accept `open` writes is absent from every command a forward issues, and
/// which fails when the permit is put back.
///
/// What this establishes instead, and what no unit test can: that the rule
/// porthole writes renders to a dnat and to nothing in the zone's filter
/// path. A unit test can only ever assert the string firewalld was handed;
/// the question of what firewalld makes of it -- whether a `forward-port`
/// rich rule also emits an accept somewhere -- is answerable only against a
/// real one, and the answer is what the decision to write a single rule
/// rests on.
///
/// Two things are asserted about the same real ruleset, and the second is
/// what makes the first mean anything:
///
/// 1. With the redirect in the zone, no `filter_IN_*` chain has a rule for
///    the external port, and one rule names the container: a dnat in
///    `nat_PRE_<zone>_allow`.
/// 2. Adding the accept `open` writes puts a rule for that port in exactly
///    such a chain. Without this control, assertion 1 would pass just as
///    well if `nft_chains` found no chains at all, if firewalld had renamed
///    its filter chains, or if the rule had simply failed to be added.
///
/// What this does **not** assert: that a forward works. No packet is sent
/// here, and reachability is a separate test with a separate topology.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn a_redirect_rich_rule_renders_to_a_dnat_and_no_filter_rule() {
    use porthole_core::backend::firewalld::Firewalld;
    use porthole_core::forward::ForwardTo;
    use porthole_core::model::{Lifetime, OpenRequest, Protocol, Target};

    require_environment!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let req = OpenRequest {
        port: 3000,
        protocol: Protocol::Tcp,
        target: Target::Network {
            cidr: "10.10.10.0/24".parse().unwrap(),
        },
        lifetime: Lifetime::UntilReboot,
    };
    let to = ForwardTo {
        container_addr: std::net::Ipv4Addr::new(172, 18, 0, 2),
        container_port: 8080,
        published_port: 3000,
        protocol: Protocol::Tcp,
    };
    // Both strings come from the backend itself. A retyped copy would go on
    // passing after the code that builds them changed.
    let redirect = Firewalld::forward_rich_rule(&req, &to, Protocol::Tcp);
    let accept = Firewalld::rich_rule(&req);

    let args = vec!["--cap-add=NET_ADMIN".to_string()];
    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n\
         ZONE=$(firewall-cmd --get-default-zone)\n\
         firewall-cmd --zone=\"$ZONE\" '--add-rich-rule={redirect}'\n\
         {}\n\
         firewall-cmd --zone=\"$ZONE\" '--add-rich-rule={accept}'\n\
         {}\n",
        marker_block("REDIRECT_ONLY", "nft list table inet firewalld"),
        marker_block("WITH_ACCEPT", "nft list table inet firewalld"),
    );

    eprintln!("== firewalld test: what the redirect rich rule renders to ==");
    let out = podman_run(FEDORA_IMAGE, &args, &script);
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert_container_ok(&out, "the firewalld rendering container");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let redirect_only = nft_chains(extract_marker(&stdout, "REDIRECT_ONLY"));
    let with_accept = nft_chains(extract_marker(&stdout, "WITH_ACCEPT"));

    let filtering_the_port = |chains: &[(String, String)]| -> Vec<String> {
        chains
            .iter()
            .filter(|(name, body)| name.starts_with("filter_IN") && body.contains("dport 3000"))
            .map(|(name, _)| name.clone())
            .collect()
    };

    // The redirect itself: one dnat, in a nat chain, naming the container.
    let dnat: Vec<&String> = redirect_only
        .iter()
        .filter(|(_, body)| body.contains("172.18.0.2:8080"))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        dnat.len(),
        1,
        "the redirect renders to one rule; chains naming the container: {dnat:?}"
    );
    assert!(
        dnat[0].starts_with("nat_PRE"),
        "the redirect must be in a nat prerouting chain, not {}",
        dnat[0]
    );

    assert!(
        filtering_the_port(&redirect_only).is_empty(),
        "the redirect put a rule for the external port in a filter chain: {:?}\n{}",
        filtering_the_port(&redirect_only),
        extract_marker(&stdout, "REDIRECT_ONLY"),
    );

    // The rule this design now rests on, in firewalld's own rendering:
    // `filter_FORWARD` accepts DNAT'd traffic ahead of the jump to any zone
    // chain. That it is what the redirected connection travels through was
    // measured elsewhere with packet counters -- zero at the input hook, and
    // the connection still completing with the zone's target set to DROP.
    // All that is asserted here is that the rule exists, so that a firewalld
    // release dropping it fails loudly rather than turning every forward
    // into a redirect nothing lets through.
    let forward_chain = redirect_only
        .iter()
        .find(|(name, _)| name == "filter_FORWARD")
        .map(|(_, body)| body.clone())
        .unwrap_or_else(|| {
            panic!(
                "firewalld has no filter_FORWARD chain; chains: {:?}",
                redirect_only.iter().map(|(n, _)| n).collect::<Vec<_>>()
            )
        });
    assert!(
        forward_chain.contains("ct status dnat accept"),
        "filter_FORWARD no longer accepts DNAT'd traffic, which is what a forward \
         relies on here: {forward_chain}"
    );

    // The control: such a rule is visible here when it exists.
    assert!(
        !filtering_the_port(&with_accept).is_empty(),
        "the accept `open` writes did not show up in any filter_IN chain, so the \
         assertion above proves nothing about where rules land:\n{}",
        extract_marker(&stdout, "WITH_ACCEPT"),
    );
}

// ---------------------------------------------------------------------------
// `porthole forward` against a real firewalld and a real Docker.
// ---------------------------------------------------------------------------
//
// Six of the eight tests below need a Docker daemon: `porthole_core::docker`
// reads the `DOCKER` chain of iptables' `nat` table and nothing else, so the
// only way to exercise it against anything but a captured fixture is to have
// a daemon write that chain. `Containerfile.docker` carries Docker 29.8.0
// from Docker's own repository -- the version this project's development host
// runs -- alongside the same firewalld the other Fedora tests use.
//
// The remaining two need no Docker at all, and that is the point of them:
// `Engine::forward` asks `FirewallBackend::forward_capability` before it
// reads anything, so on ufw and on nftables the refusal happens with Docker
// never consulted.

/// The LAN these tests forward towards, and the client that connects over it.
///
/// **The router side is deliberately named `eth0`.** It is a veth, but
/// `porthole_core::net::default_route_interface` filters by interface *name*
/// -- `veth*`, `docker*`, `br-*` and the rest are excluded -- and
/// `Firewalld::managed_zone` needs a default route on an interface that
/// survives that filter. Measured: with the pair named `veth0`/`veth1`, as
/// [`NFT_RULESET_AND_NETNS_SETUP`] names its own, every porthole command in
/// this container fails with exit 8, "no default route on a physical
/// interface". The nftables tests do not hit this because that backend finds
/// its chain instead of asking which interface carries the route.
///
/// The default route points at the client, which never answers it. Nothing
/// here needs a working gateway: it is there so `net` can resolve a subnet,
/// exactly as [`FAKE_LAN_INTERFACE`]'s own fabricated gateway is.
///
/// `ip netns` does not work in rootless podman, so the client is
/// `unshare --net` plus `nsenter -t <pid> -n`, the same technique
/// [`NFT_RULESET_AND_NETNS_SETUP`] uses.
///
/// The `mount -t proc proc /proc` is not decoration. podman masks parts of
/// `/proc` read-only, and Docker cannot bring up a container's own interface
/// without writing `net.ipv6.conf.<iface>.disable_ipv6`: measured, without
/// this line every `docker run` here fails with `failed to configure ipv6`.
const DOCKER_LAN_SETUP: &str = r#"
set -e
mount -t proc proc /proc

ip link add eth0 type veth peer name lan1
ip addr add 10.10.10.1/24 dev eth0
ip link set eth0 up
ip link set lo up
ip route add default via 10.10.10.42 dev eth0

unshare --net sleep 3000 &
PEER_PID=$!
sleep 0.5
ip link set lan1 netns "$PEER_PID"
nsenter -t "$PEER_PID" -n ip addr add 10.10.10.42/24 dev lan1
nsenter -t "$PEER_PID" -n ip link set lan1 up
nsenter -t "$PEER_PID" -n ip link set lo up

# The client's own request, from its own network namespace. It asks for a
# body rather than a bare TCP connect: the body is the container's, so a
# connection answered by anything else on this machine cannot satisfy it.
client_get() {
  nsenter -t "$PEER_PID" -n curl -sS --max-time 4 "http://10.10.10.1:$1/" 2>/dev/null \
    || echo CLIENT_UNREACHABLE
}
# `with_helper` writes its body to a file and runs it under `dbus-run-session
# -- bash`, which is a *different* bash: a function defined here is not in it
# unless it is exported. Same for PEER_PID.
export PEER_PID
export -f client_get
"#;

/// Start `dockerd` and build, offline, the one image these tests run.
///
/// Every container in this file is `--network=none`, so the Docker daemon
/// inside one can pull nothing. `docker import` of a tarball needs no
/// registry: the tarball's only executable is Fedora's statically linked
/// `busybox`, and `busybox httpd` serves one file whose contents are the
/// evidence a client is really talking to the container.
const DOCKER_DAEMON_SETUP: &str = r#"
dockerd >/tmp/dockerd.log 2>&1 &
docker_ready=0
for i in $(seq 1 120); do
  if docker info >/dev/null 2>&1; then
    docker_ready=1
    break
  fi
  sleep 1
done
if [ "$docker_ready" != 1 ]; then
  echo "DOCKERD_NEVER_READY" >&2
  tail -50 /tmp/dockerd.log >&2
  exit 94
fi

# The image deliberately does not pin a Docker version -- see
# `Containerfile.docker` for why -- so the version is an input nobody
# declared. Printing it makes every run's output name the Docker it actually
# got, so a failure that turns out to be "Docker changed the DOCKER chain"
# says which Docker rather than leaving it to be guessed at. `report` echoes
# this whole stream on success and on failure alike.
echo "PORTHOLE_TEST_DOCKER_VERSION=$(docker version --format '{{.Server.Version}}')"

mkdir -p /img/bin /img/www
cp /usr/sbin/busybox /img/bin/busybox
echo 'PORTHOLE-TARGET-OK' > /img/www/index.html
tar -C /img -c . | docker import - porthole-target >/dev/null

# One place that knows how the target is run, so the two tests that restart
# it cannot drift from the four that do not. $1 is extra `docker run` flags.
start_target() {
  docker run -d --name target $1 -p 127.0.0.1:3000:8080 porthole-target \
    /bin/busybox httpd -f -p 8080 -h /www >/dev/null
  # Give httpd a moment to bind. Not a guess about the daemon: `docker run`
  # has already returned, so this waits only for the process inside.
  for i in $(seq 1 50); do
    if curl -sS --max-time 2 http://127.0.0.1:3000/ >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "TARGET_NEVER_ANSWERED_ON_LOOPBACK" >&2
  docker logs target >&2 || true
  exit 93
}
export -f start_target
"#;

/// A rich rule the user added by hand, so every before/after listing compares
/// two non-empty listings rather than two empty ones, and so that "porthole
/// removed its own rule" can be told apart from "porthole flushed the zone".
const USERS_OWN_RICH_RULE: &str = "firewall-cmd --add-rich-rule='rule family=\"ipv4\" \
source address=\"192.168.77.0/24\" port port=\"9999\" protocol=\"tcp\" accept'";

/// The lines of `firewall-cmd --list-rich-rules` that are not the user's own
/// rule from [`USERS_OWN_RICH_RULE`].
fn porthole_rich_rules(listing: &str) -> Vec<&str> {
    listing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains(r#"port="9999""#))
        .collect()
}

/// Build the Docker image and start a systemd container of it, with the
/// binaries bound in. `extra` is inserted before the image name.
fn docker_container(name: &str, cli: &Path, helper: &Path, extra: &[String]) -> SystemdContainer {
    ensure_image(DOCKER_IMAGE, "Containerfile.docker");
    let mut args = cli_mounts(cli, helper);
    args.extend(extra.iter().cloned());
    SystemdContainer::start(name, DOCKER_IMAGE, &args)
}

fn report(out: &Output, what: &str) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    eprintln!("{stdout}");
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    // Repeated on its own line, after the dump, so it is the last thing
    // before the panic message rather than one line inside several hundred.
    // See `DOCKER_DAEMON_SETUP` for why the version is worth naming at all.
    if let Some(rest) = stdout.split("PORTHOLE_TEST_DOCKER_VERSION=").nth(1) {
        eprintln!(
            "== this container's Docker: {} ==",
            rest.lines().next().unwrap_or("?").trim()
        );
    }
    assert_container_ok(out, what);
    stdout
}

/// A forward is **one** rich rule -- the `forward-port` redirect -- and
/// closing it takes exactly that one rule back out.
///
/// The design this asserts was settled by measurement, not by reading
/// firewalld's documentation: an accept for the external port beside the
/// redirect carries none of the forwarded traffic (zero packets at the input
/// hook, with and without it, byte-identical counters) and *is* a working
/// accept for something else -- with a service of the host's own bound to
/// `0.0.0.0:<external>`, that accept alone makes the host's own service
/// reachable from the LAN. So porthole writes one rule, and this is the test
/// that fails if a second ever appears.
///
/// What this can prove that `backend/firewalld.rs`'s own
/// `a_forward_is_one_rule_and_its_handle_is_that_rule` cannot: that unit test
/// counts the `--add-rich-rule` invocations porthole *issued* against a
/// `RecordingRunner`. This counts the rules a real firewalld is *holding*
/// afterwards, which is a different claim -- firewalld normalises what it is
/// given, and a single `forward-port` rich rule could in principle have
/// become two lines in the zone.
///
/// The expected rule string is built by `Firewalld::forward_rich_rule`
/// itself, from the container address read out of the running Docker, rather
/// than retyped here: a retyped copy goes on passing after the code that
/// builds it changes.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn a_forward_is_one_rich_rule_and_closing_takes_exactly_it_back_out() {
    use porthole_core::backend::firewalld::Firewalld;
    use porthole_core::forward::ForwardTo;
    use porthole_core::model::{Lifetime, OpenRequest, Protocol, Target};

    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    let container = docker_container("porthole-container-test-forward-rule", &cli, &helper, &[]);

    let body = format!(
        "porthole --session forward 3000 --to 10.10.10.0/24 --for 15m\n{}\n{}\n\
         porthole --session close 3000\n",
        marker_block("RULES_WHILE_FORWARDED", "firewall-cmd --list-rich-rules"),
        marker_block("LIST_WHILE_FORWARDED", "porthole --session list --json"),
    );

    let script = format!(
        "{DOCKER_LAN_SETUP}\n{FIREWALLD_DAEMON_SETUP}\n{DOCKER_DAEMON_SETUP}\n\
         start_target ''\n\
         {USERS_OWN_RICH_RULE}\n\
         {}\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block(
            "CONTAINER_ADDR",
            "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' target"
        ),
        marker_block("RULES_BEFORE", "firewall-cmd --list-rich-rules"),
        with_helper(&body),
        marker_block("RULES_AFTER_CLOSE", "firewall-cmd --list-rich-rules"),
    );

    eprintln!("== forward test: one rich rule, and closing removes exactly it ==");
    let stdout = report(&container.exec(&script), "the forward rich-rule container");

    let addr: std::net::Ipv4Addr = extract_marker(&stdout, "CONTAINER_ADDR")
        .parse()
        .unwrap_or_else(|e| {
            panic!(
                "Docker reported no address for the target container ({e}): {:?}",
                extract_marker(&stdout, "CONTAINER_ADDR")
            )
        });

    let before = porthole_rich_rules(extract_marker(&stdout, "RULES_BEFORE"));
    assert!(
        before.is_empty(),
        "nothing but the user's own rule may be in the zone before the forward: {before:?}"
    );

    let while_forwarded = extract_marker(&stdout, "RULES_WHILE_FORWARDED");
    let ours = porthole_rich_rules(while_forwarded);
    // The assertion the whole design rests on. Two rules here -- a redirect
    // and a permit -- is the shape a spike measured to expose the *host's*
    // own service on the external port.
    assert_eq!(
        ours.len(),
        1,
        "a forward is one rich rule; firewalld is holding {}: {while_forwarded}",
        ours.len()
    );

    let expected = Firewalld::forward_rich_rule(
        &OpenRequest {
            port: 3000,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            lifetime: Lifetime::For(std::time::Duration::from_secs(900)),
        },
        &ForwardTo {
            container_addr: addr,
            container_port: 8080,
            published_port: 3000,
            protocol: Protocol::Tcp,
        },
        Protocol::Tcp,
    );
    assert_eq!(
        ours[0], expected,
        "the rule firewalld is holding must be the one Firewalld::forward_rich_rule builds"
    );
    assert!(
        !ours[0].contains("accept"),
        "a forward wrote an accept for the external port: {}",
        ours[0]
    );
    assert!(
        while_forwarded.contains(r#"port="9999""#),
        "the user's own rule must still be there: {while_forwarded}"
    );

    let listed = extract_marker(&stdout, "LIST_WHILE_FORWARDED");
    assert!(
        listed.contains(r#""port":3000"#)
            && listed.contains(&format!(r#""container_addr":"{addr}""#)),
        "porthole must name the forward it made, container address and all: {listed}"
    );

    let after = extract_marker(&stdout, "RULES_AFTER_CLOSE");
    assert!(
        porthole_rich_rules(after).is_empty(),
        "the close must take the redirect back out: {after}"
    );
    assert!(
        after.contains(r#"port="9999""#),
        "and must leave the user's own rule where it was: {after}"
    );
}

/// A client on the local network reaches the container **through** the
/// forward, and stops reaching it when the forward closes.
///
/// The container is published on `127.0.0.1` only, so nothing outside this
/// machine can reach it: that is the situation `porthole forward` exists for,
/// and phase 1 below is the proof it holds before porthole does anything.
///
/// **Three things are asserted, and the third is what the spike asked for.**
///
/// 1. The client gets the container's own body, not merely a TCP connect. A
///    connect-only check would pass against anything at all listening on the
///    external port.
/// 2. Reachability really begins with the forward and ends with the close.
/// 3. The traffic travels the **forward** path, not the input path. A
///    counter-only table of this test's own (`inet probe`, at hook priority
///    -400 in both directions -- firewalld's own table carries
///    `flags owner,persist` and cannot be written into) counts packets at
///    each hook. Before the forward, the client's SYN is counted at the
///    *input* hook and nothing at the forward hook; with the forward, the
///    DNAT has already happened in prerouting, so the input hook counts
///    **zero** and the forward hook counts the connection. That asymmetry is
///    the whole reason porthole writes no accept for the external port, and
///    this is what fails loudly if a firewalld release ever stops accepting
///    DNAT'd traffic in `filter_FORWARD`.
///
/// Phase 1's non-zero input counter is the control: without it, "input == 0"
/// in phase 2 would be satisfied just as well by a probe table that counts
/// nothing at all.
///
/// **Phase 4 is `--as`, and it is the half of this command that had no test
/// anywhere.** `porthole forward 3000 --as 4000` gives the local network
/// **4000** while Docker published **3000**, and until this phase existed no
/// test at any level asserted what rule is written when those two differ: the
/// host test for `--as` checks two JSON fields that both come from the
/// `OpenRequest` and never the rule; every fixture in `backend/firewalld.rs`
/// used `published_port == req.port`; and phases 1-3 above forward 3000 to a
/// container published as 3000. A confusion between `req.port` and
/// `to.published_port` inside `forward_rich_rule` would have passed the whole
/// workspace. `a_forward_writes_the_external_port_not_the_published_one` is
/// the unit half of that repair -- measured: with the two swapped, every one
/// of the twenty pre-existing forward tests still passed and only the new
/// fixtures failed -- and this is the half that shows a real packet arriving.
///
/// Three things are asserted about it, and the second is the security-
/// relevant one:
///
/// 1. The LAN reaches the container **on 4000**, and gets the container's own
///    body there.
/// 2. The LAN still **cannot** reach **3000**. A forward given `--as` must
///    move the exposure, not add to it -- and nothing asserted that before.
/// 3. `porthole close 4000` (the external port, not the published one) is
///    what closes it, and the rule firewalld held was the one
///    `Firewalld::forward_rich_rule` builds for the differing pair.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn the_lan_reaches_the_container_through_the_forward_hook_and_only_on_the_port_it_was_given() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    let container = docker_container("porthole-container-test-forward-reach", &cli, &helper, &[]);

    // Rebuilt between the phases rather than reset: `nft` spells a rule
    // counter reset differently across releases, and deleting the table is
    // unambiguous in every one of them.
    let probe = "\
nft add table inet probe
nft 'add chain inet probe pin { type filter hook input priority -400; }'
nft 'add chain inet probe pfwd { type filter hook forward priority -400; }'
nft add rule inet probe pin tcp dport 3000 counter
nft add rule inet probe pfwd ct status dnat counter";

    let body = format!(
        "{}\n\
         nft delete table inet probe\n{probe}\n\
         porthole --session forward 3000 --to 10.10.10.0/24 --for 15m\n\
         {}\n\
         {}\n\
         porthole --session close 3000\n\
         {}\n\
         {}\n\
         # --- phase 4: the same container, given a different external port ---\n\
         porthole --session forward 3000 --as 4000 --to 10.10.10.0/24 --for 15m\n\
         {}\n\
         {}\n\
         {}\n\
         {}\n\
         porthole --session close 4000\n\
         {}\n\
         {}\n",
        marker_block("PROBE_BEFORE", "nft list table inet probe"),
        marker_block("PHASE2_CLIENT", "client_get 3000"),
        marker_block("PROBE_WHILE", "nft list table inet probe"),
        marker_block("PHASE3_CLIENT", "client_get 3000"),
        marker_block(
            "LOOPBACK_AFTER_CLOSE",
            "curl -sS --max-time 4 http://127.0.0.1:3000/ || echo LOOPBACK_BROKEN"
        ),
        marker_block("AS_RULES", "firewall-cmd --list-rich-rules"),
        marker_block("AS_LIST", "porthole --session list --json"),
        marker_block("AS_EXTERNAL", "client_get 4000"),
        marker_block("AS_PUBLISHED", "client_get 3000"),
        marker_block("AS_AFTER_CLOSE", "client_get 4000"),
        marker_block("AS_RULES_AFTER_CLOSE", "firewall-cmd --list-rich-rules"),
    );

    let script = format!(
        "{DOCKER_LAN_SETUP}\n{FIREWALLD_DAEMON_SETUP}\n{DOCKER_DAEMON_SETUP}\n\
         start_target ''\n{probe}\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block(
            "CONTAINER_ADDR",
            "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' target"
        ),
        marker_block("PHASE1_CLIENT", "client_get 3000"),
        with_helper(&body),
    );

    eprintln!("== forward test: the LAN reaches the container, through the forward hook ==");
    let stdout = report(
        &container.exec(&script),
        "the forward reachability container",
    );

    assert_eq!(
        extract_marker(&stdout, "PHASE1_CLIENT"),
        "CLIENT_UNREACHABLE",
        "a container published on loopback must not be reachable from the LAN before \
         porthole forwards anything -- otherwise phase 2 proves nothing"
    );
    assert_eq!(
        extract_marker(&stdout, "PHASE2_CLIENT"),
        "PORTHOLE-TARGET-OK",
        "the client must get the container's own body through the forward"
    );
    assert_eq!(
        extract_marker(&stdout, "PHASE3_CLIENT"),
        "CLIENT_UNREACHABLE",
        "closing the forward must take the LAN's access away again"
    );
    assert_eq!(
        extract_marker(&stdout, "LOOPBACK_AFTER_CLOSE"),
        "PORTHOLE-TARGET-OK",
        "closing a forward must not disturb Docker's own publication on loopback"
    );

    let (input_before, forward_before) = probe_counters(extract_marker(&stdout, "PROBE_BEFORE"));
    let (input_while, forward_while) = probe_counters(extract_marker(&stdout, "PROBE_WHILE"));

    // The control: the probe can count, and an un-forwarded connection to the
    // external port really does arrive at the input hook.
    assert!(
        input_before > 0,
        "the probe counted nothing at the input hook for a refused connection, so \
         `input == 0` below would prove nothing: {}",
        extract_marker(&stdout, "PROBE_BEFORE")
    );
    assert_eq!(
        forward_before,
        0,
        "nothing was DNAT'd before the forward existed: {}",
        extract_marker(&stdout, "PROBE_BEFORE")
    );

    // The assertion the design rests on.
    assert_eq!(
        input_while,
        0,
        "the forwarded connection reached the input hook, so an accept in a zone's \
         input chain would after all be part of what carries it -- which is the claim \
         porthole's one-rule forward denies: {}",
        extract_marker(&stdout, "PROBE_WHILE")
    );
    assert!(
        forward_while > 0,
        "the forwarded connection was counted at neither hook: {}",
        extract_marker(&stdout, "PROBE_WHILE")
    );

    // --- phase 4: `--as`, where the two port numbers finally differ ---

    let addr: std::net::Ipv4Addr = extract_marker(&stdout, "CONTAINER_ADDR")
        .parse()
        .unwrap_or_else(|e| {
            panic!(
                "Docker reported no address for the target container ({e}): {:?}",
                extract_marker(&stdout, "CONTAINER_ADDR")
            )
        });

    assert_eq!(
        extract_marker(&stdout, "AS_EXTERNAL"),
        "PORTHOLE-TARGET-OK",
        "`--as 4000` must make the container answer on 4000 -- and this is a real \
         packet arriving, not a rule that merely reads right"
    );
    // The security-relevant half. A forward given `--as` moves the exposure;
    // it does not add to it. Before this, nothing anywhere asserted that the
    // published port stays unreachable while the redirect is live on another.
    assert_eq!(
        extract_marker(&stdout, "AS_PUBLISHED"),
        "CLIENT_UNREACHABLE",
        "the published port must stay unreachable from the LAN while the forward is \
         live on a different one -- `--as` moves the exposure, it does not widen it"
    );

    // The same technique the one-rule test uses: the expected string comes
    // from the backend, so it cannot be a retyped copy that goes on passing
    // after the code changes. With external 4000, published 3000 and
    // container 8080, all three numbers are distinct -- which is what makes
    // this compare anything at all.
    let expected_as = {
        use porthole_core::backend::firewalld::Firewalld;
        use porthole_core::forward::ForwardTo;
        use porthole_core::model::{Lifetime, OpenRequest, Protocol, Target};
        Firewalld::forward_rich_rule(
            &OpenRequest {
                port: 4000,
                protocol: Protocol::Tcp,
                target: Target::Network {
                    cidr: "10.10.10.0/24".parse().unwrap(),
                },
                lifetime: Lifetime::For(std::time::Duration::from_secs(900)),
            },
            &ForwardTo {
                container_addr: addr,
                container_port: 8080,
                published_port: 3000,
                protocol: Protocol::Tcp,
            },
            Protocol::Tcp,
        )
    };
    let as_rules = extract_marker(&stdout, "AS_RULES");
    let ours_as = porthole_rich_rules(as_rules);
    assert_eq!(
        ours_as.len(),
        1,
        "a forward with `--as` is still one rich rule: {as_rules}"
    );
    assert_eq!(
        ours_as[0], expected_as,
        "the rule firewalld is holding must name the external port it matches and the \
         container port it sends to -- and the published port nowhere"
    );

    let as_list = extract_marker(&stdout, "AS_LIST");
    assert!(
        as_list.contains(r#""port":4000"#) && as_list.contains(r#""published_port":3000"#),
        "`list --json` must carry both numbers, so a person can tell which is which: \
         {as_list}"
    );

    assert_eq!(
        extract_marker(&stdout, "AS_AFTER_CLOSE"),
        "CLIENT_UNREACHABLE",
        "`close 4000` -- the external port, not the published one -- must be what ends it"
    );
    assert!(
        porthole_rich_rules(extract_marker(&stdout, "AS_RULES_AFTER_CLOSE")).is_empty(),
        "and it must take the redirect out of firewalld: {}",
        extract_marker(&stdout, "AS_RULES_AFTER_CLOSE")
    );
}

/// `(input hook packets, forward hook packets)` out of one `nft list table
/// inet probe` dump.
///
/// Each chain holds exactly one rule and that rule ends in `counter packets N
/// bytes M`, so the two numbers are read positionally within each chain's own
/// body rather than by matching the whole rule text.
fn probe_counters(dump: &str) -> (u64, u64) {
    fn packets(chains: &[(String, String)], name: &str, dump: &str) -> u64 {
        let body = chains
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b.clone())
            .unwrap_or_else(|| panic!("no chain {name} in the probe table:\n{dump}"));
        let after = body
            .split("counter packets ")
            .nth(1)
            .unwrap_or_else(|| panic!("chain {name} has no counter:\n{dump}"));
        after
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("chain {name}'s counter is unreadable:\n{dump}"))
    }
    let chains = nft_chains(dump);
    (
        packets(&chains, "pin", dump),
        packets(&chains, "pfwd", dump),
    )
}

/// A container that stops closes the forward that pointed at it, with the
/// reason `target-gone` and no other.
///
/// The wake-up is `porthole_helper::netmon`'s own poll, whose interval is a
/// production constant (60s) a test may not shorten -- which is why this test
/// takes over two and a half minutes. `-e PORTHOLE_NETMON=1` is what lets the
/// monitor run under `--session` at all; see `netmon::should_run`.
///
/// **The first wait is the control.** One whole poll passes with the
/// container still running, and the forward has to still be there afterwards.
/// Without it, "the rule is gone after 140 seconds" would be satisfied by a
/// helper that closed every forward on its first wake-up regardless.
///
/// A `--for 15m` lifetime, so nothing in the two waits comes near expiry: an
/// expiry would close the rule too, and announce `expired` rather than
/// `target-gone`. The reason on the bus is what tells the two apart, and it
/// is asserted rather than inferred from the rule having gone.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn stopping_the_container_closes_the_forward_and_says_the_target_is_gone() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    let container = docker_container(
        "porthole-container-test-forward-gone",
        &cli,
        &helper,
        &["-e".to_string(), "PORTHOLE_NETMON=1".to_string()],
    );

    let body = format!(
        r#"
stdbuf -oL dbus-monitor --session "type='signal',interface='com.jacopobriccola.Porthole1'" \
  > /tmp/signals.txt 2>&1 &
MONPID=$!
for i in $(seq 1 100); do [ -s /tmp/signals.txt ] && break; sleep 0.1; done

porthole --session forward 3000 --to 10.10.10.0/24 --for 15m

# One whole poll interval with the container still running.
sleep 70
{}

docker stop target >/dev/null

sleep 70
{}
{}
{}
sleep 1
kill "$MONPID" 2>/dev/null || true
"#,
        marker_block("STILL_THERE", "porthole --session list --json"),
        marker_block("AFTER_STOP", "porthole --session list --json"),
        marker_block("RULES_AFTER_STOP", "firewall-cmd --list-rich-rules"),
        marker_block("CLIENT_AFTER_STOP", "client_get 3000"),
    );

    let script = format!(
        "{DOCKER_LAN_SETUP}\n{FIREWALLD_DAEMON_SETUP}\n{DOCKER_DAEMON_SETUP}\n\
         start_target ''\n{USERS_OWN_RICH_RULE}\n{}\n{}\n",
        with_helper(&body),
        marker_block("SIGNALS", "cat /tmp/signals.txt"),
    );

    eprintln!(
        "== forward test: a stopped container closes its forward (this one takes ~2.5 minutes) =="
    );
    let stdout = report(
        &container.exec(&script),
        "the forward target-gone container",
    );

    let still = extract_marker(&stdout, "STILL_THERE");
    assert!(
        still.contains(r#""port":3000"#),
        "one poll passed with the container still up and the forward closed anyway, so \
         nothing below would distinguish `target-gone` from `closes on every wake-up`: \
         {still}"
    );

    let after = extract_marker(&stdout, "AFTER_STOP");
    assert!(
        after.contains(r#""rules":[]"#),
        "the forward must be gone once its container is: {after}"
    );
    let rules = extract_marker(&stdout, "RULES_AFTER_STOP");
    assert!(
        porthole_rich_rules(rules).is_empty(),
        "the redirect must be out of firewalld too, not merely out of the state file: {rules}"
    );
    assert!(
        rules.contains(r#"port="9999""#),
        "the user's own rule must survive an unasked close: {rules}"
    );
    assert_eq!(
        extract_marker(&stdout, "CLIENT_AFTER_STOP"),
        "CLIENT_UNREACHABLE",
        "the LAN must have lost the redirect along with the record of it"
    );

    let signals = extract_marker(&stdout, "SIGNALS");
    assert_eq!(
        signals.matches("member=RuleClosed").count(),
        1,
        "exactly one close, for the forward whose container went: {signals}"
    );
    assert!(
        signals.contains(r#"string "target-gone""#),
        "the close must say the container is no longer the one it was created against: \
         {signals}"
    );
    for wrong in ["requested", "expired", "network-changed", "reconciled"] {
        assert!(
            !signals.contains(&format!(r#"string "{wrong}""#)),
            "nothing may report this close as `{wrong}`: {signals}"
        );
    }
}

/// A container that comes back at a **different address** closes the forward
/// rather than being followed to it.
///
/// This is the case `forward::stale_forwards` exists for and the one a
/// weaker check would miss: the published port is the same, the protocol is
/// the same, the container port is the same, and only the container's own
/// address has moved. porthole re-resolves rather than assuming, so the
/// request is closed and the user is invited to make it again -- see
/// `porthole-agent`'s `Reopen` on a `target-gone` notification.
///
/// A user-defined Docker network with explicit `--ip` addresses, because the
/// address has to be *known* to be different: on the default bridge Docker
/// hands out whatever is free, and a replacement container commonly gets the
/// address the old one gave up, which would make this test assert nothing.
/// Both addresses are read back and asserted to differ before anything else
/// is concluded.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn a_container_that_came_back_elsewhere_closes_the_forward_rather_than_being_followed() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    let container = docker_container(
        "porthole-container-test-forward-moved",
        &cli,
        &helper,
        &["-e".to_string(), "PORTHOLE_NETMON=1".to_string()],
    );

    let body = format!(
        r#"
stdbuf -oL dbus-monitor --session "type='signal',interface='com.jacopobriccola.Porthole1'" \
  > /tmp/signals.txt 2>&1 &
MONPID=$!
for i in $(seq 1 100); do [ -s /tmp/signals.txt ] && break; sleep 0.1; done

porthole --session forward 3000 --to 10.10.10.0/24 --for 15m
{}

docker rm -f target >/dev/null
start_target '--network pt-net --ip 172.28.0.6'
{}

sleep 70
{}
{}
sleep 1
kill "$MONPID" 2>/dev/null || true
"#,
        marker_block("BEFORE_MOVE", "porthole --session list --json"),
        marker_block(
            "NEW_ADDR",
            "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' target"
        ),
        marker_block("AFTER_MOVE", "porthole --session list --json"),
        marker_block("RULES_AFTER_MOVE", "firewall-cmd --list-rich-rules"),
    );

    let script = format!(
        "{DOCKER_LAN_SETUP}\n{FIREWALLD_DAEMON_SETUP}\n{DOCKER_DAEMON_SETUP}\n\
         docker network create --subnet=172.28.0.0/16 pt-net >/dev/null\n\
         start_target '--network pt-net --ip 172.28.0.5'\n{USERS_OWN_RICH_RULE}\n\
         {}\n{}\n",
        with_helper(&body),
        marker_block("SIGNALS", "cat /tmp/signals.txt"),
    );

    eprintln!(
        "== forward test: a container that moved is not followed (this one takes ~1.5 minutes) =="
    );
    let stdout = report(
        &container.exec(&script),
        "the forward moved-container container",
    );

    let before = extract_marker(&stdout, "BEFORE_MOVE");
    assert!(
        before.contains(r#""container_addr":"172.28.0.5""#),
        "the forward must have been created against the first address: {before}"
    );
    assert_eq!(
        extract_marker(&stdout, "NEW_ADDR"),
        "172.28.0.6",
        "the replacement container has to be somewhere else, or this test compares \
         an address with itself"
    );

    let after = extract_marker(&stdout, "AFTER_MOVE");
    assert!(
        after.contains(r#""rules":[]"#),
        "the forward must close rather than follow the container: {after}"
    );
    let rules = extract_marker(&stdout, "RULES_AFTER_MOVE");
    assert!(
        porthole_rich_rules(rules).is_empty(),
        "and nothing may be left in firewalld: {rules}"
    );
    assert!(
        !rules.contains("172.28.0.6"),
        "porthole must never re-aim a redirect at whatever holds the port now: {rules}"
    );

    let signals = extract_marker(&stdout, "SIGNALS");
    assert!(
        signals.contains(r#"string "target-gone""#),
        "an address that moved is the same fact as a container that stopped, and must \
         carry the same reason: {signals}"
    );
    assert!(
        !signals.contains("172.28.0.6"),
        "the close announces the mapping the rule held, never the one that replaced it: \
         {signals}"
    );
}

/// A Docker table that **cannot be read** closes nothing.
///
/// Not knowing is not knowing it changed. `Engine::close_stale_forwards` has
/// no way to spell "no answer" to `forward::stale_forwards` -- an empty slice
/// is the answer "no container publishes anything", which would name every
/// forward -- so a read failure returns empty and leaves the next wake-up to
/// try again.
///
/// The failure is made by taking the `iptables` binary away, so what
/// `docker::published` meets is a real spawn failure rather than a
/// fabricated exit status. It must not be confused with the neighbouring
/// case: exit **1** is `iptables(8)`'s "No chain/target/match by that name",
/// which is what a *stopped Docker daemon* produces, and that is an answer --
/// "nothing published" -- which does close every forward. This test is about
/// the other half.
///
/// **The control is in the helper's own log.** "Nothing closed" is what a
/// wake-up that never happened also looks like, so the assertion is not the
/// absence of a close but the presence of the line
/// `close_stale_forwards` prints on exactly this path.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn a_docker_table_that_cannot_be_read_closes_no_forward() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    let container = docker_container(
        "porthole-container-test-forward-unreadable",
        &cli,
        &helper,
        &["-e".to_string(), "PORTHOLE_NETMON=1".to_string()],
    );

    let body = format!(
        r#"
porthole --session forward 3000 --to 10.10.10.0/24 --for 15m
{}

# A read that fails, not a read that answers "nothing". Moving the binary
# makes `docker::published` fail to spawn it at all; deleting the DOCKER
# chain instead would exit 1, which porthole reads as an answer.
mv /usr/sbin/iptables /usr/sbin/iptables-taken-away

sleep 70
{}
{}
"#,
        marker_block("BEFORE", "porthole --session list --json"),
        marker_block("AFTER", "porthole --session list --json"),
        marker_block("RULES_AFTER", "firewall-cmd --list-rich-rules"),
    );

    let script = format!(
        "{DOCKER_LAN_SETUP}\n{FIREWALLD_DAEMON_SETUP}\n{DOCKER_DAEMON_SETUP}\n\
         start_target ''\n{}\n{}\n",
        with_helper(&body),
        marker_block("HELPER_LOG", "cat /tmp/porthole-helper.log"),
    );

    eprintln!("== forward test: an unreadable Docker table closes nothing (this one takes ~1.5 minutes) ==");
    let stdout = report(&container.exec(&script), "the unreadable-Docker container");

    assert!(
        extract_marker(&stdout, "BEFORE").contains(r#""port":3000"#),
        "the forward has to exist before the table is taken away: {}",
        extract_marker(&stdout, "BEFORE")
    );

    // The control, first: without it, everything below is also satisfied by a
    // wake-up that never ran.
    let log = extract_marker(&stdout, "HELPER_LOG");
    assert!(
        log.contains("could not read Docker's published ports"),
        "the monitor must have woken, tried to read Docker's table and failed -- \
         otherwise `nothing closed` says nothing about why: {log}"
    );

    let after = extract_marker(&stdout, "AFTER");
    assert!(
        after.contains(r#""port":3000"#),
        "a table porthole could not read is not evidence the container moved, and must \
         take nobody's access away: {after}"
    );
    let rules = extract_marker(&stdout, "RULES_AFTER");
    assert_eq!(
        porthole_rich_rules(rules).len(),
        1,
        "the redirect must still be in firewalld: {rules}"
    );
}

/// ufw refuses a forward, in a message that names ufw.
///
/// ufw has no forwarding command at all: its port forwarding is a hand-edited
/// `*nat` block in `/etc/ufw/before.rules`, a file ufw reloads at boot.
/// Writing one would be writing a permanent firewall rule, which porthole
/// never does -- so this backend inherits `FirewallBackend::forward`'s
/// refusing default.
///
/// A separate test from the nftables one on purpose. They refuse for
/// different reasons and say different things, and one test covering both
/// would let either of them start succeeding, or start saying the other's
/// sentence, without anything noticing.
///
/// Nothing about Docker is set up here, and that is itself the point:
/// `Engine::forward` asks `forward_capability` before it reads anything at
/// all, so a machine whose firewall cannot redirect is told that rather than
/// sent looking for a container.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn on_ufw_a_forward_is_refused_with_a_message_that_names_ufw() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(DEBIAN_IMAGE, "Containerfile.debian");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(cli_mounts(&cli, &helper));

    let body = "\
set +e
porthole --session forward 3000 --to 10.10.10.0/24 --for 15m --json
echo \"EXIT=$?\"
set -e";

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\nufw --force enable\n\
         ufw allow 2222/tcp comment 'not-porthole'\n\
         {}\n{}\n{}\n",
        marker_block("BEFORE", "ufw status numbered"),
        with_helper(&marker_block("REFUSAL", body)),
        marker_block("AFTER", "ufw status numbered"),
    );

    eprintln!("== forward test: ufw refuses ==");
    let out = podman_run(DEBIAN_IMAGE, &args, &script);
    let stdout = report(&out, "the ufw forward-refusal container");

    let refusal = extract_marker(&stdout, "REFUSAL");
    assert!(
        refusal.contains("EXIT=12"),
        "a backend with no redirect must exit ForwardUnsupported (12): {refusal}"
    );
    assert!(
        refusal.contains(r#""kind":"forward_unsupported""#),
        "and must say so in --json's own machine-readable slug: {refusal}"
    );
    assert!(
        refusal.contains("ufw cannot redirect a port"),
        "the refusal must name the backend the machine actually has: {refusal}"
    );
    assert!(
        !refusal.contains("nftables"),
        "ufw's refusal must not be nftables' -- the two exist separately so that \
         either one changing is visible: {refusal}"
    );
    assert_eq!(
        extract_marker(&stdout, "BEFORE"),
        extract_marker(&stdout, "AFTER"),
        "a refused forward may leave nothing behind in ufw"
    );
}

/// nftables refuses a forward, in a message that names why nftables cannot.
///
/// Its reason is not ufw's. A redirect on its own was measured unreachable on
/// a ruleset whose forward chain drops, and the accept that would carry it
/// belongs in the chain deciding forwarded traffic -- where porthole does not
/// write, and where an accept of porthole's would land ahead of
/// `DOCKER-USER` on a host that also runs Docker. So the refusal is the
/// backend's own sentence, not the trait's default.
///
/// The two refusal tests assert *different* strings, which is what makes
/// keeping them apart worth the second container.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn on_nftables_a_forward_is_refused_with_a_message_that_names_why_nftables_cannot() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    ensure_image(ARCH_IMAGE, "Containerfile.arch");

    let mut args: Vec<String> =
        vec!["--cap-add=NET_ADMIN,NET_RAW,SYS_ADMIN,SYS_PTRACE".to_string()];
    args.extend(cli_mounts(&cli, &helper));

    let ruleset_setup = "\
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input iif lo accept";

    let body = "\
set +e
porthole --session forward 3000 --to 10.10.10.0/24 --for 15m --json
echo \"EXIT=$?\"
set -e";

    let script = [
        "set -e".to_string(),
        ruleset_setup.to_string(),
        marker_block("BEFORE", "nft -a list ruleset"),
        with_helper(&marker_block("REFUSAL", body)),
        marker_block("AFTER", "nft -a list ruleset"),
    ]
    .join("\n");

    eprintln!("== forward test: nftables refuses ==");
    let out = podman_run(ARCH_IMAGE, &args, &script);
    let stdout = report(&out, "the nftables forward-refusal container");

    let refusal = extract_marker(&stdout, "REFUSAL");
    assert!(
        refusal.contains("EXIT=12"),
        "a backend with no redirect must exit ForwardUnsupported (12): {refusal}"
    );
    assert!(
        refusal.contains(r#""kind":"forward_unsupported""#),
        "and must say so in --json's own machine-readable slug: {refusal}"
    );
    assert!(
        refusal.contains("nftables cannot redirect a port"),
        "the refusal must name the backend the machine actually has: {refusal}"
    );
    assert!(
        refusal.contains("forward chain that drops"),
        "and must give nftables' own reason, not the trait's default sentence: {refusal}"
    );
    assert!(
        !refusal.contains("porthole has no forward for this backend"),
        "the trait default is ufw's answer; nftables overrides it and must keep doing \
         so: {refusal}"
    );
    assert_eq!(
        extract_marker(&stdout, "BEFORE"),
        extract_marker(&stdout, "AFTER"),
        "a refused forward may leave nothing behind in the ruleset, handles included"
    );
}

/// A forward is refused when something on this machine already answers on the
/// external port, and the refusal names `--as`.
///
/// The companion of the `--as` phase above, and the reason `--as` exists at
/// all: exit 11 is what a user meets when the number they typed is already
/// taken, and its message is where they are told what to do about it.
///
/// **The discrimination this test exists for is which listeners refuse.**
/// `Engine::forward` refuses on a socket bound to an address the network
/// reaches (`Binding::AllInterfaces` or `Binding::Specific`) and deliberately
/// does *not* refuse on a loopback-bound one — because `docker-proxy` holds
/// `127.0.0.1:<published>` for every container published the way this command
/// exists to forward, and refusing on that would refuse
/// `porthole forward <PORT>` with no `--as` on a default Docker install.
/// Both halves are asserted here against real sockets in `/proc`, which is
/// what no unit test can do: the host tests feed `listening::scan` a
/// fabricated `/proc/net/tcp`.
///
/// So the second half is the control. Without it, "exit 11 when a listener is
/// present" would be satisfied just as well by a check that refuses on every
/// listener there is — which would make this command unusable for its own
/// primary case.
#[test]
#[ignore = "container integration test: run tests/container/run.sh (needs rootless podman and the musl binaries)"]
fn a_forward_is_refused_when_the_external_port_already_answers_and_the_refusal_names_as() {
    require_environment!();
    let (cli, helper) = require_musl_binaries!();
    let container = docker_container("porthole-container-test-forward-inuse", &cli, &helper, &[]);

    let body = format!(
        "set +e\n\
         porthole --session forward 3000 --as 4000 --to 10.10.10.0/24 --for 15m --json\n\
         echo \"EXIT=$?\"\n\
         set -e\n\
         {}\n\
         {}\n",
        marker_block("STATE", "porthole --session list --json"),
        marker_block("RULES", "firewall-cmd --list-rich-rules"),
    );

    let script = format!(
        "{DOCKER_LAN_SETUP}\n{FIREWALLD_DAEMON_SETUP}\n{DOCKER_DAEMON_SETUP}\n\
         start_target ''\n\
         # A service of the machine's own on the port `--as` would take, bound\n\
         # where the local network can reach it. This is the situation exit 11\n\
         # is for. `-h /img/www` is this container's own copy, built by\n\
         # DOCKER_DAEMON_SETUP: `/www` exists only inside the Docker image, and\n\
         # naming it here leaves busybox exiting instead of binding -- which is\n\
         # what the LISTENERS control below caught when this was first written.\n\
         busybox httpd -f -p 0.0.0.0:4000 -h /img/www &\n\
         sleep 1\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block("LISTENERS", "porthole listen"),
        with_helper(&marker_block("REFUSAL", &body)),
        marker_block(
            "LOOPBACK_STILL_PUBLISHED",
            "curl -sS --max-time 4 http://127.0.0.1:3000/ || echo LOOPBACK_BROKEN"
        ),
    );

    eprintln!("== forward test: an external port something already answers on ==");
    let stdout = report(
        &container.exec(&script),
        "the forward external-port-in-use container",
    );

    // The control comes first: porthole has to be able to see both sockets,
    // or nothing below distinguishes "refused for the right reason" from
    // "refused because it saw nothing and something else went wrong".
    // `porthole listen` prints one row per socket -- `<port>/<proto>
    // <process> <address> pid <n>` -- with the bind address alone in the
    // third column, not `address:port`.
    let listeners = extract_marker(&stdout, "LISTENERS");
    let row = |port: &str| -> &str {
        listeners
            .lines()
            .find(|l| l.trim_start().starts_with(port))
            .unwrap_or_else(|| panic!("no row for {port} in:\n{listeners}"))
    };
    assert!(
        row("4000/tcp").contains("0.0.0.0"),
        "the host service must be visible to porthole's own /proc scan, bound where the \
         network reaches it, or the refusal below is not the one this test is about: \
         {listeners}"
    );
    assert!(
        row("3000/tcp").contains("127.0.0.1"),
        "and docker-proxy's loopback socket must be visible too, since the whole point \
         is that it does *not* refuse: {listeners}"
    );

    let refusal = extract_marker(&stdout, "REFUSAL");
    assert!(
        refusal.contains("EXIT=11"),
        "an external port something on this machine already answers on must be \
         ExternalPortInUse (11): {refusal}"
    );
    assert!(
        refusal.contains(r#""kind":"external_port_in_use""#),
        "and must say so in --json's own slug: {refusal}"
    );
    assert!(
        refusal.contains("--as"),
        "the refusal must name the flag that gives the local network a different port \
         -- it is the only way out of this, and a user who is not told it is stuck: \
         {refusal}"
    );
    assert!(
        refusal.contains("4000"),
        "and must name the port it refused, not the one Docker published: {refusal}"
    );

    // The loopback listener did not refuse: the request got as far as the
    // external-port check, which means `docker-proxy` on 127.0.0.1:3000 was
    // looked at and passed over.
    // Both slugs, because "no container publishes that port" arrives under
    // either depending on whether anything is listening on it, and this
    // guard is about the fact rather than about which of the two words it.
    for slug in ["not_published_by_container", "nothing_listening"] {
        assert!(
            !refusal.contains(&format!(r#""kind":"{slug}""#)),
            "the request must have found the container -- if it did not, the exit 11 above \
             would be about a port nothing publishes: {refusal}"
        );
    }

    assert!(
        extract_marker(&stdout, "STATE").contains(r#""rules":[]"#),
        "a refused forward may record nothing: {}",
        extract_marker(&stdout, "STATE")
    );
    assert!(
        porthole_rich_rules(extract_marker(&stdout, "RULES")).is_empty(),
        "and may leave nothing in the firewall: {}",
        extract_marker(&stdout, "RULES")
    );
    assert_eq!(
        extract_marker(&stdout, "LOOPBACK_STILL_PUBLISHED"),
        "PORTHOLE-TARGET-OK",
        "a refused forward must not have disturbed Docker's own publication"
    );
}
