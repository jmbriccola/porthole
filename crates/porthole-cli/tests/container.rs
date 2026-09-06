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
//! # Two deliberate departures from a literal reading of the task brief
//!
//! - **`--until-reboot`, not `--for 5m`, for the mutating opens.** A real
//!   `--for <duration>` schedules its own close with `systemd-run`, and these
//!   containers have no systemd PID 1 to serve it -- confirmed by running
//!   exactly that and getting `No such file or directory`. `--until-reboot`
//!   is a first-class, equally real porthole invocation that skips the timer
//!   entirely (`Lifetime::UntilReboot` in `engine.rs`), and every test here
//!   controls its own "reboot" directly rather than waiting one out, so
//!   nothing about what is being proven needs a timer at all. The dry-run
//!   tests do use `--for 5m` exactly as written: dry-run withholds the
//!   `systemd-run` command too, so nothing ever tries to run it.
//! - **The command that reconciles on "boot 2" of the ufw test is
//!   `close --all`, not `list`.** `porthole list` deliberately touches
//!   nothing but the state file (see `run.rs`'s own comment on `Commands::List`)
//!   and never reconciles. `porthole status` reconciles read-only
//!   (`SweepMode::ReadOnly`) and can never remove an orphan by design --
//!   [`reconcile.rs`]'s own module docs are explicit that a read path must
//!   never be able to cause a close. Only `open`, `close_by_port`,
//!   `close_by_id` and `close_all` run `SweepMode::Apply`, which is the only
//!   mode that ever calls `FirewallBackend::close` on an orphan. `close --all`
//!   is the least surprising of those to run when nothing is known to be
//!   open.
//!
//! # Environment this file assumes
//!
//! - `podman`, rootless, reachable on `$PATH`.
//! - The musl binaries already built: `cargo build --target
//!   x86_64-unknown-linux-musl --bins`. Checked and skipped loudly if
//!   missing, the same way `helper_e2e.rs` skips loudly rather than silently
//!   passing when `porthole-helper` was never built.
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

/// Skip loudly and return from the calling test, exactly as
/// `helper_e2e.rs`'s `start_or_skip!` does -- a gated test nobody can tell
/// ran is not a test.
macro_rules! require_environment {
    () => {
        if !container_tests_enabled() {
            eprintln!("skipped: set PORTHOLE_CONTAINER_TESTS=1 and have podman to run this test");
            return;
        }
        if !podman_available() {
            eprintln!("skipped: PORTHOLE_CONTAINER_TESTS is set but `podman --version` failed");
            return;
        }
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

/// The two binaries every mutating test bind-mounts into its container.
/// `None` -- with a message identical in spirit to `helper_e2e.rs`'s own
/// `StartFailure::MissingBinary` -- when they were never built.
fn musl_binaries() -> Option<(PathBuf, PathBuf)> {
    let dir = musl_dir();
    let cli = dir.join("porthole");
    let helper = dir.join("porthole-helper");
    if cli.is_file() && helper.is_file() {
        Some((cli, helper))
    } else {
        None
    }
}

macro_rules! require_musl_binaries {
    () => {
        match musl_binaries() {
            Some(paths) => paths,
            None => {
                eprintln!(
                    "skipped: build the musl binaries first: \
                     `cargo build --target x86_64-unknown-linux-musl --bins` \
                     (looked in {})",
                    musl_dir().display()
                );
                return;
            }
        }
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
#[test]
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

    // --- Boot 1: enable ufw, add a rule of the user's own, then open a port
    //     through porthole for real. ---
    let boot1_script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n\
         ufw --force enable\n\
         # Unrelated to porthole, no porthole: comment -- must survive every\n\
         # sweep in this test untouched.\n\
         ufw allow 2222/tcp comment 'not-porthole'\n\
         {}\n\
         {}\n",
        with_helper("porthole --session open 5173 --until-reboot"),
        marker_block("BOOT1_STATUS", "ufw status numbered"),
    );

    eprintln!("== ufw reboot test: boot 1 (open, then enable) ==");
    let out1 = podman_run(DEBIAN_IMAGE, &args, &boot1_script);
    eprintln!("{}", String::from_utf8_lossy(&out1.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out1.stderr));
    assert_container_ok(&out1, "boot 1");

    let stdout1 = String::from_utf8_lossy(&out1.stdout).to_string();
    let boot1_status = extract_marker(&stdout1, "BOOT1_STATUS");
    assert!(
        boot1_status.contains("5173/tcp") && boot1_status.contains("porthole:"),
        "boot 1 must show porthole's own rule: {boot1_status}"
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
         /lib/ufw/ufw-init start || true\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block("BEFORE_INIT", "ufw status"),
        marker_block("AFTER_INIT", "ufw status numbered"),
        with_helper("porthole --session close --all --json"),
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
        after_init.contains("5173/tcp") && after_init.contains("porthole:"),
        "`ufw-init start` -- exactly what ufw.service runs at boot -- must \
         bring the orphaned rule back before porthole ever runs, or this test \
         would pass against an implementation that does nothing: {after_init}"
    );
    assert!(
        after_init.contains("2222/tcp"),
        "the user's rule must have reloaded too: {after_init}"
    );

    let final_status = extract_marker(&stdout2, "FINAL_STATUS");
    assert!(
        !final_status.contains("porthole:"),
        "reconciliation must have removed the orphaned rule nobody remembered: \
         {final_status}"
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
/// anywhere. This is the opposite of what `helper_e2e.rs`'s
/// `an_open_reaches_the_firewall_and_changes_nothing_when_refused` relies on
/// for an *unprivileged* caller against the *host's* real firewalld and
/// polkit -- that test explicitly skips itself when run as root, for exactly
/// this reason.
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
fn dry_run_is_byte_identical_to_reality_on_ufw() {
    require_environment!();
    let (cli, _helper) = require_musl_binaries!();
    ensure_image(DEBIAN_IMAGE, "Containerfile.debian");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(bind_ro(&cli, "/usr/local/bin/porthole"));

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\nufw --force enable\n\
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
fn dry_run_is_byte_identical_to_reality_on_firewalld() {
    require_environment!();
    let (cli, _helper) = require_musl_binaries!();
    ensure_image(FEDORA_IMAGE, "Containerfile.fedora");

    let mut args: Vec<String> = vec!["--cap-add=NET_ADMIN".to_string()];
    args.extend(bind_ro(&cli, "/usr/local/bin/porthole"));

    let script = format!(
        "set -e\n{FAKE_LAN_INTERFACE}\n{FIREWALLD_DAEMON_SETUP}\n\
         {}\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block("ZONE", "firewall-cmd --get-default-zone"),
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
fn dry_run_is_byte_identical_to_reality_on_nftables() {
    require_environment!();
    let (cli, _helper) = require_musl_binaries!();
    ensure_image(ARCH_IMAGE, "Containerfile.arch");

    let mut args: Vec<String> =
        vec!["--cap-add=NET_ADMIN,NET_RAW,SYS_ADMIN,SYS_PTRACE".to_string()];
    args.extend(bind_ro(&cli, "/usr/local/bin/porthole"));

    let script = format!(
        "set -e\n\
         nft add table inet filter\n\
         nft 'add chain inet filter input {{ type filter hook input priority 0; policy drop; }}'\n\
         nft add rule inet filter input ct state established,related accept\n\
         nft add rule inet filter input iif lo accept\n\
         {}\n\
         {}\n\
         {}\n",
        marker_block("BEFORE", "nft -a list ruleset"),
        marker_block(
            "DRYRUN_JSON",
            "porthole --dry-run open 5173 --to 10.10.10.0/24 --for 5m --json"
        ),
        marker_block("AFTER", "nft -a list ruleset"),
    );

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
}
