//! One private session bus per test binary in this crate, and the two
//! constructors every test here uses instead of `zbus`'s `session()` ones.
//!
//! # Why not the ambient session bus
//!
//! Every test in this crate that needs a bus used to take the developer's
//! own, under a probe name unique *within its own binary* —
//! `com.jacopobriccola.PortholeTestList`, `…TestProbeAllow`, and so on, with
//! `com.jacopobriccola.PortholeProbe` in `roundtrip.rs`. Unique within one
//! process is not unique on a shared bus, and that is what kept the project
//! to one `cargo test` at a time: a second `cargo test` — a second developer
//! on the same machine, a second CI job on the same runner, or the same
//! person running the suite twice — asks for the very same names on the very
//! same daemon.
//!
//! `zbus`'s `request_name` passes `DoNotQueue`, so the loser of that race
//! gets an error and the test fails on `.unwrap()`. That is the *kind* half
//! of the problem. The worse half is what happens to the winner: the loser's
//! *client* still resolves those names, and resolves them to the winner's
//! objects. Measured on this machine, both runs failing at once:
//!
//! ```text
//! ---- always_allow_records_what_it_was_asked stdout ----
//! assertion `left == right` failed: both calls must be recorded:
//!   [("com.jacopobriccola.Porthole.close",    ":1.5717"),
//!    ("com.jacopobriccola.Porthole.open-any", ":1.5719"),
//!    ("com.jacopobriccola.Porthole.close",    ":1.5719")]
//!   left: 3
//!  right: 2
//! ```
//!
//! Two distinct sender names against one authorizer: one `cargo test`'s
//! client calling the other `cargo test`'s server. `src/netmon.rs`'s signal
//! test failed in the same run with a rule id it never created, because the
//! other process's `RuleClosed` arrived at its subscriber first. Neither
//! failure names a bus, and neither is a defect in the code under test.
//!
//! # The shape
//!
//! The same one `crates/porthole-cli/tests/{cli,helper_e2e}.rs` and
//! `crates/porthole-agent/tests/session.rs` each carry: one
//! `dbus-run-session` daemon started on first use and shared by every test in
//! the binary, with connections *addressed* at it rather than resolved
//! through `DBUS_SESSION_BUS_ADDRESS`. Addressed matters. `session()` reads
//! that variable from this process's own environment, and `std::env::set_var`
//! is unsound with other tests' threads running, so redirecting the variable
//! is not available to an in-process connection — the address has to be
//! passed at the call site, which is what [`builder`] and [`connect`] exist
//! to make unmissable.
//!
//! Written once and shared by the six test binaries that need it rather than
//! copied into each: six copies of a rule about isolation is how a repair
//! survives in one place and rots in the other five.

// Six test binaries include this module and none of them uses all of it.
#![allow(dead_code)]

use std::io::BufRead as _;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

/// The one session bus every connection in this test binary is made on, and
/// the only one any of them can reach.
pub struct PrivateBus {
    /// `dbus-run-session`, alive for as long as the pipe its inner shell
    /// reads stays open. This process exiting closes that pipe, the shell
    /// exits, and the daemon goes down with it — so nothing is left behind
    /// even though this value is never dropped.
    _daemon: Child,
    pub address: String,
}

/// Start this binary's private bus, once, or hand back the running one.
pub fn private_bus() -> &'static PrivateBus {
    static BUS: OnceLock<PrivateBus> = OnceLock::new();
    BUS.get_or_init(|| {
        // Asserted, not skipped. A test that cannot get its own bus must fail
        // rather than quietly run against this machine's — which is the whole
        // of what this module exists to stop.
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
            .unwrap_or_else(|e| {
                panic!(
                    "dbus-run-session would not start: {e}\n\
                     `Command::new` resolves the program off this process's own \
                     `PATH` at the moment of the first call. Two files here \
                     (`forward_gate.rs`, `reconciled_signal.rs`) set `PATH` to a \
                     stub directory alone, so if a test in one of them is the \
                     first to reach this function the resolution fails with \
                     NotFound -- start the bus before stripping `PATH`, as both \
                     of those files now do."
                )
            });
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

/// The drop-in for `zbus::connection::Builder::session()`: a builder aimed at
/// [`private_bus`], for a connection that owns a name and serves objects.
pub fn builder() -> zbus::connection::Builder<'static> {
    zbus::connection::Builder::address(private_bus().address.as_str())
        .expect("dbus-run-session printed an address zbus can parse")
}

/// The drop-in for `zbus::Connection::session()`: a plain client connection
/// on [`private_bus`].
pub async fn connect() -> zbus::Connection {
    builder()
        .build()
        .await
        .expect("the private session bus accepts a client")
}
