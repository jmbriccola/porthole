//! `porthole doctor` — why it is not working, and what to do.
//!
//! The spec asks for this by name: across three distributions, three
//! firewalls, a system D-Bus service and Docker, the first problem every user
//! has is "it does not work and I do not know why". So every check says what
//! it looked for, what it found, and what to do about it. A check that reports
//! a problem without a remedy has done half the job — and it is the half a
//! stuck user cannot supply for themselves.

use porthole_core::backend::{self, nftables, BackendId};
use porthole_core::cli_path;
use porthole_core::command::{CommandRunner, RealRunner};
use porthole_core::ipc::PortholeProxy;
use porthole_core::net;
use serde_json::{json, Value};

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    /// Empty when there is nothing to do.
    pub remedy: String,
}

impl Check {
    fn good(name: &'static str, detail: String) -> Self {
        Check {
            name,
            ok: true,
            detail,
            remedy: String::new(),
        }
    }
    fn bad(name: &'static str, detail: String, remedy: &str) -> Self {
        Check {
            name,
            ok: false,
            detail,
            remedy: remedy.to_string(),
        }
    }
}

/// Checks in the order a failure cascades: no firewall makes everything else
/// moot, no helper makes authorization moot, and so on.
pub fn run(session: bool) -> Vec<Check> {
    let runner = RealRunner;
    let mut checks = Vec::new();

    checks.push(match backend::detect(&runner) {
        Ok(backend) => firewall_check(backend.as_ref(), &runner),
        Err(e) => {
            let remedy = format!(
                "porthole {} can drive firewalld, ufw or nftables — whichever this \
                 machine already has — but none of the three was found. Install one \
                 of them; porthole will not install or enable a firewall for you.",
                env!("CARGO_PKG_VERSION")
            );
            Check::bad("Firewall", e.to_string(), &remedy)
        }
    });

    checks.push(check_helper(session));
    checks.push(check_expiry_timer(session));

    checks.push(if std::path::Path::new(POLICY_PATH).exists() {
        Check::good("polkit", format!("{POLICY_PATH} is installed"))
    } else {
        Check::bad(
            "polkit",
            format!("{POLICY_PATH} is not installed"),
            "Without it polkit falls back to its default and porthole's own \
             severity choices are ignored. Install the porthole package, or copy \
             the file from data/ in the source tree.",
        )
    });

    let state_dir = std::path::Path::new(porthole_core::state::STATE_DIR);
    checks.push(if state_dir.is_dir() {
        Check::good("State", format!("{} exists", state_dir.display()))
    } else {
        Check::good(
            "State",
            format!(
                "{} does not exist yet — the helper creates it on first use",
                state_dir.display()
            ),
        )
    });

    checks.push(match net::current_network(&runner) {
        Ok(n) => Check::good("Network", format!("{} · {}", n.interface, n.cidr)),
        Err(e) => Check::bad(
            "Network",
            e.to_string(),
            "porthole opens ports towards the network you are on. There is none — \
             connect to Wi-Fi or plug in a cable. `--to any` still works without a \
             local network, since it does not need one.",
        ),
    });

    checks.push(check_docker());
    checks.push(check_ipv6(&runner));

    checks
}

/// The `Firewall` check: which backend was detected, whether it is enforcing
/// anything, and the caveat specific to that backend that a user cannot see
/// from `porthole status` alone — each backend's `health()` already names
/// itself in its own detail text (`"firewalld 2.4.4 is running"`, `"ufw
/// 0.36.2 is active"`, `"nftables v1.1.6: inet filter input is enforcing"`),
/// so this function only adds what `health()` cannot: nftables' "more than
/// one candidate chain" refusal, which `health()` reports as `active: true`
/// because *something* is enforcing even though porthole cannot use it, and
/// ufw's standing persistence caveat, which is true every time ufw is active,
/// not only on failure.
fn firewall_check(backend: &dyn backend::FirewallBackend, runner: &dyn CommandRunner) -> Check {
    let health = match backend.health() {
        Ok(h) => h,
        Err(e) => return Check::bad("Firewall", e.to_string(), health_error_remedy(backend.id())),
    };

    if !health.active {
        // `active: false` is two different facts porthole cannot read apart
        // from that one bit alone -- see `BackendHealth::active_unknown`'s
        // own doc comment. `not_active_remedy` is written for the confirmed
        // case ("no chain is registered... the port is already reachable");
        // saying that when the truth is "porthole could not read the
        // ruleset at all" is a false claim in the dangerous direction, which
        // is exactly the "feeling safe when you are not" failure this
        // milestone spent a whole task guarding against elsewhere. Ask
        // `health` which case this is rather than assume the confirmed one.
        let remedy = if health.active_unknown {
            activity_unconfirmed_remedy(backend.id())
        } else {
            not_active_remedy(backend.id())
        };
        return Check::bad("Firewall", health.detail, remedy);
    }

    // nftables' `active: true` means "something is registered at the input
    // hook", not "porthole can act". Two or more candidate chains is exactly
    // that gap: health() already explains the ambiguity in its detail, but
    // leaves `active` true because the hook genuinely is enforced by
    // *something*. `open` and `close` refuse outright rather than guess which
    // chain decides, so doctor must surface that as a failure here too,
    // rather than let the ambiguity read as a plain "ok".
    if backend.id() == BackendId::Nftables {
        match nftables::input_chains(runner) {
            Ok(chains) if chains.len() > 1 => {
                return Check::bad(
                    "Firewall",
                    health.detail,
                    "porthole will refuse every `open` and `close` here until exactly \
                     one base chain is registered at the input hook, because it cannot \
                     prove which one decides a packet's fate. Remove or merge the extra \
                     chain, or manage this port with whatever wrote it instead.",
                );
            }
            Ok(_) => {}
            // `health()` just ran this exact command successfully -- this is
            // re-running it, not learning something new -- so an error here
            // is unexpected, not confirmation of a healthy single chain. A
            // diagnostic tool that discards this and falls through to "ok"
            // fails *open* on a discarded error, which is the wrong
            // direction for the one command whose entire job is surfacing
            // problems.
            Err(e) => {
                return Check::bad(
                    "Firewall",
                    format!("could not re-check the input hook's chains: {e}"),
                    health_error_remedy(BackendId::Nftables),
                );
            }
        }
    }

    // ufw has no runtime-only concept at all: `ufw allow` writes straight to
    // /etc/ufw/user.rules, and ufw.service reloads it at every boot. If
    // porthole is killed between opening and closing a port -- the process
    // killed, the machine losing power, anything short of its own close
    // running -- the rule is still there and still enforced after a reboot,
    // until the next porthole command's reconciliation pass notices and
    // removes it. That is not a failure of this check (reconciliation closes
    // the gap in practice), but it is a property worth a user knowing on
    // every single run, not only when something is wrong -- so it is said
    // here rather than only in docs/backends.md.
    if backend.id() == BackendId::Ufw {
        return Check {
            name: "Firewall",
            ok: true,
            detail: health.detail,
            remedy: "ufw's rules are persistent: a reboot does not close them by \
                     itself. If porthole is killed between opening and closing a \
                     port, the rule survives until the next porthole command \
                     reconciles it away."
                .to_string(),
        };
    }

    // Every other standing caveat (currently: nftables' accepting-chain
    // warning) follows the same convention `Docker` and `IPv6` already use --
    // the plain fact in `detail`, the standing caution in `remedy`, even
    // though `ok` is `true` -- rather than appending it to `detail` with
    // nothing in `remedy` to find it by.
    match &health.caveat {
        Some(caveat) => Check {
            name: "Firewall",
            ok: true,
            detail: health.detail,
            remedy: caveat.clone(),
        },
        None => Check::good("Firewall", health.detail),
    }
}

/// What to tell someone when the detected backend's own health check itself
/// failed -- not "stopped", an actual error asking it.
fn health_error_remedy(id: BackendId) -> &'static str {
    match id {
        BackendId::Firewalld => {
            "`systemctl status firewalld` to see whether it is running, and \
             `journalctl -u firewalld -n 50` for why it is not."
        }
        BackendId::Ufw => {
            "`ufw status verbose` to see what ufw itself reports, and \
             `journalctl -u ufw -n 50` for why the call failed."
        }
        BackendId::Nftables => {
            "`nft -j list chains` by hand to see what it actually returns; \
             porthole could not make sense of the output."
        }
    }
}

/// What to tell someone when the detected backend is installed and
/// *confirmed* not enforcing anything -- `health()` actually read its state
/// and got a definite answer. Never call this for the other reason `active`
/// can be `false`: see [`activity_unconfirmed_remedy`] and
/// `BackendHealth::active_unknown`'s own doc comment for why the two need
/// different, non-interchangeable wording.
fn not_active_remedy(id: BackendId) -> &'static str {
    match id {
        BackendId::Firewalld => {
            "Start it — `sudo systemctl start firewalld`. While it is stopped, \
             nothing porthole does changes what is reachable."
        }
        BackendId::Ufw => {
            "Enable it — `sudo ufw enable`. While it is disabled, nothing porthole \
             does changes what is reachable."
        }
        BackendId::Nftables => {
            "Nothing to start: no chain is registered at the input hook, so \
             nothing is filtering incoming traffic and the port is already \
             reachable. Set one up if that is not what you want — porthole will \
             not do it for you."
        }
    }
}

/// What to tell someone when the detected backend is installed, but
/// `porthole doctor` — which runs unprivileged, by design — could not
/// confirm whether anything is enforcing traffic.
///
/// Deliberately silent on which way the answer would actually go: naming a
/// direction here would just be `not_active_remedy`'s mistake with the
/// wording softened, not fixed. Also deliberately silent on asserting *why*
/// porthole could not confirm it: a permission-denied read is the common
/// reason for ufw and nftables, but `active_unknown` sets for any failure to
/// confirm, not only that one -- a broken install or a stray traceback also
/// exits non-zero, and porthole has not established which this is. Naming
/// "needs privilege" unconditionally was a narrower claim than the condition
/// that sets the flag actually supports; name it as the common cause worth
/// ruling out first, not the established one.
fn activity_unconfirmed_remedy(id: BackendId) -> &'static str {
    match id {
        // Reachable, if rarely: firewalld's own reads (`firewall-cmd
        // --version`, `--state`) never need more privilege than any user
        // has, but a resource-level failure to even run `--state` (EAGAIN,
        // ENOMEM, the binary swapped mid-upgrade) still sets `active_unknown`
        // -- see `Firewalld::health`'s own `Err(e)` arm on that call.
        BackendId::Firewalld => {
            "porthole could not confirm whether firewalld is enforcing anything just now. \
             This should never need more privilege than any user has, so try `porthole \
             doctor` again, or check `firewall-cmd --state` by hand for the actual reason."
        }
        BackendId::Ufw => {
            "porthole could not confirm whether ufw is enforcing anything here -- one way \
             or the other. The common reason is that reading its status needs more \
             privilege than this process has; run `porthole doctor` as root to rule that \
             out, or check `sudo ufw status` yourself for the actual reason."
        }
        BackendId::Nftables => {
            "porthole could not confirm whether nftables is filtering incoming traffic \
             here -- one way or the other. The common reason is that reading its ruleset \
             needs more privilege than this process has; run `porthole doctor` as root to \
             rule that out, or check `sudo nft -j list chains` yourself for the actual \
             reason."
        }
    }
}

/// What the bus said when we asked the helper for the rule list.
///
/// `list` is polkit-gated on the helper's side, so a refusal is *proof the
/// helper is running* — the opposite of what a swallowed error suggests.
/// Collapsing these into one "not answering" verdict makes doctor recommend
/// reinstalling a package that is already correctly installed.
enum HelperState {
    Answering(usize),
    NotOnTheBus(String),
    NoBus(String),
    Refused(String),
}

fn ask_helper(session: bool) -> HelperState {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async {
            let conn = match if session {
                zbus::Connection::session().await
            } else {
                zbus::Connection::system().await
            } {
                Ok(c) => c,
                Err(e) => return HelperState::NoBus(e.to_string()),
            };
            let proxy = match PortholeProxy::new(&conn).await {
                Ok(p) => p,
                Err(e) => return HelperState::NoBus(e.to_string()),
            };
            match proxy.list().await {
                Ok(rules) => HelperState::Answering(rules.len()),
                Err(zbus::Error::MethodError(name, detail, _)) => {
                    let message = detail.unwrap_or_else(|| name.to_string());
                    match name.as_str().rsplit('.').next().unwrap_or("") {
                        // The bus answered; nothing owns the name and nothing
                        // is activatable. The package is not installed.
                        "ServiceUnknown" | "NameHasNoOwner" | "ServiceNotFound" => {
                            HelperState::NotOnTheBus(message)
                        }
                        // Anything else came *from the helper*. It is running.
                        _ => HelperState::Refused(message),
                    }
                }
                Err(e) => HelperState::NotOnTheBus(e.to_string()),
            }
        })
}

const POLICY_PATH: &str = "/usr/share/polkit-1/actions/com.jacopobriccola.Porthole.policy";

fn helper_check(state: HelperState) -> Check {
    match state {
        HelperState::Answering(n) => Check::good("Helper", format!("answering, {n} rule(s) open")),
        // Wording unchanged from before this fix — it was already good.
        HelperState::NotOnTheBus(_detail) => Check::bad(
            "Helper",
            "not answering on the bus".to_string(),
            "Either /usr/libexec/porthole-helper is not installed, or its dbus \
             activation file is missing from /usr/share/dbus-1/system-services/. \
             Install the porthole package. Until then `porthole list`, `status` \
             and `--dry-run` still work; opening and closing do not.",
        ),
        HelperState::NoBus(detail) => Check::bad(
            "Helper",
            format!("cannot reach a bus ({detail})"),
            "No session/system bus is reachable. This is almost never the case \
             on a desktop; check what changed about how this machine starts D-Bus.",
        ),
        HelperState::Refused(detail) => Check::bad(
            "Helper",
            format!("running, but refused: {detail}"),
            &format!(
                "The helper is running and answered — this is not a missing-package \
                 problem. It refused the request, which is usually polkit: check \
                 that {POLICY_PATH} is installed and that its rules allow you. \
                 Opening and closing do not work until it does."
            ),
        ),
    }
}

fn check_helper(session: bool) -> Check {
    helper_check(ask_helper(session))
}

/// Which CLI binary the expiry timer will invoke, and whether one resolves at
/// all.
///
/// A missing timer target is invisible at open time — the open itself
/// succeeds — and surfaces only much later as a port that never closed,
/// which is exactly the kind of silent failure `doctor` exists to catch.
/// This calls `porthole_core::cli_path::resolve_cli_for` rather than
/// re-deriving the answer, so it can never disagree with what the real
/// helper will decide — the failure mode a second, hand-rolled opinion would
/// invite.
fn check_expiry_timer(session: bool) -> Check {
    // The production helper always runs as root: systemd starts it with no
    // `User=` override, so its own `resolve_cli` always sees euid 0.
    // `--session` is the unprivileged helper this same suite spawns for
    // tests, which is the only case where looking past the two system paths
    // to the CLI built alongside it applies at all — so this simulates that
    // same euid rather than always assuming privileged.
    let euid: u32 = if session {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    } else {
        0
    };
    // `resolve_cli_for`'s rules can never drift from what the real helper
    // applies -- both read this doctor process's own `CLI_CANDIDATES` -- but
    // in the unprivileged (`session`) branch, the *sibling* candidate it adds
    // is derived from `std::env::current_exe()` of whichever process calls
    // it: here, this `porthole` binary's own directory, not the session
    // helper's. They agree in the test layout only because `cargo
    // build`/`cargo test` put both binaries in the same `target/debug`, not
    // because anything guarantees it -- a `porthole` installed somewhere
    // other than alongside the `--session` helper it is diagnosing would get
    // a verdict that disagrees with what that helper actually resolves.
    match cli_path::resolve_cli_for(euid) {
        Ok(path) => Check::good(
            "Expiry timer",
            format!("will run {} when a timed opening expires", path.display()),
        ),
        Err(detail) => Check::bad(
            "Expiry timer",
            detail,
            "Without a usable CLI binary the expiry timer cannot be scheduled: \
             a timed opening would have nothing able to close it automatically \
             and would stay open until reboot. Install porthole to /usr/bin or \
             /usr/local/bin.",
        ),
    }
}

fn check_docker() -> Check {
    if !std::path::Path::new("/sys/class/net/docker0").exists() {
        return Check::good("Docker", "not present".to_string());
    }
    // Not a failure — a warning. Docker writes its own iptables rules, which
    // are evaluated before firewalld, so porthole neither sees nor controls
    // ports a container published.
    Check {
        name: "Docker",
        ok: true,
        detail: "present. A container publishing a port on 0.0.0.0 is already \
                 reachable, and porthole cannot close it: Docker's rules are \
                 evaluated before firewalld's."
            .to_string(),
        remedy: "Publish container ports on 127.0.0.1 in your compose files. \
                 Detecting which ports are affected arrives in a later release."
            .to_string(),
    }
}

fn check_ipv6(runner: &RealRunner) -> Check {
    use porthole_core::command::{Command, CommandRunner};
    let cmd = Command::read("ip", ["-6", "-o", "addr", "show", "scope", "global"]);
    let has_v6 = runner
        .run(&cmd)
        .map(|out| !out.stdout.trim().is_empty())
        .unwrap_or(false);

    if has_v6 {
        Check {
            name: "IPv6",
            ok: true,
            detail: "this machine has a global IPv6 address".to_string(),
            remedy: "porthole v1 manages IPv4 rules only. Opening or closing a \
                     port here says nothing about whether it is reachable over \
                     IPv6. Do not read a closed port as protection."
                .to_string(),
        }
    } else {
        Check::good("IPv6", "no global IPv6 address".to_string())
    }
}

/// Wrap prose to a readable width.
///
/// Counts characters, not bytes: this output contains `·` and `—`, and a
/// byte-counting wrap would break early on any line holding them.
fn wrap(text: &str, width: usize) -> Vec<String> {
    // A literal 0 would force-break at index 0 forever: `split_at` at 0 pushes
    // an empty line and hands the whole remaining string right back to the
    // `while` loop below, unchanged. Both call sites pass a fixed width today,
    // but a width computed from a terminal size can legitimately be zero — a
    // pipe, a detached process — so this is guarded here rather than trusted
    // to every future caller.
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);

        // A single token longer than `width` never fits on a line no matter
        // how much room the rest of the loop gives it — doctor prints system
        // error strings and filesystem paths, exactly where an unbroken
        // over-long token comes from. Force-break it at the width boundary
        // rather than letting it run off the line.
        while current.chars().count() > width {
            let split_at = current
                .char_indices()
                .nth(width)
                .map(|(i, _)| i)
                .unwrap_or(current.len());
            let rest = current.split_off(split_at);
            lines.push(std::mem::take(&mut current));
            current = rest;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

pub fn print_human(checks: &[Check]) {
    // Align the detail column so the eye can run down it. Names are ASCII.
    let name_width = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);

    for c in checks {
        let head = format!(
            "{}  {:name_width$}  ",
            if c.ok { "ok  " } else { "FAIL" },
            c.name,
        );
        let continuation = " ".repeat(head.chars().count());

        // Details are prose too, and some of them are long — wrap them rather
        // than emitting a 160-character line nobody will read to the end of.
        let mut detail = wrap(&c.detail, 72).into_iter();
        match detail.next() {
            Some(first) => println!("{head}{first}"),
            None => println!("{}", head.trim_end()),
        }
        for line in detail {
            println!("{continuation}{line}");
        }

        for line in wrap(&c.remedy, 68) {
            println!("        {line}");
        }
    }
}

pub fn json(checks: &[Check]) -> Value {
    json!({
        "schema": crate::output::JSON_SCHEMA,
        "checks": checks.iter().map(|c| json!({
            "name": c.name,
            "ok": c.ok,
            "detail": c.detail,
            "remedy": c.remedy,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::backend::{nftables::Nftables, ufw::Ufw, FirewallBackend};
    use porthole_core::command::{Output, RecordingRunner};

    /// Captured shape (see `nftables.rs`'s own tests for the same fixture):
    /// one base chain at the input hook, policy `accept`.
    const ONE_INPUT_CHAIN_ACCEPT: &str = r#"{"nftables":[
        {"metainfo":{"version":"1.1.3","json_schema_version":1}},
        {"chain":{"family":"inet","table":"filter","name":"input","handle":1,
                  "type":"filter","hook":"input","prio":0,"policy":"accept"}}
    ]}"#;

    /// The same chain's rule list, empty: no rule to drop or reject with.
    const NO_RULES: &str = r#"{"nftables":[
        {"metainfo":{"version":"1.1.3","json_schema_version":1}}
    ]}"#;

    /// Two base chains at the input hook -- porthole cannot prove which one
    /// decides a packet's fate.
    const TWO_INPUT_CHAINS: &str = r#"{"nftables":[
        {"metainfo":{"version":"1.1.3","json_schema_version":1}},
        {"chain":{"family":"inet","table":"filter","name":"input","handle":1,
                  "type":"filter","hook":"input","prio":0,"policy":"drop"}},
        {"chain":{"family":"ip","table":"legacy","name":"INPUT","handle":1,
                  "type":"filter","hook":"input","prio":0,"policy":"drop"}}
    ]}"#;

    /// No base chain at all at the input hook.
    const NO_INPUT_CHAINS: &str = r#"{"nftables":[
        {"metainfo":{"version":"1.1.3","json_schema_version":1}}
    ]}"#;

    #[test]
    fn ufw_active_is_ok_and_names_the_persistence_caveat_every_time() {
        // Not a failure: ufw being active is exactly what "ok" means. But the
        // caveat is a standing property of the backend, not a symptom of
        // something wrong, so it must show up on every green run, not only
        // when doctor has bad news.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("ufw 0.36.2"),
            Output::stdout("Status: active"),
        ]);
        let backend = Ufw::new(&runner);
        let check = firewall_check(&backend, &runner);
        assert!(check.ok, "detail={} remedy={}", check.detail, check.remedy);
        assert!(check.detail.contains("active"), "got: {}", check.detail);
        assert!(
            check.remedy.contains("persistent") && check.remedy.contains("reboot"),
            "the persistence caveat must be stated, got: {}",
            check.remedy
        );
    }

    #[test]
    fn nftables_two_input_chains_is_a_failure_not_a_quiet_ok() {
        // health() alone reports `active: true` here -- something at the
        // hook genuinely is enforcing -- which would read as "ok" if doctor
        // trusted `active` alone. `open`/`close` refuse outright on this
        // ruleset, so doctor must fail here too.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("nftables v1.1.6"), // --version
            Output::stdout(TWO_INPUT_CHAINS),  // health()'s own list_chains
            Output::stdout(TWO_INPUT_CHAINS),  // firewall_check's own input_chains
        ]);
        let backend = Nftables::new(&runner);
        let check = firewall_check(&backend, &runner);
        assert!(!check.ok, "two candidate chains must not read as ok");
        assert!(
            check.remedy.contains("one base chain"),
            "got: {}",
            check.remedy
        );
    }

    #[test]
    fn nftables_no_input_chain_is_a_failure_that_says_the_port_is_reachable() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("nftables v1.1.6"),
            Output::stdout(NO_INPUT_CHAINS),
        ]);
        let backend = Nftables::new(&runner);
        let check = firewall_check(&backend, &runner);
        assert!(!check.ok);
        assert!(
            check.remedy.contains("already") && check.remedy.contains("reachable"),
            "got: {}",
            check.remedy
        );
    }

    #[test]
    fn nftables_accept_policy_with_no_drop_stays_ok_but_says_so_plainly() {
        // The direction that misleads: everything is already allowed, so
        // closing a port here does not make it unreachable. This must still
        // read as "ok" (porthole did what it could prove), but the standing
        // caveat must say the dangerous part in words, not just imply it --
        // in `remedy`, following the same convention `Docker` and `IPv6`
        // already use for a standing caution on an `ok: true` check, not
        // buried in `detail` where nothing points a reader at it.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("nftables v1.1.6"),      // --version
            Output::stdout(ONE_INPUT_CHAIN_ACCEPT), // health()'s list_chains
            Output::stdout(NO_RULES),               // chain_itself_has_a_drop_or_reject
            Output::stdout(ONE_INPUT_CHAIN_ACCEPT), // firewall_check's input_chains
        ]);
        let backend = Nftables::new(&runner);
        let check = firewall_check(&backend, &runner);
        assert!(check.ok);
        assert!(
            check.remedy.contains("closing a port here"),
            "the misleading direction must be spelled out, got: {}",
            check.remedy
        );
    }

    #[test]
    fn nftables_input_chains_error_on_the_recheck_fails_closed_not_open() {
        // health() itself just ran `nft -j list chains` successfully -- this
        // test's first response -- so firewall_check's own re-check of the
        // same command failing is not evidence of a healthy single chain.
        // Discarding that error and falling through to "ok" would be a
        // diagnostic tool hiding a problem it could not actually rule out.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("nftables v1.1.6"),      // --version
            Output::stdout(ONE_INPUT_CHAIN_ACCEPT), // health()'s list_chains
            Output::stdout(NO_RULES),               // chain_itself_has_a_drop_or_reject
            Output::failure("boom"),                // firewall_check's own input_chains
        ]);
        let backend = Nftables::new(&runner);
        let check = firewall_check(&backend, &runner);
        assert!(
            !check.ok,
            "a failed re-check must not be silently treated as a healthy chain"
        );
        assert!(
            check.remedy.contains("nft -j list chains"),
            "got: {}",
            check.remedy
        );
    }

    #[test]
    fn nftables_unparseable_ruleset_is_available_not_absent_and_names_the_command() {
        // `nft --version` succeeds but `nft -j list chains` returns garbage --
        // a version whose JSON shape porthole has never seen, say. This test
        // used to assert that `health()` propagated the parse failure as an
        // `Err`; it no longer does (a fix in a later wave than the one that
        // wrote that assumption: an installed `nft` porthole cannot parse is
        // still an installed `nft`, not "no firewall found", and `detect`
        // propagates any `health()` error with `?` before `firewall_check`
        // is ever reached in production -- see
        // `detect_does_not_report_no_firewall_when_nftables_output_is_unparseable`
        // in `backend/mod.rs` for the production-path proof this test,
        // constructing `Nftables` directly, cannot give). `firewall_check`
        // must still read this as a failure -- porthole genuinely could not
        // confirm anything -- and the remedy must still give someone
        // something to run by hand.
        let unparseable = || {
            vec![
                Output::stdout("nftables v1.1.6"),
                Output::stdout("not valid nft -j output"),
            ]
        };

        // Two independent runners, same script: `firewall_check` below calls
        // `health()` again itself, and a single runner's script would run
        // out after this direct call, feeding the second call empty output
        // instead of the fixture -- a different, accidental scenario rather
        // than the one this test is actually about.
        let health_runner = RecordingRunner::with_responses(unparseable());
        let health = Nftables::new(&health_runner).health().expect(
            "a parse failure must degrade to Ok(active_unknown: true), never propagate as Err",
        );
        assert!(
            health.available,
            "the binary is there; that must stand alone"
        );
        assert!(health.active_unknown);

        let runner = RecordingRunner::with_responses(unparseable());
        let backend = Nftables::new(&runner);
        let check = firewall_check(&backend, &runner);
        assert!(!check.ok);
        assert!(
            check.remedy.contains("nft -j list chains"),
            "got: {}",
            check.remedy
        );
    }

    #[test]
    fn nftables_active_unknown_does_not_claim_reachability_either_way() {
        // Follow-up to C1: `active: false` on nftables now has two different
        // causes -- a confirmed-empty input hook (`not_active_remedy`'s "the
        // port is already reachable"), and a permission-denied read that
        // tells porthole nothing at all. That sentence is true of the first
        // and false, in the dangerous direction, of the second. Assert on
        // the property -- no claim about reachability in either direction --
        // rather than the literal sentence, so a future rewording of either
        // remedy cannot quietly reintroduce it.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("nftables v1.1.6"),
            Output {
                status: 1,
                stdout: String::new(),
                stderr: "Error: Operation not permitted (you must be root)".to_string(),
            },
        ]);
        let backend = Nftables::new(&runner);
        let check = firewall_check(&backend, &runner);
        assert!(
            !check.ok,
            "porthole genuinely does not know here -- must not read as ok"
        );
        assert!(
            !check.remedy.to_lowercase().contains("reachable"),
            "must not claim the port is reachable, or that it is not, when porthole \
             could not read the ruleset at all: {}",
            check.remedy
        );
        assert!(
            check.remedy.contains("root") || check.remedy.contains("privilege"),
            "must say the actual reason -- needs privilege -- got: {}",
            check.remedy
        );
    }

    #[test]
    fn ufw_active_unknown_does_not_claim_reachability_either_way() {
        // Same follow-up, ufw's shape: `not_active_remedy`'s "Enable it --
        // `sudo ufw enable`. While it is disabled, ..." is a claim that ufw
        // is confirmed disabled, which is false when the truth is porthole
        // could not read its status at all.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("ufw 0.36.2"),
            Output {
                status: 1,
                stdout: String::new(),
                stderr: "ERROR: You need to be root to run this script".to_string(),
            },
        ]);
        let backend = Ufw::new(&runner);
        let check = firewall_check(&backend, &runner);
        assert!(
            !check.ok,
            "porthole genuinely does not know here -- must not read as ok"
        );
        assert!(
            !check.remedy.to_lowercase().contains("disabled")
                && !check.remedy.to_lowercase().contains("reachable"),
            "must not claim ufw is confirmed disabled, or say anything about \
             reachability, when porthole could not read its status at all: {}",
            check.remedy
        );
        assert!(
            check.remedy.contains("root") || check.remedy.contains("privilege"),
            "must say the actual reason -- needs privilege -- got: {}",
            check.remedy
        );
    }

    #[test]
    fn answering_is_ok() {
        let check = helper_check(HelperState::Answering(3));
        assert!(check.ok);
        assert!(check.detail.contains('3'));
    }

    #[test]
    fn not_on_the_bus_is_a_failure_that_says_install_the_package() {
        let check = helper_check(HelperState::NotOnTheBus(
            "The name is not activatable".to_string(),
        ));
        assert!(!check.ok);
        assert!(check.remedy.contains("Install the porthole package"));
    }

    #[test]
    fn no_bus_is_a_failure() {
        let check = helper_check(HelperState::NoBus("no connection".to_string()));
        assert!(!check.ok);
    }

    #[test]
    fn the_expiry_timer_check_reports_the_same_candidates_resolve_cli_would() {
        // This is deliberately not a check on doctor's own logic in isolation:
        // the whole point of reusing `cli_path::resolve_cli_for` is that
        // doctor cannot silently drift from what the real helper decides. On
        // a machine with no `porthole` installed at either system path (true
        // of this test environment), a *privileged* resolution (euid 0, what
        // the real systemd-started helper always is) must fail exactly the
        // way `resolve_cli_for(0)` fails on its own.
        let check = check_expiry_timer(false);
        let expected_ok = cli_path::resolve_cli_for(0).is_ok();
        assert_eq!(
            check.ok, expected_ok,
            "doctor disagreed with resolve_cli_for"
        );
        if !check.ok {
            assert!(
                !check.remedy.is_empty(),
                "a failing check must say what to do"
            );
        }
    }

    #[test]
    fn refused_is_a_failure_that_names_the_policy_and_does_not_say_install() {
        // A refusal is proof the helper is running: the fix is polkit, not
        // reinstalling a package that is already there. Getting this backwards
        // is exactly the wrong-lead bug this mapping exists to prevent.
        let check = helper_check(HelperState::Refused("Not authorized".to_string()));
        assert!(!check.ok);
        assert!(check.detail.contains("Not authorized"));
        assert!(check.remedy.contains(POLICY_PATH));
        assert!(!check
            .remedy
            .to_lowercase()
            .contains("install the porthole package"));
    }

    #[test]
    fn a_zero_width_returns_rather_than_looping_forever() {
        // Before the `width.max(1)` guard, `wrap("hi", 0)` never returned:
        // splitting at index 0 pushes an empty line and hands the whole
        // string right back, forever. Asserting on the result (not merely
        // that the call returns at all) is what would have caught a
        // regression that made the guard a no-op.
        let lines = wrap("hi", 0);
        assert!(!lines.is_empty());
        for line in &lines {
            assert!(line.chars().count() <= 1, "got: {line:?}");
        }
    }

    #[test]
    fn wrap_never_returns_a_line_longer_than_width() {
        let width = 10;
        let long_token = "a".repeat(37);
        let text = format!("short {long_token} words after");
        for line in wrap(&text, width) {
            assert!(
                line.chars().count() <= width,
                "line {line:?} exceeds width {width}"
            );
        }
    }
}
