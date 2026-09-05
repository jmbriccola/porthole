//! `porthole doctor` — why it is not working, and what to do.
//!
//! The spec asks for this by name: across three distributions, three
//! firewalls, a system D-Bus service and Docker, the first problem every user
//! has is "it does not work and I do not know why". So every check says what
//! it looked for, what it found, and what to do about it. A check that reports
//! a problem without a remedy has done half the job — and it is the half a
//! stuck user cannot supply for themselves.

use porthole_core::backend;
use porthole_core::command::RealRunner;
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
        Ok(backend) => match backend.health() {
            Ok(h) if h.active => Check::good("Firewall", h.detail),
            Ok(h) => Check::bad(
                "Firewall",
                h.detail,
                "Start it — `sudo systemctl start firewalld`. While it is stopped, \
                 nothing porthole does changes what is reachable.",
            ),
            Err(e) => Check::bad(
                "Firewall",
                e.to_string(),
                "`systemctl status firewalld` to see whether it is running, and \
                 `journalctl -u firewalld -n 50` for why it is not.",
            ),
        },
        Err(e) => Check::bad(
            "Firewall",
            e.to_string(),
            "porthole 0.2 manages firewalld. Install it, or wait for the ufw and \
             nftables backends. porthole will not install one for you.",
        ),
    });

    checks.push(check_helper(session));

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
