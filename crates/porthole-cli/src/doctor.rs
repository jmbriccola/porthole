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
            Err(e) => Check::bad("Firewall", e.to_string(), "Check the firewall service."),
        },
        Err(e) => Check::bad(
            "Firewall",
            e.to_string(),
            "porthole 0.2 manages firewalld. Install it, or wait for the ufw and \
             nftables backends. porthole will not install one for you.",
        ),
    });

    checks.push(check_helper(session));

    let policy = "/usr/share/polkit-1/actions/com.jacopobriccola.Porthole.policy";
    checks.push(if std::path::Path::new(policy).exists() {
        Check::good("polkit", format!("{policy} is installed"))
    } else {
        Check::bad(
            "polkit",
            format!("{policy} is not installed"),
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
            "porthole opens ports towards the network you are on. There is none.",
        ),
    });

    checks.push(check_docker());
    checks.push(check_ipv6(&runner));

    checks
}

fn check_helper(session: bool) -> Check {
    let reachable = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async {
            let conn = if session {
                zbus::Connection::session().await
            } else {
                zbus::Connection::system().await
            }
            .ok()?;
            let proxy = PortholeProxy::new(&conn).await.ok()?;
            proxy.list().await.ok().map(|rules| rules.len())
        });

    match reachable {
        Some(n) => Check::good("Helper", format!("answering, {n} rule(s) open")),
        None => Check::bad(
            "Helper",
            "not answering on the bus".to_string(),
            "Either /usr/libexec/porthole-helper is not installed, or its dbus \
             activation file is missing from /usr/share/dbus-1/system-services/. \
             Install the porthole package. Until then `porthole list`, `status` \
             and `--dry-run` still work; opening and closing do not.",
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

pub fn print_human(checks: &[Check]) {
    for c in checks {
        println!(
            "{}  {}  {}",
            if c.ok { "ok  " } else { "FAIL" },
            c.name,
            c.detail
        );
        if !c.remedy.is_empty() {
            for line in c.remedy.split_whitespace().collect::<Vec<_>>().chunks(11) {
                println!("        {}", line.join(" "));
            }
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
