//! Rendering. Two audiences: a person reading a terminal, and a script reading
//! `--json`.
//!
//! The JSON shape is a public interface and is documented in
//! `docs/json-schema.md`. Add fields; do not rename or remove them.

use porthole_core::backend::BackendId;
use porthole_core::command::Command;
use porthole_core::engine::Status;
use porthole_core::error::Error;
use porthole_core::listening::{Binding, Service};
use porthole_core::model::Target;
use porthole_core::state::ManagedRule;
use serde_json::{json, Value};

/// The version of the `--json` output shape.
pub const JSON_SCHEMA: u32 = 1;

/// A countdown as a person would say it.
pub fn format_remaining(seconds: Option<u64>) -> String {
    match seconds {
        None => "until reboot".to_string(),
        Some(0) => "now".to_string(),
        Some(s) if s < 60 => format!("{s}s"),
        Some(s) if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        Some(s) => format!("{}h {}m", s / 3600, (s % 3600) / 60),
    }
}

fn scope_name(target: &Target) -> &'static str {
    match target {
        Target::Network { .. } => "network",
        Target::Anywhere => "anywhere",
    }
}

fn rule_json(rule: &ManagedRule, now: u64) -> Value {
    json!({
        "id": rule.id,
        "port": rule.port,
        "protocol": rule.protocol.to_string(),
        "target": rule.target.to_string(),
        "scope": scope_name(&rule.target),
        "backend": rule.backend.to_string(),
        "opened_at": rule.opened_at,
        "expires_at": rule.expires_at,
        "expires_in_seconds": rule.expires_in(now),
        "uid": rule.uid,
    })
}

pub fn json_rules(rules: &[ManagedRule], now: u64) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "rules": rules.iter().map(|r| rule_json(r, now)).collect::<Vec<_>>(),
    })
}

pub fn json_status(status: &Status, now: u64) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "backend": status.backend.to_string(),
        "firewall_available": status.health.available,
        "firewall_active": status.health.active,
        // `false` in every case that exists before this field was added, and
        // a script reading only `firewall_active` behaves exactly as it
        // always has: this is `true` only in the one new case --
        // `firewall_active: false` because ufw or nftables refused a
        // permission-denied ruleset read, not because porthole confirmed
        // nothing is enforcing. Without this, a script has strictly less
        // information than a human running plain `status`, who at least
        // sees `firewall_caveat`-adjacent detail prose explaining the
        // difference -- see `BackendHealth::active_unknown`'s own doc
        // comment for why the two facts cannot share one boolean.
        "firewall_active_unknown": status.health.active_unknown,
        "firewall_version": status.health.version,
        "firewall_caveat": status.health.caveat,
        "location": status.location,
        "network": status.network.as_ref().map(|n| json!({
            "interface": n.interface,
            "address": n.address.to_string(),
            "cidr": n.cidr.to_string(),
        })),
        "rules": status.rules.iter().map(|r| rule_json(r, now)).collect::<Vec<_>>(),
    })
}

/// The label `print_status` puts in front of `location` -- the concept
/// `location` names is different per backend (a firewalld zone is not a ufw
/// chain), so the word in front of it has to change too, or the label lies
/// for two out of three backends.
fn location_label(backend: BackendId) -> &'static str {
    match backend {
        BackendId::Firewalld => "Zone",
        BackendId::Ufw => "Location",
        BackendId::Nftables => "Chain",
    }
}

fn error_json(error: &Error) -> Value {
    json!({
        "code": error.exit_code() as i32,
        "kind": error.kind(),
        "message": error.to_string(),
    })
}

pub fn json_error(error: &Error) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "error": error_json(error),
    })
}

pub fn print_rules(rules: &[ManagedRule], now: u64) {
    if rules.is_empty() {
        println!("No ports open.");
        return;
    }

    let rows: Vec<[String; 4]> = rules
        .iter()
        .map(|r| {
            [
                format!("{}/{}", r.port, r.protocol),
                r.target.to_string(),
                r.backend.to_string(),
                format_remaining(r.expires_in(now)),
            ]
        })
        .collect();

    let headers = ["PORT", "TOWARDS", "BACKEND", "CLOSES IN"];
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let line = |cells: [&str; 4]| {
        let mut out = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i == cells.len() - 1 {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{:width$}  ", cell, width = widths[i]));
            }
        }
        out
    };

    println!("{}", line(headers));
    for row in &rows {
        println!(
            "{}",
            line([
                row[0].as_str(),
                row[1].as_str(),
                row[2].as_str(),
                row[3].as_str()
            ])
        );
    }
}

pub fn json_opened(rule: &ManagedRule, now: u64, dry_run: bool, commands: &[Command]) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "dry_run": dry_run,
        "rule": rule_json(rule, now),
        "commands": commands.iter().map(Command::display).collect::<Vec<_>>(),
    })
}

pub fn print_opened(rule: &ManagedRule, now: u64) {
    println!(
        "Opened {}/{} towards {} · closes {}",
        rule.port,
        rule.protocol,
        rule.target,
        format_remaining(rule.expires_in(now))
    );
}

pub fn print_dry_run(commands: &[Command]) {
    println!();
    if commands.is_empty() {
        println!("No firewall changes would be made.");
        return;
    }
    println!("Would run:");
    for command in commands {
        println!("  {}", command.display());
    }
    println!();
    println!("Nothing was changed.");
}

/// `--all` can partly succeed, so failures belong inside this object rather
/// than in a second one printed afterwards: two top-level objects on stdout
/// are unparseable by any JSON reader.
///
/// `forgotten` is `--forget`: the eighth instance of this milestone's own
/// pattern was this function itself, immediately below `print_closed`'s own
/// guard against exactly this, putting a forgotten rule in `closed` --
/// which `docs/json-schema.md` documents as "rules that closed" -- when
/// nothing was closed in any firewall, only porthole's own record was
/// dropped. A script (or a GUI reading `WireStatus`) that trusted `closed`
/// here would record a port as shut that may still be open in a firewall
/// porthole can no longer reach.
///
/// `rules` goes into `forgotten` instead of `closed` when `forgotten` is
/// `true`, never both: `--forget` always resolves to at most one rule (see
/// `Engine::close_by_id`'s own doc comment), so a single call is either an
/// ordinary close/close-all or a forget, never a mix.
pub fn json_closed(
    rules: &[ManagedRule],
    errors: &[Error],
    now: u64,
    dry_run: bool,
    forgotten: bool,
    commands: &[Command],
) -> Value {
    let rule_jsons: Vec<Value> = rules.iter().map(|r| rule_json(r, now)).collect();
    let (closed, forgotten_rules) = if forgotten {
        (Vec::new(), rule_jsons)
    } else {
        (rule_jsons, Vec::new())
    };
    json!({
        "schema": JSON_SCHEMA,
        "dry_run": dry_run,
        "closed": closed,
        "forgotten": forgotten_rules,
        "errors": errors.iter().map(error_json).collect::<Vec<_>>(),
        "commands": commands.iter().map(Command::display).collect::<Vec<_>>(),
    })
}

/// `forgotten` is `--forget`: nothing was closed in any firewall, only
/// porthole's own record of the rule was dropped, so saying "Closed" would
/// be exactly the overclaim the rest of this milestone spent so much effort
/// removing elsewhere. `--forget` only ever resolves to a single rule (see
/// `Engine::close_by_id`'s own doc comment), but `rules` still takes a slice
/// so this stays one function for every shape `close` can report.
pub fn print_closed(rules: &[ManagedRule], dry_run: bool, forgotten: bool) {
    if rules.is_empty() {
        println!("Nothing to close.");
        return;
    }
    let verb = match (dry_run, forgotten) {
        (false, false) => "Closed",
        (true, false) => "Would close",
        (false, true) => "Forgot",
        (true, true) => "Would forget",
    };
    for rule in rules {
        let suffix = if forgotten {
            " (no firewall was touched)"
        } else {
            ""
        };
        println!(
            "{verb} {}/{} towards {}{suffix}",
            rule.port, rule.protocol, rule.target
        );
    }
}

/// The word `print_status` puts in parentheses after the backend's name and
/// version -- split out from `print_status` itself so this three-way choice
/// is testable without capturing stdout.
///
/// Three states, not two: `active: false` alone does not mean "confirmed not
/// running" -- ufw and nftables can also come back this way when porthole
/// could not read enough of the ruleset to tell (see
/// `BackendHealth::active_unknown`). Printing "NOT running" for that case
/// would tell an unprivileged user their port is already reachable when the
/// truth is porthole simply could not see the ruleset -- false in the
/// dangerous direction, and the same claim `doctor`'s remedy selection
/// exists to avoid making.
fn firewall_state_word(health: &porthole_core::backend::BackendHealth) -> &'static str {
    if health.active {
        "running"
    } else if health.active_unknown {
        "unknown"
    } else {
        "NOT running"
    }
}

pub fn print_status(status: &Status, now: u64) {
    let firewall = if !status.health.available {
        // Not "firewalld (NOT running)" — there is no firewalld to run.
        "none installed".to_string()
    } else {
        let state = firewall_state_word(&status.health);
        match &status.health.version {
            Some(v) => format!("{} {} ({state})", status.backend, v),
            None => format!("{} ({state})", status.backend),
        }
    };
    println!("Firewall  {firewall}");
    if let Some(location) = &status.location {
        println!("{:<9} {location}", location_label(status.backend));
    }
    match &status.network {
        Some(n) => println!("Network   {} · {}", n.interface, n.cidr),
        None => println!("Network   not connected"),
    }
    println!();

    if status.health.available && !status.health.active {
        println!("{}", status.health.detail);
        if status.health.active_unknown {
            // Do not repeat the confirmed-inactive sentence below: it
            // asserts the firewall is not running, which is exactly the
            // claim this state cannot support either way.
            println!(
                "porthole could not confirm whether this firewall is enforcing anything -- \
                 see the detail above for why."
            );
        } else {
            println!(
                "While the firewall is not running, nothing porthole does changes what is \
                 reachable."
            );
        }
        println!();
    } else if !status.health.available {
        println!("{}", status.health.detail);
        println!();
    } else if let Some(caveat) = &status.health.caveat {
        // A caveat is a standing property of an *active, available* backend
        // (nftables' accepting-chain warning is the only one today) — the
        // two branches above already cover "not active"/"not installed", so
        // this is reached only when neither of those applies. `status` is
        // where a user actually looks; leaving this out here just because
        // `active` reads as healthy is exactly the safe-looking silence
        // docs/backends.md promises does not happen.
        println!("{caveat}");
        println!();
    }

    print_rules(&status.rules, now);
}

/// The `binding` tag `porthole listen --json` reports. A plain string, not
/// `Target`'s `{"kind": ...}` shape: `Binding::Specific`'s address is already
/// carried in `address` above it, so there is nothing more for the tag to
/// hold than which case this is.
fn binding_tag(binding: &Binding) -> &'static str {
    match binding {
        Binding::LoopbackOnly => "loopback_only",
        Binding::AllInterfaces => "all_interfaces",
        Binding::Specific(_) => "specific",
        Binding::BeyondReach(_) => "beyond_reach",
    }
}

fn service_json(service: &Service) -> Value {
    json!({
        "port": service.port,
        "protocol": service.protocol.to_string(),
        "address": service.address.to_string(),
        "binding": binding_tag(&service.binding),
        "process": service.process,
        "pid": service.pid,
    })
}

pub fn json_listening(services: &[Service]) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "services": services.iter().map(service_json).collect::<Vec<_>>(),
    })
}

/// `porthole listen` for a person. Grouped into up to three labelled
/// sections rather than one flat list with a per-row "open" affordance:
///
/// - network-facing rows (`AllInterfaces`/`Specific`), unlabelled, at the
///   top — these are the actionable ones, worth `porthole open`ing.
/// - `BeyondReach` rows, if any: reachable over IPv6, but porthole manages
///   IPv4 rules only and cannot open or close a rule for them. This is
///   deliberately **not** worded as "changes nothing" -- unlike loopback-only,
///   these sockets are exposed to the network; porthole is simply blind to
///   that exposure. Conflating the two headings would be exactly the
///   understated-risk bug `Binding::BeyondReach`'s own doc comment guards
///   against.
/// - `LoopbackOnly` rows, labelled plainly: on an ordinary desktop these are
///   usually the majority of the list (see `milestone-4-verified-facts.md`),
///   and opening the firewall for one of them genuinely changes nothing,
///   since the process is not listening on a network interface at all.
pub fn print_listening(services: &[Service]) {
    print!("{}", render_listening(services));
}

/// The text `print_listening` prints, built as a `String` rather than
/// printed line-by-line so tests can assert on it directly -- see the
/// `BeyondReach` tests below, which check a *property* of this text (it must
/// never claim the service is unreachable), not a literal sentence.
fn render_listening(services: &[Service]) -> String {
    use std::fmt::Write as _;
    let w = "writing to a String cannot fail";
    let mut out = String::new();
    writeln!(out, "Listening on this machine").expect(w);
    writeln!(out).expect(w);

    if services.is_empty() {
        writeln!(out, "Nothing is listening.").expect(w);
        return out;
    }

    // One set of column widths across every group, so the lists still read
    // as one table rather than several differently-aligned ones.
    let port_width = services
        .iter()
        .map(|s| format!("{}/{}", s.port, s.protocol).len())
        .max()
        .unwrap_or(0);
    let name_width = services
        .iter()
        .map(|s| s.process.as_deref().unwrap_or("—").chars().count())
        .max()
        .unwrap_or(0);

    let network_facing: Vec<&Service> = services
        .iter()
        .filter(|s| matches!(s.binding, Binding::AllInterfaces | Binding::Specific(_)))
        .collect();
    let beyond_reach: Vec<&Service> = services
        .iter()
        .filter(|s| matches!(s.binding, Binding::BeyondReach(_)))
        .collect();
    let loopback: Vec<&Service> = services
        .iter()
        .filter(|s| s.binding == Binding::LoopbackOnly)
        .collect();

    append_listening_rows(&mut out, &network_facing, port_width, name_width);

    if !beyond_reach.is_empty() {
        if !network_facing.is_empty() {
            writeln!(out).expect(w);
        }
        writeln!(
            out,
            "Reachable over IPv6 — porthole manages IPv4 firewall rules only and cannot \
             open or close these:"
        )
        .expect(w);
        append_listening_rows(&mut out, &beyond_reach, port_width, name_width);
    }

    if !loopback.is_empty() {
        if !network_facing.is_empty() || !beyond_reach.is_empty() {
            writeln!(out).expect(w);
        }
        writeln!(
            out,
            "Loopback only — opening the firewall for these changes nothing:"
        )
        .expect(w);
        append_listening_rows(&mut out, &loopback, port_width, name_width);
    }

    out
}

fn append_listening_rows(
    out: &mut String,
    services: &[&Service],
    port_width: usize,
    name_width: usize,
) {
    use std::fmt::Write as _;
    for service in services {
        let port_proto = format!("{}/{}", service.port, service.protocol);
        let process = service.process.as_deref().unwrap_or("—").to_string();
        let pid = service
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        writeln!(
            out,
            "  {port_proto:port_width$}  {process:name_width$}  pid {pid}"
        )
        .expect("writing to a String cannot fail");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::backend::{BackendId, RuleHandle};
    use porthole_core::model::{Protocol, Target};
    use porthole_core::state::ManagedRule;

    fn rule() -> ManagedRule {
        ManagedRule {
            id: "1f0c8b6e-0000-4000-8000-000000000001".into(),
            port: 5173,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            backend: BackendId::Firewalld,
            opened_at: 1_757_000_000,
            expires_at: Some(1_757_003_600),
            uid: 1000,
            handle: RuleHandle::Firewalld {
                zone: "FedoraWorkstation".into(),
                rich_rule: "rule ...".into(),
            },
        }
    }

    #[test]
    fn remaining_time_reads_the_way_a_person_would_say_it() {
        assert_eq!(format_remaining(None), "until reboot");
        assert_eq!(format_remaining(Some(0)), "now");
        assert_eq!(format_remaining(Some(1)), "1s");
        assert_eq!(format_remaining(Some(59)), "59s");
        assert_eq!(format_remaining(Some(60)), "1m 0s");
        assert_eq!(format_remaining(Some(3432)), "57m 12s");
        assert_eq!(format_remaining(Some(3600)), "1h 0m");
        assert_eq!(format_remaining(Some(28800)), "8h 0m");
    }

    #[test]
    fn json_rules_has_the_documented_shape() {
        let json = json_rules(&[rule()], 1_757_000_000);
        assert_eq!(json["schema"], 1);
        let r = &json["rules"][0];
        assert_eq!(r["id"], "1f0c8b6e-0000-4000-8000-000000000001");
        assert_eq!(r["port"], 5173);
        assert_eq!(r["protocol"], "tcp");
        assert_eq!(r["target"], "10.10.10.0/24");
        assert_eq!(r["scope"], "network");
        assert_eq!(r["backend"], "firewalld");
        assert_eq!(r["opened_at"], 1_757_000_000_u64);
        assert_eq!(r["expires_at"], 1_757_003_600_u64);
        assert_eq!(r["expires_in_seconds"], 3600);
        assert_eq!(r["uid"], 1000);
    }

    #[test]
    fn an_until_reboot_rule_has_null_expiry_in_json() {
        let forever = ManagedRule {
            expires_at: None,
            ..rule()
        };
        let json = json_rules(&[forever], 1_757_000_000);
        assert!(json["rules"][0]["expires_at"].is_null());
        assert!(json["rules"][0]["expires_in_seconds"].is_null());
    }

    #[test]
    fn json_errors_carry_a_code_and_a_stable_kind() {
        use porthole_core::error::Error;
        let json = json_error(&Error::RuleNotFound("5173/tcp".into()));
        assert_eq!(json["schema"], 1);
        assert_eq!(json["error"]["code"], 7);
        assert_eq!(json["error"]["kind"], "rule_not_found");
        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("5173/tcp"));
    }

    #[test]
    fn json_status_can_report_that_there_is_no_firewall() {
        // This field was unreachable until `status` learned to answer in its
        // own shape rather than failing: `detect` errors exactly when the
        // firewall is absent, so nothing could ever emit `available: false`.
        use porthole_core::backend::{BackendHealth, BackendId};
        use porthole_core::engine::Status;

        let status = Status {
            backend: BackendId::Firewalld,
            health: BackendHealth {
                available: false,
                active: false,
                active_unknown: false,
                version: None,
                detail: "no supported firewall found".to_string(),
                caveat: None,
            },
            network: None,
            location: None,
            rules: Vec::new(),
        };

        let json = json_status(&status, 1_757_000_000);
        assert_eq!(json["firewall_available"], false);
        assert_eq!(json["firewall_active"], false);
        // No firewall at all is not the permission-denied case: there is
        // nothing porthole failed to read, only nothing to read at all.
        assert_eq!(json["firewall_active_unknown"], false);
        assert!(json["firewall_version"].is_null());
        assert!(json["firewall_caveat"].is_null());
        assert!(json["network"].is_null());
        assert!(json["location"].is_null());
    }

    #[test]
    fn a_standing_caveat_reaches_json_status_even_while_active() {
        // The bug this guards against: `print_status`/`json_status` used to
        // gate all of `health.detail` on `!active`, so a caveat that only
        // exists when the backend *is* active (nftables' accepting-chain
        // warning) could never reach a script reading `--json`, or a person
        // reading plain `status`. `caveat` must not depend on `active` to be
        // seen.
        use porthole_core::backend::{BackendHealth, BackendId};
        use porthole_core::engine::Status;

        let status = Status {
            backend: BackendId::Nftables,
            health: BackendHealth {
                available: true,
                active: true,
                active_unknown: false,
                version: Some("1.1.6".to_string()),
                detail: "1.1.6: inet filter input is enforcing".to_string(),
                caveat: Some(
                    "its policy is accept and no rule in this chain drops or rejects".to_string(),
                ),
            },
            network: None,
            location: Some("inet filter input".to_string()),
            rules: Vec::new(),
        };

        let json = json_status(&status, 1_757_000_000);
        assert_eq!(json["firewall_active"], true);
        assert_eq!(
            json["firewall_caveat"],
            "its policy is accept and no rule in this chain drops or rejects"
        );
    }

    #[test]
    fn a_healthy_backend_with_no_caveat_has_a_null_json_caveat() {
        // The other half of the same guard: a backend with nothing special
        // to say must not invent one, or every plain "it's fine" status
        // would grow a phantom caveat.
        use porthole_core::backend::{BackendHealth, BackendId};
        use porthole_core::engine::Status;

        let status = Status {
            backend: BackendId::Firewalld,
            health: BackendHealth {
                available: true,
                active: true,
                active_unknown: false,
                version: Some("2.4.4".to_string()),
                detail: "firewalld 2.4.4 is running".to_string(),
                caveat: None,
            },
            network: None,
            location: Some("FedoraWorkstation".to_string()),
            rules: Vec::new(),
        };

        let json = json_status(&status, 1_757_000_000);
        assert!(json["firewall_caveat"].is_null());
    }

    #[test]
    fn the_unknown_activity_state_never_reads_as_confirmed_not_running() {
        // Follow-up to C1: `print_status` used to have only two states
        // (running / NOT running), keyed on `active` alone. A
        // permission-denied ufw or nftables read comes back `active: false`
        // too, and printing "NOT running" for that would tell an
        // unprivileged user their port is already reachable when porthole
        // in fact could not see the ruleset at all -- false in the
        // dangerous direction. Assert on the property (the confirmed-not-
        // running word is absent), not the exact wording of the word this
        // state does print, so a future rewording of either cannot quietly
        // collapse the two states back together.
        //
        // Both renderers are checked against the *same* fixture here rather
        // than in two separate tests, human (`firewall_state_word`, the
        // piece `print_status` uses) and machine (`json_status`'s
        // `firewall_active_unknown`) alike: a script reading `--json` has no
        // sentence to fall back on the way a human reading `detail` does, so
        // it needs this distinction at least as much, and the two output
        // modes disagreeing about what exists is exactly the hazard this
        // milestone has already had once.
        use porthole_core::backend::{BackendHealth, BackendId};
        use porthole_core::engine::Status;

        let confirmed_inactive = BackendHealth {
            available: true,
            active: false,
            active_unknown: false,
            version: None,
            detail: String::new(),
            caveat: None,
        };
        assert_eq!(firewall_state_word(&confirmed_inactive), "NOT running");

        let unknown = BackendHealth {
            available: true,
            active: false,
            active_unknown: true,
            version: None,
            detail: String::new(),
            caveat: None,
        };
        let word = firewall_state_word(&unknown);
        assert_ne!(
            word, "NOT running",
            "an unread ruleset must not print the same word as a confirmed one"
        );
        assert_ne!(word, "running", "porthole did not confirm this either");

        let status = Status {
            backend: BackendId::Ufw,
            health: unknown,
            network: None,
            location: None,
            rules: Vec::new(),
        };
        let json = json_status(&status, 1_757_000_000);
        assert_eq!(
            json["firewall_active"], false,
            "unchanged: a script reading only this field must behave exactly as before"
        );
        assert_eq!(
            json["firewall_active_unknown"], true,
            "a script that cares can now tell this apart from a confirmed-inactive backend"
        );
    }

    #[test]
    fn location_label_names_the_concept_each_backend_actually_uses() {
        // "Zone" printed for a ufw or nftables location would be a label
        // that means nothing there -- see docs/json-schema.md's own table of
        // what `location` holds per backend.
        assert_eq!(location_label(BackendId::Firewalld), "Zone");
        assert_eq!(location_label(BackendId::Ufw), "Location");
        assert_eq!(location_label(BackendId::Nftables), "Chain");
    }

    #[test]
    fn the_empty_list_is_an_empty_array_not_a_missing_key() {
        let json = json_rules(&[], 1_757_000_000);
        assert_eq!(json["rules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn json_closed_puts_failures_in_the_same_object() {
        // `--all` can partly fail. The output has to stay ONE object: a second
        // top-level object on stdout is unparseable by any JSON reader, and a
        // script asking what closed would see only the first one.
        use porthole_core::error::Error;

        let json = json_closed(
            &[],
            &[Error::RuleNotFound("9999/tcp".to_string())],
            1_757_000_000,
            false,
            false,
            &[],
        );
        assert_eq!(json["schema"], 1);
        assert_eq!(json["closed"].as_array().unwrap().len(), 0);
        assert_eq!(json["errors"].as_array().unwrap().len(), 1);
        assert_eq!(json["errors"][0]["kind"], "rule_not_found");
        assert_eq!(json["errors"][0]["code"], 7);
    }

    #[test]
    fn json_closed_never_reports_a_forgotten_rule_as_closed() {
        // The eighth instance of this milestone's own pattern: `print_closed`
        // was taught never to say "Closed" for a forget, in the same commit
        // that left this function saying exactly that in `closed` -- which
        // `docs/json-schema.md` documents as "rules that closed". A script
        // (or a GUI reading `WireStatus`, widened one wave ago for precisely
        // this reason) trusting `closed` here would record a port as shut
        // that may still be open in a firewall porthole can no longer reach.
        let json = json_closed(&[rule()], &[], 1_757_000_000, true, true, &[]);
        assert_eq!(
            json["closed"].as_array().unwrap().len(),
            0,
            "a forgotten rule must never appear in `closed`: {json}"
        );
        let forgotten = json["forgotten"].as_array().unwrap();
        assert_eq!(
            forgotten.len(),
            1,
            "it must appear in `forgotten` instead: {json}"
        );
        assert_eq!(forgotten[0]["id"], "1f0c8b6e-0000-4000-8000-000000000001");
    }

    #[test]
    fn json_closed_puts_an_ordinary_close_in_closed_never_forgotten() {
        // The other half of the same guard: an ordinary close (or close
        // --all) must not grow a phantom `forgotten` entry just because the
        // field exists now.
        let json = json_closed(&[rule()], &[], 1_757_000_000, false, false, &[]);
        assert_eq!(json["closed"].as_array().unwrap().len(), 1);
        assert_eq!(json["forgotten"].as_array().unwrap().len(), 0);
    }

    fn service(port: u16, binding: Binding, process: Option<&str>, pid: Option<u32>) -> Service {
        use porthole_core::model::Protocol;
        use std::net::{IpAddr, Ipv4Addr};

        let address = match binding {
            Binding::LoopbackOnly => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Binding::AllInterfaces => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Binding::Specific(a) => IpAddr::V4(a),
            Binding::BeyondReach(a) => IpAddr::V6(a),
        };
        Service {
            port,
            protocol: Protocol::Tcp,
            address,
            binding,
            process: process.map(str::to_string),
            pid,
        }
    }

    #[test]
    fn json_listening_has_the_documented_shape() {
        let services = vec![service(
            5173,
            Binding::AllInterfaces,
            Some("node"),
            Some(12043),
        )];
        let json = json_listening(&services);
        assert_eq!(json["schema"], 1);
        let svc = &json["services"][0];
        assert_eq!(svc["port"], 5173);
        assert_eq!(svc["protocol"], "tcp");
        assert_eq!(svc["address"], "0.0.0.0");
        assert_eq!(svc["binding"], "all_interfaces");
        assert_eq!(svc["process"], "node");
        assert_eq!(svc["pid"], 12043);
    }

    #[test]
    fn an_unresolved_process_is_null_in_json_never_a_placeholder_string() {
        // A script must be able to tell "porthole could not resolve this" from
        // "the process is actually named that" -- a literal "unknown" string
        // would erase exactly that distinction.
        let services = vec![service(53, Binding::LoopbackOnly, None, None)];
        let json = json_listening(&services);
        assert!(json["services"][0]["process"].is_null());
        assert!(json["services"][0]["pid"].is_null());
    }

    #[test]
    fn a_specific_binding_reports_the_specific_tag() {
        let services = vec![service(
            8080,
            Binding::Specific("10.10.10.5".parse().unwrap()),
            None,
            None,
        )];
        let json = json_listening(&services);
        assert_eq!(json["services"][0]["binding"], "specific");
        assert_eq!(json["services"][0]["address"], "10.10.10.5");
    }

    #[test]
    fn the_empty_listening_list_is_an_empty_array_not_a_missing_key() {
        let json = json_listening(&[]);
        assert_eq!(json["services"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn a_beyond_reach_binding_reports_its_own_tag_and_address() {
        let services = vec![service(
            9999,
            Binding::BeyondReach("2001:db8::1".parse().unwrap()),
            None,
            None,
        )];
        let json = json_listening(&services);
        assert_eq!(json["services"][0]["binding"], "beyond_reach");
        assert_eq!(json["services"][0]["address"], "2001:db8::1");
    }

    #[test]
    fn a_beyond_reach_row_never_reads_as_unreachable_from_the_network() {
        // The bug this guards against: an earlier version of this renderer
        // (inherited from classify_v6's own earlier bug) would have put this
        // row under the loopback heading, or worded a heading for it the
        // same way -- both claim "porthole cannot help" *because the socket
        // is not reachable from the network*, which is false here: this
        // address is reachable over IPv6, and porthole simply cannot open or
        // close a rule for it. Assert the property (neither false claim
        // appears), not today's exact sentence, so a future rewording cannot
        // quietly reintroduce either one.
        let services = vec![service(
            9999,
            Binding::BeyondReach("2001:db8::1".parse().unwrap()),
            None,
            None,
        )];
        let text = render_listening(&services);
        let lower = text.to_lowercase();
        assert!(
            !lower.contains("changes nothing"),
            "must not claim opening the firewall is a no-op for an exposed service: {text}"
        );
        assert!(
            !lower.contains("only this machine"),
            "must not claim this listener is unreachable from the network: {text}"
        );
    }

    #[test]
    fn a_loopback_row_still_says_the_firewall_change_is_a_no_op() {
        // The other half of the same guard: fixing BeyondReach must not
        // water down the (true, for loopback) claim this heading makes.
        let services = vec![service(53, Binding::LoopbackOnly, None, None)];
        let text = render_listening(&services);
        assert!(text.contains("Loopback only — opening the firewall for these changes nothing:"));
    }
}
