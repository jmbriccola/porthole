//! Rendering. Two audiences: a person reading a terminal, and a script reading
//! `--json`.
//!
//! The JSON shape is a public interface and is documented in
//! `docs/json-schema.md`. Add fields; do not rename or remove them.

use porthole_core::backend::BackendId;
use porthole_core::command::Command;
use porthole_core::engine::Status;
use porthole_core::error::Error;
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
pub fn json_closed(
    rules: &[ManagedRule],
    errors: &[Error],
    now: u64,
    dry_run: bool,
    commands: &[Command],
) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "dry_run": dry_run,
        "closed": rules.iter().map(|r| rule_json(r, now)).collect::<Vec<_>>(),
        "errors": errors.iter().map(error_json).collect::<Vec<_>>(),
        "commands": commands.iter().map(Command::display).collect::<Vec<_>>(),
    })
}

pub fn print_closed(rules: &[ManagedRule], dry_run: bool) {
    if rules.is_empty() {
        println!("Nothing to close.");
        return;
    }
    let verb = if dry_run { "Would close" } else { "Closed" };
    for rule in rules {
        println!(
            "{verb} {}/{} towards {}",
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
        use porthole_core::backend::BackendHealth;

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
            &[],
        );
        assert_eq!(json["schema"], 1);
        assert_eq!(json["closed"].as_array().unwrap().len(), 0);
        assert_eq!(json["errors"].as_array().unwrap().len(), 1);
        assert_eq!(json["errors"][0]["kind"], "rule_not_found");
        assert_eq!(json["errors"][0]["code"], 7);
    }
}
