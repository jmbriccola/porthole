//! Rendering. Two audiences: a person reading a terminal, and a script reading
//! `--json`.
//!
//! The JSON shape is a public interface and is documented in
//! `docs/json-schema.md`. Add fields; do not rename or remove them.

use porthole_core::backend::BackendId;
use porthole_core::command::Command;
use porthole_core::devices::{DeviceAddress, DeviceStatus};
use porthole_core::docker::Published;
use porthole_core::engine::Status;
use porthole_core::error::Error;
use porthole_core::listening::{Binding, Service};
use porthole_core::model::{Protocol, Target};
use porthole_core::state::ManagedRule;
use porthole_core::update::{Consent, Install, Verdict, PACKAGE};
use serde_json::{json, Value};

/// The Docker publish rule matching `port`/`protocol`, if any -- the lookup
/// that keeps Docker's own facts out of [`Service`] and [`Binding`]
/// entirely, rather than as a new field or variant on either. `Binding` is
/// matched exhaustively, with no wildcard arm, by `porthole-gui`'s own
/// `listening_section.rs` (`subtitle_for` and `group_rank`, plus a test
/// helper) -- a new variant there is never silently dropped, which also
/// means a Docker variant added there would need that crate updated and
/// rebuilt to prove it still compiles, and this host cannot build
/// `porthole-gui` at all. `Service` carries the same risk one level down: it
/// is built as a whole-struct literal (`Service { .. }`) across this crate's
/// and `porthole-gui`'s own tests, so an added field would need every one of
/// those updated too. A third fact porthole-core itself has no opinion on
/// belongs beside a `Service`, not inside one. See `docs/json-schema.md`'s
/// `listen --json` section for the JSON shape this produces.
fn docker_for(port: u16, protocol: Protocol, docker: &[Published]) -> Option<Published> {
    // The most exposing match, not the first -- one host port can carry more
    // than one DNAT rule, and `docs/json-schema.md` documents this field as a
    // single object. Reporting the loopback rule of a port that is *also*
    // published on every interface would tell a script the port is not
    // reachable from the network when it is. Same ordering as
    // `porthole_core::docker::advise`, and for the same reason.
    docker
        .iter()
        .filter(|p| p.host_port == port && p.protocol == protocol)
        .min_by_key(|p| match p.host_addr {
            None => 0,
            Some(addr) if !addr.is_loopback() => 1,
            Some(_) => 2,
        })
        .copied()
}

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
        // `null` for a rule that only permits, which is every rule `open`
        // creates. The three members are the wire's own three
        // (`WireRule::container_addr` and the two ports); there is no
        // protocol among them because a forward whose two ends disagree is
        // refused before it exists (`backend::forward_protocol`), so the
        // rule's own `protocol` governs both.
        "forward": rule.forward.as_ref().map(|f| json!({
            "container_addr": f.container_addr.to_string(),
            "container_port": f.container_port,
            "published_port": f.published_port,
        })),
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

/// One rule's `REDIRECTS TO` cell: where a forward actually sends what
/// arrives, and the port the container is published on -- the number the
/// person typed, and the one `porthole listen` shows.
///
/// `--` for a rule that only permits. A forward rendered like an open tells a
/// user their port permits traffic when it redirects it, and names nothing at
/// the far end.
fn redirect_cell(rule: &ManagedRule) -> String {
    match &rule.forward {
        Some(f) => format!(
            "{}:{} (published on {})",
            f.container_addr, f.container_port, f.published_port
        ),
        None => "--".to_string(),
    }
}

pub fn print_rules(rules: &[ManagedRule], now: u64) {
    if rules.is_empty() {
        println!("No ports open.");
        return;
    }

    // The extra column appears only when there is a forward to put in it, so
    // `list` on a machine that has never forwarded anything prints the four
    // columns it always printed.
    let any_forward = rules.iter().any(|r| r.forward.is_some());

    let mut headers: Vec<&str> = vec!["PORT", "TOWARDS"];
    if any_forward {
        headers.push("REDIRECTS TO");
    }
    headers.extend(["BACKEND", "CLOSES IN"]);

    let rows: Vec<Vec<String>> = rules
        .iter()
        .map(|r| {
            let mut row = vec![format!("{}/{}", r.port, r.protocol), r.target.to_string()];
            if any_forward {
                row.push(redirect_cell(r));
            }
            row.push(r.backend.to_string());
            row.push(format_remaining(r.expires_in(now)));
            row
        })
        .collect();

    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let line = |cells: &[&str]| {
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

    println!("{}", line(&headers));
    for row in &rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        println!("{}", line(&cells));
    }
}

/// `docker_note` is [`porthole_core::docker::advise`]'s own text -- `None`
/// on almost every open, since Docker has an opinion about this exact
/// port/protocol only rarely. It is a plain string here, not a structured
/// object: a script that wants to *act* on this would need the same
/// `Published` fact `porthole listen --json`'s own `docker` field already
/// carries, and this is a one-line warning for the person reading `open`'s
/// own output, not a second copy of that data.
pub fn json_opened(
    rule: &ManagedRule,
    now: u64,
    dry_run: bool,
    commands: &[Command],
    docker_note: Option<&str>,
) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "dry_run": dry_run,
        "rule": rule_json(rule, now),
        "commands": commands.iter().map(Command::display).collect::<Vec<_>>(),
        "docker_note": docker_note,
    })
}

pub fn print_opened(rule: &ManagedRule, now: u64, docker_note: Option<&str>) {
    println!(
        "Opened {}/{} towards {} · closes {}",
        rule.port,
        rule.protocol,
        rule.target,
        format_remaining(rule.expires_in(now))
    );
    if let Some(note) = docker_note {
        println!();
        println!("{note}");
    }
}

/// What `forward` did, or would do.
///
/// Three numbers, on two lines, because they are three different facts and a
/// person told only the first cannot check the other two: the port the local
/// network connects to, the address and port inside Docker that traffic
/// actually reaches, and the port Docker published on this machine -- which
/// is the number that was typed.
pub fn print_forwarded(rule: &ManagedRule, now: u64, dry_run: bool) {
    let verb = if dry_run {
        "Would forward"
    } else {
        "Forwarded"
    };
    println!(
        "{verb} {}/{} towards {} · closes {}",
        rule.port,
        rule.protocol,
        rule.target,
        format_remaining(rule.expires_in(now))
    );
    match &rule.forward {
        Some(f) => println!(
            "  -> {}:{} in Docker, published on this machine as {}/{}",
            f.container_addr, f.container_port, f.published_port, rule.protocol
        ),
        // `Engine::forward` always records the mapping, and `client::forward`
        // carries it back whenever the answer holds a container address. An
        // answer that held none leaves nothing here to name, and naming one
        // anyway would mean inventing it.
        None => println!("  -> no container address came back with this rule"),
    }
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
        println!("{verb} {}{suffix}", closed_subject(rule));
    }
}

/// What a `close` line names, split out of [`print_closed`] so the one
/// distinction it draws is testable without capturing stdout -- the same
/// reason [`firewall_state_word`] is its own function.
///
/// **A forward says what it was.** `list`, `list --json`, the GUI row and
/// the expiry notification were each taught to tell a redirect from an open;
/// `close`'s own confirmation line was the surface that was missed.
/// "Closed 3000/tcp towards 10.10.10.0/24" reads as an open ending: a person
/// is told traffic to something on this machine stopped being let through,
/// when what stopped was a redirect into a container.
///
/// The container's own address and port, in [`print_forwarded`]'s own words,
/// because that is what says *which* redirect ended when more than one was
/// open.
fn closed_subject(rule: &ManagedRule) -> String {
    match &rule.forward {
        Some(f) => format!(
            "{}/{} towards {} (a redirect to {}:{} in Docker)",
            rule.port, rule.protocol, rule.target, f.container_addr, f.container_port
        ),
        None => format!("{}/{} towards {}", rule.port, rule.protocol, rule.target),
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

/// `docker` is `None` when Docker information could not be checked at all
/// (the helper is absent, or the D-Bus call otherwise failed) -- see
/// `json_listening`'s own `docker_checked` for the field that carries that
/// fact, since this row-level shape alone cannot distinguish "checked, and
/// Docker does not touch this port" from "not checked" and must not be read
/// as claiming the latter.
fn service_json(service: &Service, docker: Option<&[Published]>) -> Value {
    let published = docker.and_then(|list| docker_for(service.port, service.protocol, list));
    json!({
        "port": service.port,
        "protocol": service.protocol.to_string(),
        "address": service.address.to_string(),
        "binding": binding_tag(&service.binding),
        "process": service.process,
        "pid": service.pid,
        "docker": published.map(|p| json!({
            "published_on": p.host_addr.map(|a| a.to_string()),
        })),
    })
}

/// `docker` is `None` when it could not be checked at all -- the privileged
/// helper is what can actually read Docker's own DNAT rules (see
/// `porthole_core::docker`'s own module doc), and `listen` must keep working
/// without it, the same way it already does without a firewall backend
/// installed. `docker_checked` says which case this is; a script that reads
/// `docker: null` on every row without also checking `docker_checked` would
/// be unable to tell "Docker was checked and touches nothing here" from "not
/// checked at all" -- exactly the silent claim of absence this field exists
/// to rule out.
pub fn json_listening(services: &[Service], docker: Option<&[Published]>) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "docker_checked": docker.is_some(),
        "services": services.iter().map(|s| service_json(s, docker)).collect::<Vec<_>>(),
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
///   usually the majority of the list -- six of the seven listening TCP
///   sockets on the machine this was measured on -- and opening the firewall
///   for one of them genuinely changes nothing, since the process is not
///   listening on a network interface at all.
pub fn print_listening(services: &[Service], docker: Option<&[Published]>) {
    print!("{}", render_listening(services, docker));
}

/// The text `print_listening` prints, built as a `String` rather than
/// printed line-by-line so tests can assert on it directly -- see the
/// `BeyondReach` tests below, which check a *property* of this text (it must
/// never claim the service is unreachable), not a literal sentence.
fn render_listening(services: &[Service], docker: Option<&[Published]>) -> String {
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
    // A dual-stack service (one socket on `0.0.0.0`, another on `::`) shares
    // its port and process name with its own other socket, so without this
    // column the two rows print as visually identical pairs -- on an
    // ordinary desktop, half the list or more. `address_width` over every
    // service, the same way `port_width`/`name_width` already are, so this
    // column lines up across every group too.
    let address_width = services
        .iter()
        .map(|s| s.address.to_string().chars().count())
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

    append_listening_rows(
        &mut out,
        &network_facing,
        port_width,
        name_width,
        address_width,
        docker,
    );

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
        append_listening_rows(
            &mut out,
            &beyond_reach,
            port_width,
            name_width,
            address_width,
            docker,
        );
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
        append_listening_rows(
            &mut out,
            &loopback,
            port_width,
            name_width,
            address_width,
            docker,
        );
    }

    // Silence here would read as "Docker was checked, and touches nothing on
    // this machine" -- exactly the false-in-the-dangerous-direction claim
    // `porthole_core::docker`'s own module doc exists to rule out. Said once,
    // at the end, rather than per row: every row would otherwise need the
    // same caveat repeated.
    if docker.is_none() {
        writeln!(out).expect(w);
        writeln!(
            out,
            "Docker information unavailable — the porthole helper could not be reached, or \
             answered with an error, so porthole cannot say whether any of these ports are \
             already published by a container."
        )
        .expect(w);
    }

    out
}

/// `address_width` disambiguates a dual-stack service's two rows -- the same
/// port and process name, one bound to `0.0.0.0`, the other to `::` -- so
/// they read as two distinct sockets rather than one service printed twice.
/// See this function's own caller for why the width is computed once, over
/// every service, rather than per group.
///
/// `docker` is threaded through from `render_listening` rather than looked
/// up once per group: the lookup is by port/protocol, not by group, and
/// `None` (not checked) must stay `None` for every row rather than reading
/// as "checked, and this row is not published" -- see `service_json`'s own
/// doc comment for the same distinction on the `--json` side.
fn append_listening_rows(
    out: &mut String,
    services: &[&Service],
    port_width: usize,
    name_width: usize,
    address_width: usize,
    docker: Option<&[Published]>,
) {
    use std::fmt::Write as _;
    for service in services {
        let port_proto = format!("{}/{}", service.port, service.protocol);
        let process = service.process.as_deref().unwrap_or("—").to_string();
        let address = service.address.to_string();
        let pid = service
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let published = docker.and_then(|list| docker_for(service.port, service.protocol, list));
        let docker_suffix = match published {
            Some(p) => match p.host_addr {
                Some(addr) => format!("  docker: published on {addr}"),
                None => "  docker: published on every interface".to_string(),
            },
            None => String::new(),
        };
        writeln!(
            out,
            "  {port_proto:port_width$}  {process:name_width$}  {address:address_width$}  \
             pid {pid}{docker_suffix}"
        )
        .expect("writing to a String cannot fail");
    }
}

fn device_address_string(address: &DeviceAddress) -> String {
    match address {
        DeviceAddress::Mac(mac) => mac.clone(),
        DeviceAddress::Host(host) => host.clone(),
    }
}

fn device_json(row: &DeviceStatus) -> Value {
    let (kind, address) = match &row.device.address {
        DeviceAddress::Mac(mac) => ("mac", mac.clone()),
        DeviceAddress::Host(host) => ("host", host.clone()),
    };
    json!({
        "name": row.device.name,
        "kind": kind,
        "address": address,
        "resolvable": row.resolved.is_some(),
        "resolved_address": row.resolved.map(|a| a.to_string()),
    })
}

/// What `devices add` and `devices rm` print under `--json`.
///
/// Deliberately not [`device_json`]'s shape: that one carries `resolvable`
/// and `resolved_address`, which are a live lookup `devices list` performs
/// and neither of these commands does. Reporting them here would mean either
/// resolving a device nobody asked to resolve, or printing two fields whose
/// value says nothing.
///
/// `action` is `"added"` or `"forgotten"`, so one parser can read both.
pub fn json_device_changed(action: &str, name: &str, address: Option<&DeviceAddress>) -> Value {
    let (kind, addr) = match address {
        Some(DeviceAddress::Mac(mac)) => (Some("mac"), Some(mac.clone())),
        Some(DeviceAddress::Host(host)) => (Some("host"), Some(host.clone())),
        None => (None, None),
    };
    json!({
        "schema": JSON_SCHEMA,
        "action": action,
        "device": {
            "name": name,
            "kind": kind,
            "address": addr,
        },
    })
}

/// The slug `--json` publishes for each consent state. Three, because there
/// are three: `never_asked` is not `no`, and a script that could not tell
/// them apart could not tell "this person declined" from "nobody has asked".
fn consent_slug(consent: Consent) -> &'static str {
    match consent {
        Consent::Yes => "yes",
        Consent::No => "no",
        Consent::NeverAsked => "never_asked",
    }
}

/// What porthole knows about how it was installed, as one sentence.
fn install_sentence(install: &Install) -> String {
    match install {
        Install::Packaged(p) => format!("porthole was installed by {}", p.as_str()),
        Install::Unpackaged => "porthole was not installed by any package manager on this \
             machine, so it was built and installed from source. porthole will not offer to \
             replace a tree it did not install."
            .to_string(),
        Install::Undetermined(reason) => reason.clone(),
    }
}

/// `porthole update --json`.
///
/// **`available` is `true`, `false` or `null`, and the third is not a
/// nuisance to be flattened away.** `null` is every case where porthole did
/// not get an answer: a source install, a machine with no package manager, a
/// manager that answered in a way that answers nothing, and -- on apt and
/// pacman -- a question their own documentation defines no exit code for.
/// Rendering any of those as `false` would tell a script there is nothing to
/// install on a machine that may well have something, which is the same
/// collapse `porthole listen --json`'s own `docker_checked` field exists to
/// avoid. `detail` is where the reason is said in words.
pub fn json_update(consent: Consent, install: &Install, verdict: Option<&Verdict>) -> Value {
    let (available, version, detail) = match verdict {
        Some(Verdict::Available { version }) => (
            Some(true),
            version.clone(),
            match version {
                Some(v) => format!("{PACKAGE} {v} is available to install"),
                None => format!(
                    "an update to {PACKAGE} is available to install; the package manager's \
                     own listing named no version porthole could read"
                ),
            },
        ),
        Some(Verdict::UpToDate) => (
            Some(false),
            None,
            format!("{PACKAGE} is up to date as far as this machine's package manager knows"),
        ),
        Some(Verdict::NoContract(reason)) | Some(Verdict::Unknown(reason)) => {
            (None, None, reason.clone())
        }
        None => (None, None, install_sentence(install)),
    };
    json!({
        "schema": JSON_SCHEMA,
        "update": {
            "consent": consent_slug(consent),
            "packaging": match install {
                Install::Packaged(p) => Some(p.as_str()),
                _ => None,
            },
            "packaged": matches!(install, Install::Packaged(_)),
            "available": available,
            "version": version,
            "detail": detail,
            // What to run by hand. Present whenever porthole knows which
            // manager owns this install, whether or not it could answer the
            // question -- a person told there may be an update and given
            // nothing to type has been told half of something.
            "command": match install {
                Install::Packaged(p) => Some(p.manual_command()),
                _ => None,
            },
        },
    })
}

/// `porthole update`, for a person.
pub fn print_update(consent: Consent, install: &Install, verdict: Option<&Verdict>) {
    match verdict {
        Some(Verdict::Available { version }) => match version {
            Some(v) => println!("{PACKAGE} {v} is available to install."),
            None => println!(
                "An update to {PACKAGE} is available to install. The package manager's own \
                 listing named no version porthole could read; the answer that there is \
                 one comes from its exit code."
            ),
        },
        Some(Verdict::UpToDate) => {
            println!(
                "Nothing to update: {PACKAGE} is up to date as far as this machine's \
                      package manager knows."
            );
        }
        Some(Verdict::NoContract(reason)) | Some(Verdict::Unknown(reason)) => {
            println!("porthole did not find out whether an update is available.");
            println!("{reason}");
        }
        None => println!("{}", install_sentence(install)),
    }

    if let Install::Packaged(p) = install {
        println!();
        println!("To update it yourself: {}", p.manual_command());
    }

    println!();
    match consent {
        Consent::Yes => println!(
            "The daily check is on: porthole asks this machine's package manager once a \
             day and says so on screen when the answer changes. `porthole update \
             --disable` stops it."
        ),
        Consent::No => println!(
            "The daily check is off. `porthole update --enable` turns it on; nothing \
             leaves this machine either way."
        ),
        Consent::NeverAsked => println!(
            "The daily check is not set up: nobody has been asked yet. The porthole \
             window asks at first launch, and `porthole update --enable` answers it from \
             here. Nothing leaves this machine either way -- the question goes to the \
             package manager already installed on it."
        ),
    }
}

/// `porthole update --enable|--disable --json`.
pub fn json_consent_changed(consent: Consent, dry_run: bool) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "dry_run": dry_run,
        "update": { "consent": consent_slug(consent) },
    })
}

pub fn print_consent_changed(consent: Consent, dry_run: bool) {
    let what = match consent {
        Consent::Yes => "on",
        Consent::No => "off",
        // Unreachable from the two flags, which is why it says so rather
        // than inventing a third sentence: `--enable` and `--disable` are
        // the only ways here, and neither produces "never asked".
        Consent::NeverAsked => "unchanged",
    };
    if dry_run {
        println!("Would turn the daily update check {what}. Nothing was written.");
        return;
    }
    match consent {
        Consent::Yes => println!(
            "The daily update check is on. porthole asks this machine's own package \
             manager once a day; nothing leaves the machine."
        ),
        Consent::No => println!("The daily update check is off."),
        Consent::NeverAsked => println!("The daily update check is unchanged."),
    }
}

pub fn json_devices(rows: &[DeviceStatus]) -> Value {
    json!({
        "schema": JSON_SCHEMA,
        "devices": rows.iter().map(device_json).collect::<Vec<_>>(),
    })
}

pub fn print_devices(rows: &[DeviceStatus]) {
    print!("{}", render_devices(rows));
}

/// The text `print_devices` prints, built as a `String` so tests can assert
/// on it directly -- the same split `render_listening` uses, for the same
/// reason.
fn render_devices(rows: &[DeviceStatus]) -> String {
    use std::fmt::Write as _;
    let w = "writing to a String cannot fail";
    let mut out = String::new();

    if rows.is_empty() {
        writeln!(out, "No saved devices.").expect(w);
        return out;
    }

    let name_width = rows.iter().map(|r| r.device.name.len()).max().unwrap_or(0);
    let address_width = rows
        .iter()
        .map(|r| device_address_string(&r.device.address).len())
        .max()
        .unwrap_or(0);
    for row in rows {
        let address = device_address_string(&row.device.address);
        let status = match row.resolved {
            Some(addr) => format!("resolves to {addr}"),
            None => "not on this network right now".to_string(),
        };
        writeln!(
            out,
            "{:name_width$}  {address:address_width$}  {status}",
            row.device.name
        )
        .expect(w);
    }
    out
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
            forward: None,
        }
    }

    #[test]
    fn a_closed_forward_does_not_read_as_a_closed_open() {
        // `close`'s own confirmation line was the one surface this branch
        // taught nothing: `list`, `list --json`, the GUI row and the expiry
        // notification all tell a redirect from an open, and
        // "Closed 8443/tcp towards 10.10.10.0/24" tells a person traffic to
        // something on this machine stopped being let through.
        let permit = rule();
        let mut forward = rule();
        forward.port = 8443;
        forward.forward = Some(porthole_core::forward::ForwardTo {
            container_addr: "172.17.0.9".parse().unwrap(),
            container_port: 80,
            published_port: 3000,
            protocol: Protocol::Tcp,
        });

        let redirected = closed_subject(&forward);
        assert!(
            redirected.contains("redirect"),
            "a closed forward must say what ended: {redirected}"
        );
        assert!(
            redirected.contains("172.17.0.9:80"),
            "and which one, when more than one was open: {redirected}"
        );
        assert!(
            redirected.starts_with("8443/tcp towards 10.10.10.0/24"),
            "without losing what every close line says: {redirected}"
        );

        let plain = closed_subject(&permit);
        assert_eq!(
            plain, "5173/tcp towards 10.10.10.0/24",
            "a rule that only permitted is unchanged, and claims no redirect"
        );
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
    fn json_opened_carries_a_null_docker_note_on_the_ordinary_open() {
        let json = json_opened(&rule(), 1_757_000_000, false, &[], None);
        assert!(json["docker_note"].is_null());
    }

    #[test]
    fn json_opened_carries_dockers_own_warning_when_there_is_one() {
        let json = json_opened(
            &rule(),
            1_757_000_000,
            false,
            &[],
            Some("Docker already publishes 5173/tcp on every interface (0.0.0.0)"),
        );
        assert_eq!(
            json["docker_note"],
            "Docker already publishes 5173/tcp on every interface (0.0.0.0)"
        );
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
        let json = json_listening(&services, None);
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
        let json = json_listening(&services, None);
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
        let json = json_listening(&services, None);
        assert_eq!(json["services"][0]["binding"], "specific");
        assert_eq!(json["services"][0]["address"], "10.10.10.5");
    }

    #[test]
    fn the_empty_listening_list_is_an_empty_array_not_a_missing_key() {
        let json = json_listening(&[], None);
        assert_eq!(json["services"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn docker_not_checked_is_a_top_level_fact_not_folded_into_every_row() {
        // `docker: null` on a row must not, by itself, be read as "Docker
        // does not touch this port" -- it also means "not checked at all"
        // when the helper could not be reached. `docker_checked` is the
        // field that tells the two apart.
        let services = vec![service(5173, Binding::AllInterfaces, None, None)];
        let json = json_listening(&services, None);
        assert_eq!(json["docker_checked"], false);
        assert!(json["services"][0]["docker"].is_null());
    }

    #[test]
    fn a_docker_published_row_carries_the_address_it_was_published_on() {
        let services = vec![
            service(8080, Binding::AllInterfaces, None, None),
            service(5432, Binding::LoopbackOnly, None, None),
        ];
        let published = vec![
            Published {
                host_addr: None,
                host_port: 8080,
                protocol: Protocol::Tcp,
                container_addr: "172.17.0.2".parse().unwrap(),
                container_port: 80,
            },
            Published {
                host_addr: Some("127.0.0.1".parse().unwrap()),
                host_port: 5432,
                protocol: Protocol::Tcp,
                container_addr: "172.17.0.3".parse().unwrap(),
                container_port: 80,
            },
        ];
        let json = json_listening(&services, Some(&published));
        assert_eq!(json["docker_checked"], true);
        assert!(json["services"][0]["docker"]["published_on"].is_null());
        assert_eq!(json["services"][1]["docker"]["published_on"], "127.0.0.1");
    }

    #[test]
    fn a_port_docker_does_not_publish_is_null_even_though_docker_was_checked() {
        let services = vec![service(5173, Binding::AllInterfaces, None, None)];
        let json = json_listening(&services, Some(&[]));
        assert_eq!(json["docker_checked"], true);
        assert!(json["services"][0]["docker"].is_null());
    }

    #[test]
    fn the_human_listing_marks_a_docker_published_row_with_its_address() {
        let services = vec![service(8080, Binding::AllInterfaces, Some("node"), Some(1))];
        let published = vec![Published {
            host_addr: None,
            host_port: 8080,
            protocol: Protocol::Tcp,
            container_addr: "172.17.0.2".parse().unwrap(),
            container_port: 80,
        }];
        let text = render_listening(&services, Some(&published));
        assert!(
            text.contains("docker: published on every interface"),
            "got: {text}"
        );
    }

    #[test]
    fn the_human_listing_says_so_when_docker_could_not_be_checked() {
        let services = vec![service(5173, Binding::AllInterfaces, None, None)];
        let text = render_listening(&services, None);
        assert!(
            text.contains("Docker information unavailable"),
            "must not silently read as \"Docker touches nothing here\": {text}"
        );
    }

    #[test]
    fn the_human_listing_says_nothing_about_docker_when_it_was_checked_and_found_nothing() {
        // The unavailable note is specifically about not having checked --
        // it must not appear once porthole actually confirmed there is
        // nothing to report.
        let services = vec![service(5173, Binding::AllInterfaces, None, None)];
        let text = render_listening(&services, Some(&[]));
        assert!(
            !text.contains("Docker information unavailable"),
            "got: {text}"
        );
        assert!(!text.contains("docker:"), "got: {text}");
    }

    #[test]
    fn a_beyond_reach_binding_reports_its_own_tag_and_address() {
        let services = vec![service(
            9999,
            Binding::BeyondReach("2001:db8::1".parse().unwrap()),
            None,
            None,
        )];
        let json = json_listening(&services, None);
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
        let text = render_listening(&services, None);
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
        let text = render_listening(&services, None);
        assert!(text.contains("Loopback only — opening the firewall for these changes nothing:"));
    }

    #[test]
    fn dual_stack_rows_sharing_a_port_read_as_two_sockets_not_one_listed_twice() {
        // A dual-stack service (one socket on `0.0.0.0`, one on `::`) shares
        // its port, protocol and process name -- both classify as
        // `AllInterfaces` -- so without an address column the two rows were
        // literally identical text, which reads as a duplicate rather than
        // two real sockets. `service()` always derives its address from the
        // binding, so this test builds both rows directly rather than
        // through that helper.
        use porthole_core::model::Protocol;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let v4 = Service {
            port: 53,
            protocol: Protocol::Tcp,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            binding: Binding::AllInterfaces,
            process: Some("dnsmasq".to_string()),
            pid: Some(100),
        };
        let v6 = Service {
            port: 53,
            protocol: Protocol::Tcp,
            address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            binding: Binding::AllInterfaces,
            process: Some("dnsmasq".to_string()),
            pid: Some(100),
        };
        let text = render_listening(&[v4, v6], None);
        let rows: Vec<&str> = text.lines().filter(|l| l.contains("53/tcp")).collect();
        assert_eq!(rows.len(), 2, "expected both rows, got: {text}");
        assert_ne!(
            rows[0], rows[1],
            "two distinct sockets must not render as identical lines: {text}"
        );
        assert!(rows[0].contains("0.0.0.0"), "got: {text}");
        assert!(rows[1].contains("::"), "got: {text}");
    }

    fn device_status(name: &str, address: DeviceAddress, resolved: Option<&str>) -> DeviceStatus {
        use porthole_core::devices::Device;
        DeviceStatus {
            device: Device {
                name: name.to_string(),
                address,
            },
            resolved: resolved.map(|a| a.parse().unwrap()),
        }
    }

    #[test]
    fn json_devices_has_the_documented_shape() {
        let rows = vec![device_status(
            "phone",
            DeviceAddress::Mac("bc:24:11:5e:1c:6e".to_string()),
            Some("10.10.10.245"),
        )];
        let json = json_devices(&rows);
        assert_eq!(json["schema"], 1);
        let d = &json["devices"][0];
        assert_eq!(d["name"], "phone");
        assert_eq!(d["kind"], "mac");
        assert_eq!(d["address"], "bc:24:11:5e:1c:6e");
        assert_eq!(d["resolvable"], true);
        assert_eq!(d["resolved_address"], "10.10.10.245");
    }

    #[test]
    fn an_unresolvable_device_reports_resolvable_false_and_a_null_address() {
        let rows = vec![device_status(
            "tablet",
            DeviceAddress::Mac("aa:bb:cc:dd:ee:ff".to_string()),
            None,
        )];
        let json = json_devices(&rows);
        assert_eq!(json["devices"][0]["resolvable"], false);
        assert!(json["devices"][0]["resolved_address"].is_null());
    }

    #[test]
    fn a_host_device_reports_the_host_kind() {
        let rows = vec![device_status(
            "printer",
            DeviceAddress::Host("printer.local".to_string()),
            Some("10.10.10.55"),
        )];
        let json = json_devices(&rows);
        assert_eq!(json["devices"][0]["kind"], "host");
        assert_eq!(json["devices"][0]["address"], "printer.local");
    }

    #[test]
    fn the_empty_device_list_is_an_empty_array_not_a_missing_key() {
        let json = json_devices(&[]);
        assert_eq!(json["devices"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn render_devices_says_nothing_saved_when_the_book_is_empty() {
        assert_eq!(render_devices(&[]), "No saved devices.\n");
    }

    #[test]
    fn render_devices_shows_the_resolved_address_or_says_it_is_absent() {
        let rows = vec![
            device_status(
                "phone",
                DeviceAddress::Mac("bc:24:11:5e:1c:6e".to_string()),
                Some("10.10.10.245"),
            ),
            device_status(
                "tablet",
                DeviceAddress::Mac("aa:bb:cc:dd:ee:ff".to_string()),
                None,
            ),
        ];
        let text = render_devices(&rows);
        assert!(
            text.contains("phone") && text.contains("resolves to 10.10.10.245"),
            "got: {text}"
        );
        assert!(
            text.contains("tablet") && text.contains("not on this network right now"),
            "got: {text}"
        );
    }
}
