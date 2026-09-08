//! Wiring: build a runner, a backend and an engine, then dispatch.

use crate::cli::{Cli, Commands};
use crate::client;
use crate::output;
use porthole_core::backend::{self, BackendHealth, BackendId, FirewallBackend};
use porthole_core::clock::{Clock, SystemClock};
use porthole_core::command::{CommandRunner, DryRunRunner, RealRunner};
use porthole_core::devices;
use porthole_core::engine::{Engine, Status};
use porthole_core::error::{Error, ExitCode, Result};
use porthole_core::listening::{self, RealProcFs};
use porthole_core::model::{Lifetime, ScopeSpec, DEFAULT_DURATION};
use porthole_core::net;
use porthole_core::state::StateStore;
use porthole_core::validate;

pub fn run(cli: &Cli) -> Result<ExitCode> {
    match &cli.command {
        // `list` deliberately touches nothing but the state file: it must work
        // even on a machine whose firewall was just uninstalled.
        Commands::List => {
            let state = StateStore::open(StateStore::default_path())?;
            let now = SystemClock.now();
            if cli.json {
                println!("{}", output::json_rules(state.rules(), now));
            } else {
                output::print_rules(state.rules(), now);
            }
            Ok(ExitCode::Success)
        }
        // `status` is a question, not an operation. It answers in its own
        // shape whatever the answer is — including "there is no firewall" —
        // and exits 0 because it succeeded at answering. Exit code 3 is for
        // operations that could not proceed, not for a query reporting bad
        // news. A script running `porthole status --json` must never have to
        // handle two different top-level shapes to learn that.
        Commands::Status => {
            let runner = make_runner(cli);
            let now = SystemClock.now();

            let status = match backend::detect(runner.as_ref()) {
                Ok(backend) => {
                    // status only ever reads, regardless of --dry-run.
                    // `Engine::status` reconciles read-only (`SweepMode::
                    // ReadOnly`): it can update its own in-memory view of
                    // what is actually open, but it never saves and never
                    // touches the firewall -- see `reconcile.rs`.
                    let mut engine = make_engine(backend.as_ref(), runner.as_ref())?;
                    engine.status()?
                }
                // Any failure to detect a backend at all -- not only the
                // documented "no firewall installed" case -- must still
                // answer in this shape. C1: `detect` used to also fail this
                // way whenever the active backend's own privileged read
                // errored (ufw and nftables both need root to say whether
                // they are enforcing anything), and returning `Err` here made
                // `status` exit non-zero with a raw error -- breaking the
                // promise, two paragraphs up, that a script reading `--json`
                // never has to handle two different top-level shapes. That
                // specific case no longer reaches here (both backends now
                // degrade `health()` instead of erroring), but folding every
                // `detect` failure into this shape, not only
                // `BackendUnavailable`, is what makes the promise hold
                // regardless of what a future backend's `detect` path can
                // fail with. That folding means `available: false` itself
                // now covers two facts -- "no firewall is installed" and,
                // more broadly, "detect could not tell" -- documented,
                // deliberately without a field of its own, in
                // `docs/json-schema.md`'s own paragraph on this collapse.
                Err(e) => Status {
                    backend: BackendId::Firewalld,
                    health: BackendHealth {
                        available: false,
                        active: false,
                        // A backend that could not even be detected is not
                        // the same fact as one that was detected and could
                        // not be read -- see `active_unknown`'s own doc
                        // comment. `detect` failing this way means no
                        // backend was ever available to ask, so there is
                        // nothing left unresolved to call "unknown".
                        active_unknown: false,
                        version: None,
                        detail: e.to_string(),
                        caveat: None,
                    },
                    network: net::current_network(runner.as_ref()).ok(),
                    location: None,
                    rules: StateStore::open(StateStore::default_path())?
                        .rules()
                        .to_vec(),
                },
            };

            if cli.json {
                println!("{}", output::json_status(&status, now));
            } else {
                output::print_status(&status, now);
            }
            Ok(ExitCode::Success)
        }
        Commands::Open(args) => open(cli, args),
        Commands::Close(args) => close(cli, args),
        Commands::Doctor => {
            let checks = crate::doctor::run(cli.session);
            if cli.json {
                println!("{}", crate::doctor::json(&checks));
            } else {
                crate::doctor::print_human(&checks);
            }
            // 1 when anything needs attention, so a script can gate on it.
            Ok(if checks.iter().all(|c| c.ok) {
                ExitCode::Success
            } else {
                ExitCode::Failure
            })
        }
        // Unprivileged and read-only, like `list`: nothing here needs the
        // helper or a firewall backend at all, so it still completes with no
        // firewall installed. Docker information is the one exception: it is
        // privileged (`porthole_core::docker`'s own module doc says why),
        // and asking for it is a best-effort extra, never a reason to fail
        // `listen` outright -- a helper that is absent, or that answers with
        // an error, is reported to the renderers as "not checked"
        // (`docker: None`), not silently folded into "Docker touches
        // nothing here".
        Commands::Listen => {
            let services = listening::scan(&RealProcFs)?;
            let docker = client::docker_ports(cli.session).ok();
            if cli.json {
                println!("{}", output::json_listening(&services, docker.as_deref()));
            } else {
                output::print_listening(&services, docker.as_deref());
            }
            Ok(ExitCode::Success)
        }
        Commands::Devices { command } => devices_command(cli, command),
    }
}

fn open(cli: &Cli, args: &crate::cli::OpenArgs) -> Result<ExitCode> {
    // Validate everything before asking for a password or touching the bus: a
    // bad port or an over-long duration must cost no round trip, and — now
    // that opening means a polkit prompt — no authentication prompt either.
    let port = validate::parse_port(&args.port)?;
    let protocol = validate::parse_protocol(&args.proto)?;

    let lifetime = match (&args.duration, args.until_reboot) {
        (Some(raw), false) => Lifetime::For(validate::parse_duration(raw)?),
        (None, true) => Lifetime::UntilReboot,
        (None, false) => Lifetime::For(DEFAULT_DURATION),
        // clap rejects this combination first; belt and braces.
        (Some(_), true) => {
            return Err(Error::InvalidArgument(
                "--for and --until-reboot cannot be combined".to_string(),
            ))
        }
    };

    // `--to` may name a saved device instead of an ordinary scope.
    // Resolution happens here, client-side: the helper (and, under
    // --dry-run, the local engine below) must only ever see an
    // already-resolved IP -- see `porthole_core::devices`'s own module doc
    // for why. `wire_to` is what actually crosses the bus for a real (non
    // dry-run) open; for anything but a device it is `args.to` unchanged.
    //
    // Below the duration, deliberately: resolving a device spawns `ip -4
    // neigh show` or `getent`, and `--for 999h` must be refused without
    // running either.
    let (scope, wire_to): (ScopeSpec, String) = match crate::cli::parse_to(&args.to) {
        crate::cli::ToSpec::Scope(scope) => (scope, args.to.clone()),
        crate::cli::ToSpec::Invalid(err) => return Err(err),
        crate::cli::ToSpec::Device(name) => {
            let book = devices::Book::load(&devices::default_path())?;
            let runner = make_runner(cli);
            let addr = devices::resolve(&book, &name, runner.as_ref())?;
            (ScopeSpec::Host(addr), addr.to_string())
        }
    };

    // A best-effort, read-only look at whether Docker already has an
    // opinion about this exact port/protocol -- see `porthole_core::docker`'s
    // own module doc for the two ways a user is misled if this stays silent.
    // Unlike every value resolved above, this never changes what `open`
    // itself does: a helper that cannot be reached, or that errors, leaves
    // `docker_note` at `None` rather than failing `open` outright -- `open`
    // has never needed the helper for anything but the real work, and a
    // missing bonus warning is not a reason to stop doing that work.
    let docker_note = client::docker_ports(cli.session)
        .ok()
        .and_then(|published| porthole_core::docker::advise(port, protocol, &published));

    if cli.dry_run {
        // The engine path below is unchanged: local, unprivileged, no helper
        // needed. Seeing what porthole would do is what earns a user's
        // trust, and asking for a password — or reaching for a helper that
        // may not even be installed — first would defeat that. `docker_note`
        // above is the one exception: it does attempt the helper, even under
        // `--dry-run`, since it only ever reads and is swallowed on failure
        // exactly as it is for a real open.
        let runner = make_runner(cli);
        let backend = backend::detect(runner.as_ref())?;
        let mut engine = make_engine(backend.as_ref(), runner.as_ref())?;

        let rule = engine.open(port, protocol, &scope, lifetime, requesting_uid())?;
        // Render against the rule's own opening instant rather than reading the
        // clock a second time: a tick between the two would report 3599 seconds
        // for a one-hour rule, and the end-to-end assertion would fail for a
        // real reason.
        let now = rule.opened_at;

        if cli.json {
            println!(
                "{}",
                output::json_opened(&rule, now, true, &runner.recorded(), docker_note.as_deref())
            );
        } else {
            println!(
                "Would open {}/{} towards {} for {}",
                rule.port,
                rule.protocol,
                rule.target,
                output::format_remaining(rule.expires_in(now))
            );
            output::print_dry_run(&runner.recorded());
            if let Some(note) = &docker_note {
                println!();
                println!("{note}");
            }
        }
        Ok(ExitCode::Success)
    } else {
        let seconds = match lifetime {
            Lifetime::UntilReboot => 0,
            Lifetime::For(d) => d.as_secs() as u32,
        };
        // No engine, no runner, no local audit line: the helper does the work
        // and, being a system service, its own journal entry is the audit
        // trail now — in every case, not just under the expiry timer.
        let rule = client::open(cli.session, port, &args.proto, &wire_to, seconds)?;
        let now = rule.opened_at;

        if cli.json {
            println!(
                "{}",
                output::json_opened(&rule, now, false, &[], docker_note.as_deref())
            );
        } else {
            output::print_opened(&rule, now, docker_note.as_deref());
        }
        Ok(ExitCode::Success)
    }
}

fn close(cli: &Cli, args: &crate::cli::CloseArgs) -> Result<ExitCode> {
    let protocol = validate::parse_protocol(&args.proto)?;
    let port = args.port.as_deref().map(validate::parse_port).transpose()?;

    if port.is_none() && args.id.is_none() && !args.all {
        return Err(Error::InvalidArgument(
            "say what to close: a port number, --id <ID>, or --all".to_string(),
        ));
    }

    // Belt and braces: clap's own `requires = "id"` on `forget` does not
    // reject `close <port> --forget` (verified by hand -- `id` also
    // `conflicts_with_all(["port", ...])`, and clap does not treat that
    // three-way combination as unsatisfiable the way a person reading the
    // two declarations together would expect). Below this point, `forget`
    // is read only inside the `args.id` branch, so without this check a
    // port-based `close <port> --forget` would silently ignore `--forget`
    // entirely and perform an ordinary close instead -- exactly the
    // "implicit forgetting" the escape hatch must never be.
    if args.forget && args.id.is_none() {
        return Err(Error::InvalidArgument(
            "--forget requires --id <ID> naming the exact rule to forget".to_string(),
        ));
    }

    if cli.dry_run {
        // Unchanged: local, unprivileged, no helper needed.
        let runner = make_runner(cli);
        let backend = backend::detect(runner.as_ref())?;
        let mut engine = make_engine(backend.as_ref(), runner.as_ref())?;

        let mut failures: Vec<Error> = Vec::new();
        let closed = if args.all {
            let (closed, errors) = engine.close_all(args.from_timer);
            failures = errors;
            closed
        } else if let Some(id) = &args.id {
            vec![engine.close_by_id(id, args.from_timer, args.forget)?]
        } else {
            vec![engine.close_by_port(
                port.expect("a port, an id or --all was required above"),
                protocol,
                args.from_timer,
            )?]
        };

        let now = SystemClock.now();
        if cli.json {
            println!(
                "{}",
                output::json_closed(
                    &closed,
                    &failures,
                    now,
                    true,
                    args.forget,
                    &runner.recorded()
                )
            );
        } else {
            // "Nothing to close." would be a lie when there WAS something and
            // every attempt failed: the ports are still open. Say nothing on
            // stdout in that case and let the errors below speak.
            if !closed.is_empty() || failures.is_empty() {
                output::print_closed(&closed, true, args.forget);
            }
            for error in &failures {
                eprintln!("porthole: {error}");
            }
            output::print_dry_run(&runner.recorded());
        }

        match failures.first() {
            Some(error) => Ok(error.exit_code()),
            None => Ok(ExitCode::Success),
        }
    } else {
        // No engine, no runner, no local audit line: the helper closes the
        // rule and logs it to the journal itself, exactly as `open` does.
        let mut failures: Vec<Error> = Vec::new();
        let closed = if args.all {
            let (closed, errors) = client::close_all(cli.session)?;
            failures = errors;
            closed
        } else if let Some(id) = &args.id {
            // `args.from_timer` matters here specifically: this is the only
            // branch the expiry timer's own `close --id <id> --from-timer`
            // ever reaches. It must cross the bus rather than being dropped
            // at the client, or the helper cannot tell a timer-triggered
            // close from an ordinary one — see
            // `porthole_helper::service::Porthole::close_by_id`.
            vec![client::close_by_id(
                cli.session,
                id,
                args.from_timer,
                args.forget,
            )?]
        } else {
            vec![client::close(
                cli.session,
                port.expect("a port, an id or --all was required above"),
                &args.proto,
            )?]
        };

        if cli.json {
            let now = SystemClock.now();
            println!(
                "{}",
                output::json_closed(&closed, &failures, now, false, args.forget, &[])
            );
        } else {
            if !closed.is_empty() || failures.is_empty() {
                output::print_closed(&closed, false, args.forget);
            }
            for error in &failures {
                eprintln!("porthole: {error}");
            }
        }

        // Report what did close, then exit on what did not. Silently succeeding
        // after a failed close would tell the user a port is shut when it is
        // open.
        //
        // The failures were rendered above — inside the single JSON object, or
        // on stderr — so this returns a code rather than an `Err`. Returning
        // `Err` would make `main` print a second top-level JSON object, which
        // no JSON reader can parse.
        match failures.first() {
            Some(error) => Ok(error.exit_code()),
            None => Ok(ExitCode::Success),
        }
    }
}

/// `porthole devices <list|add|rm>`. Unprivileged and local, like `list` and
/// `status`: the address book lives client-side, and nothing here ever
/// touches the helper or a firewall backend.
fn devices_command(cli: &Cli, command: &crate::cli::DevicesCommand) -> Result<ExitCode> {
    let path = devices::default_path();
    match command {
        crate::cli::DevicesCommand::List => {
            let book = devices::Book::load(&path)?;
            let runner = make_runner(cli);
            let rows = devices::list_status(&book, runner.as_ref())?;
            if cli.json {
                println!("{}", output::json_devices(&rows));
            } else {
                output::print_devices(&rows);
            }
            Ok(ExitCode::Success)
        }
        crate::cli::DevicesCommand::Add => add_device(cli, &path),
        crate::cli::DevicesCommand::Rm { name } => {
            let mut book = devices::Book::load(&path)?;
            if !book.remove(name) {
                return Err(Error::InvalidArgument(format!(
                    "no saved device named `{name}`"
                )));
            }
            book.save(&path)?;
            if cli.json {
                println!("{}", output::json_device_changed("forgotten", name, None));
            } else {
                println!("Forgot `{name}`.");
            }
            Ok(ExitCode::Success)
        }
    }
}

/// `porthole devices add`: presents the neighbours currently seen on this
/// network and lets the user pick one, rather than typing a MAC address by
/// hand -- typing one is exactly what saved devices exist to avoid.
fn add_device(cli: &Cli, path: &std::path::Path) -> Result<ExitCode> {
    use std::io::Write as _;

    let mut book = devices::Book::load(path)?;
    let runner = make_runner(cli);
    let neighbours = net::neighbours(runner.as_ref())?;
    // `Err`, not `Ok(ExitCode::Failure)`: `main` renders an `Err` as the
    // `--json` error object when `--json` was asked for, and prints the
    // message on stderr when it was not. Returning the code directly printed
    // prose either way, so `porthole --json devices add` exited 1 with an
    // empty stdout -- the one thing `docs/json-schema.md` promises no failure
    // does. The other way this same command fails (`net::neighbours` cannot
    // run `ip` at all) has always taken the `Err` path; both now report the
    // same way.
    if neighbours.is_empty() {
        return Err(Error::NothingToOffer(format!(
            "nothing seen on this network yet to pick from -- make sure the device has \
             talked to this machine recently, or add it by hand in {}",
            path.display()
        )));
    }

    // A MAC and an address are not something a person can choose between:
    // two of them on one line look alike, and picking the wrong one opens a
    // port towards the wrong machine. Whatever this machine's resolver
    // answers for each address goes on the row as well, and rows it answered
    // nothing for get nothing.
    let addresses: Vec<std::net::Ipv4Addr> = neighbours.iter().map(|n| n.address).collect();
    let names = net::resolver_names(runner.as_ref(), &addresses);

    // The picker is a prompt, not output: it goes to stderr so that stdout
    // carries only the result, and `--json` has a stdout worth parsing. A
    // person at a terminal sees no difference.
    eprintln!("Seen on this network:");
    for (i, n) in neighbours.iter().enumerate() {
        match names.get(i).and_then(Option::as_deref) {
            Some(name) => eprintln!(
                "  {}) {}  {}  ({})  {}",
                i + 1,
                n.mac,
                n.address,
                n.interface,
                name
            ),
            None => eprintln!("  {}) {}  {}  ({})", i + 1, n.mac, n.address, n.interface),
        }
    }
    if names.iter().any(Option::is_some) {
        // Said once, and only when there is a name to say it about. It
        // reports what porthole asked and what it saves, and claims nothing
        // about where an answer came from -- `getent` does not say which of
        // the host's name sources answered.
        eprintln!(
            "The name after an address is what this machine's resolver answered for it. The \
             MAC is what gets saved."
        );
    }
    eprint!("Pick a number: ");
    std::io::stderr().flush().ok();
    let choice = read_line()?;
    let index: usize = choice.parse().map_err(|_| {
        Error::InvalidArgument(format!("`{choice}` is not one of the numbers above"))
    })?;
    let chosen = index
        .checked_sub(1)
        .and_then(|i| neighbours.get(i))
        .ok_or_else(|| {
            Error::InvalidArgument(format!("{index} is not one of the numbers above"))
        })?;

    eprint!("Name this device: ");
    std::io::stderr().flush().ok();
    let name = read_line()?;
    devices::validate_device_name(&name)?;

    let address = devices::DeviceAddress::Mac(chosen.mac.clone());
    book.add(devices::Device {
        name: name.clone(),
        address: address.clone(),
    });
    book.save(path)?;
    if cli.json {
        println!(
            "{}",
            output::json_device_changed("added", &name, Some(&address))
        );
    } else {
        println!("Saved `{name}` as {}.", chosen.mac);
    }
    Ok(ExitCode::Success)
}

fn read_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(Error::Io)?;
    Ok(line.trim().to_string())
}

fn make_runner(cli: &Cli) -> Box<dyn CommandRunner> {
    if cli.dry_run {
        Box::new(DryRunRunner::new(Box::new(RealRunner)))
    } else {
        Box::new(RealRunner)
    }
}

/// Always opens the state store non-exclusively, on purpose: every real
/// (non-dry-run) `open`/`close` crosses the bus via `client::*` instead of
/// building an `Engine` here at all (see `open`/`close` below), so the only
/// local `Engine`s this binary ever constructs are for `--dry-run` and for
/// `status` -- and `status` never writes, regardless of `--dry-run`. Taking
/// the exclusive lock would call `ensure_dir` on `/run/porthole`, which an
/// unprivileged user cannot create, and neither of these callers is
/// documented to need any privilege at all. There is deliberately no
/// `for_write` parameter here any more: one existed, but every call site
/// passed `false`, since `open_exclusive`'s branch had no caller that could
/// ever reach it from this binary -- a doc comment describing the unreachable
/// branch as real is exactly how that went unnoticed.
fn make_engine<'a>(
    backend: &'a dyn FirewallBackend,
    runner: &'a dyn CommandRunner,
) -> Result<Engine<'a>> {
    let path = StateStore::default_path();
    let state = StateStore::open(path)?;
    let executable = std::env::current_exe()
        .map_err(|e| Error::Unexpected(format!("could not determine porthole's own path: {e}")))?;
    Ok(Engine::new(
        backend,
        runner,
        &SYSTEM_CLOCK,
        state,
        executable,
    ))
}

static SYSTEM_CLOCK: SystemClock = SystemClock;

/// The uid that asked for this, seen through sudo where possible, so the audit
/// trail names a person rather than root.
pub fn requesting_uid() -> u32 {
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse().ok())
        // SAFETY: getuid takes no arguments, touches no memory and cannot fail.
        .unwrap_or_else(|| unsafe { libc::getuid() })
}
