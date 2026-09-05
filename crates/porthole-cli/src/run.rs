//! Wiring: build a runner, a backend and an engine, then dispatch.

use crate::cli::{Cli, Commands};
use crate::client;
use crate::output;
use porthole_core::backend::{self, BackendHealth, BackendId, FirewallBackend};
use porthole_core::clock::{Clock, SystemClock};
use porthole_core::command::{CommandRunner, DryRunRunner, RealRunner};
use porthole_core::engine::{Engine, Status};
use porthole_core::error::{Error, ExitCode, Result};
use porthole_core::model::{Lifetime, DEFAULT_DURATION};
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
                    // Never for_write: status only ever reads, regardless of
                    // --dry-run. `Engine::status` now reconciles first, which
                    // can save a corrected state file if it finds drift; that
                    // save is opportunistic here (best effort, no lock held
                    // for it), never required for status to answer correctly.
                    let mut engine = make_engine(backend.as_ref(), runner.as_ref(), false)?;
                    engine.status()?
                }
                Err(Error::BackendUnavailable(detail)) => Status {
                    backend: BackendId::Firewalld,
                    health: BackendHealth {
                        available: false,
                        active: false,
                        version: None,
                        detail,
                    },
                    network: net::current_network(runner.as_ref()).ok(),
                    location: None,
                    rules: StateStore::open(StateStore::default_path())?
                        .rules()
                        .to_vec(),
                },
                Err(other) => return Err(other),
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
    }
}

fn open(cli: &Cli, args: &crate::cli::OpenArgs) -> Result<ExitCode> {
    // Validate everything before asking for a password or touching the bus: a
    // bad port or an over-long duration must cost no round trip, and — now
    // that opening means a polkit prompt — no authentication prompt either.
    let port = validate::parse_port(&args.port)?;
    let protocol = validate::parse_protocol(&args.proto)?;
    let scope = validate::parse_scope(&args.to)?;
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

    if cli.dry_run {
        // Unchanged: local, unprivileged, no helper needed. Seeing what
        // porthole would do is what earns a user's trust, and asking for a
        // password — or reaching for a helper that may not even be installed
        // — first would defeat that.
        let runner = make_runner(cli);
        let backend = backend::detect(runner.as_ref())?;
        let mut engine = make_engine(backend.as_ref(), runner.as_ref(), false)?;

        let rule = engine.open(port, protocol, &scope, lifetime, requesting_uid())?;
        // Render against the rule's own opening instant rather than reading the
        // clock a second time: a tick between the two would report 3599 seconds
        // for a one-hour rule, and the end-to-end assertion would fail for a
        // real reason.
        let now = rule.opened_at;

        if cli.json {
            println!(
                "{}",
                output::json_opened(&rule, now, true, &runner.recorded())
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
        let rule = client::open(cli.session, port, &args.proto, &args.to, seconds)?;
        let now = rule.opened_at;

        if cli.json {
            println!("{}", output::json_opened(&rule, now, false, &[]));
        } else {
            output::print_opened(&rule, now);
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

    if cli.dry_run {
        // Unchanged: local, unprivileged, no helper needed.
        let runner = make_runner(cli);
        let backend = backend::detect(runner.as_ref())?;
        let mut engine = make_engine(backend.as_ref(), runner.as_ref(), false)?;

        let mut failures: Vec<Error> = Vec::new();
        let closed = if args.all {
            let (closed, errors) = engine.close_all(args.from_timer);
            failures = errors;
            closed
        } else if let Some(id) = &args.id {
            vec![engine.close_by_id(id, args.from_timer)?]
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
                output::json_closed(&closed, &failures, now, true, &runner.recorded())
            );
        } else {
            // "Nothing to close." would be a lie when there WAS something and
            // every attempt failed: the ports are still open. Say nothing on
            // stdout in that case and let the errors below speak.
            if !closed.is_empty() || failures.is_empty() {
                output::print_closed(&closed, true);
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
            vec![client::close_by_id(cli.session, id, args.from_timer)?]
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
                output::json_closed(&closed, &failures, now, false, &[])
            );
        } else {
            if !closed.is_empty() || failures.is_empty() {
                output::print_closed(&closed, false);
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

fn make_runner(cli: &Cli) -> Box<dyn CommandRunner> {
    if cli.dry_run {
        Box::new(DryRunRunner::new(Box::new(RealRunner)))
    } else {
        Box::new(RealRunner)
    }
}

/// `for_write` is `true` only for the call sites that can actually save: `open`
/// and `close`, and only when they are not `--dry-run`. `status` never saves —
/// no matter what `--dry-run` says — so it always passes `false`: taking the
/// lock would call `ensure_dir` on `/run/porthole`, which an unprivileged user
/// cannot create, and `porthole status` is documented to need no privileges.
fn make_engine<'a>(
    backend: &'a dyn FirewallBackend,
    runner: &'a dyn CommandRunner,
    for_write: bool,
) -> Result<Engine<'a>> {
    let path = StateStore::default_path();
    let state = if for_write {
        StateStore::open_exclusive(path)?
    } else {
        StateStore::open(path)?
    };
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
