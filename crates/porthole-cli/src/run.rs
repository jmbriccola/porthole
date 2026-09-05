//! Wiring: build a runner, a backend and an engine, then dispatch.

use crate::cli::{Cli, Commands};
use crate::output;
use porthole_core::backend::{self, BackendHealth, BackendId, FirewallBackend};
use porthole_core::clock::{Clock, SystemClock};
use porthole_core::command::{CommandRunner, DryRunRunner, RealRunner};
use porthole_core::engine::{Engine, Status};
use porthole_core::error::{Error, Result};
use porthole_core::model::{Lifetime, DEFAULT_DURATION};
use porthole_core::net;
use porthole_core::state::StateStore;
use porthole_core::validate;

pub fn run(cli: &Cli) -> Result<()> {
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
            Ok(())
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
                    let engine = make_engine(backend.as_ref(), runner.as_ref())?;
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
            Ok(())
        }
        Commands::Open(args) => open(cli, args),
        Commands::Close(_) => Err(Error::Unexpected("not implemented yet".to_string())),
    }
}

fn open(cli: &Cli, args: &crate::cli::OpenArgs) -> Result<()> {
    // Validate everything before asking for a password or touching the firewall.
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

    if !cli.dry_run {
        require_root()?;
    }

    let runner = make_runner(cli);
    let backend = backend::detect(runner.as_ref())?;
    let mut engine = make_engine(backend.as_ref(), runner.as_ref())?;

    let rule = engine.open(port, protocol, &scope, lifetime, requesting_uid())?;
    // Render against the rule's own opening instant rather than reading the clock
    // a second time: a tick between the two would report 3599 seconds for a
    // one-hour rule, and the end-to-end assertion would fail for a real reason.
    let now = rule.opened_at;

    // The audit trail. Under the expiry timer this goes to the journal; run
    // interactively it goes to the terminal. Milestone 2 moves it into the
    // helper, where the journal gets it in every case.
    //
    // Never under --dry-run: nothing was opened, and an audit trail that
    // records openings which did not happen is worse than none at all.
    if !cli.dry_run {
        eprintln!(
            "porthole: uid={} opened {}/{} towards {} until {}",
            rule.uid,
            rule.port,
            rule.protocol,
            rule.target,
            rule.expires_at
                .map(|t| t.to_string())
                .unwrap_or_else(|| "reboot".to_string())
        );
    }

    if cli.json {
        println!(
            "{}",
            output::json_opened(&rule, now, cli.dry_run, &runner.recorded())
        );
    } else {
        if cli.dry_run {
            println!(
                "Would open {}/{} towards {} for {}",
                rule.port,
                rule.protocol,
                rule.target,
                output::format_remaining(rule.expires_in(now))
            );
            output::print_dry_run(&runner.recorded());
        } else {
            output::print_opened(&rule, now);
        }
    }
    Ok(())
}

fn make_runner(cli: &Cli) -> Box<dyn CommandRunner> {
    if cli.dry_run {
        Box::new(DryRunRunner::new(Box::new(RealRunner)))
    } else {
        Box::new(RealRunner)
    }
}

fn make_engine<'a>(
    backend: &'a dyn FirewallBackend,
    runner: &'a dyn CommandRunner,
) -> Result<Engine<'a>> {
    let state = StateStore::open(StateStore::default_path())?;
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

/// Real firewall changes need root in this milestone. `--dry-run` does not:
/// seeing what porthole would do is what earns a user's trust, and asking for
/// a password first defeats that.
pub fn require_root() -> Result<()> {
    // SAFETY: geteuid takes no arguments, touches no memory and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Err(Error::NotAuthorized(
            "changing firewall rules needs root in this version — run `sudo porthole …`, \
             or add --dry-run to see what would happen. The unprivileged helper arrives \
             in the next release."
                .to_string(),
        ));
    }
    Ok(())
}

/// The uid that asked for this, seen through sudo where possible, so the audit
/// trail names a person rather than root.
pub fn requesting_uid() -> u32 {
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse().ok())
        // SAFETY: getuid takes no arguments, touches no memory and cannot fail.
        .unwrap_or_else(|| unsafe { libc::getuid() })
}
