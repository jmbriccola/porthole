//! Wiring: build a runner, a backend and an engine, then dispatch.

use crate::cli::{Cli, Commands};
use crate::output;
use porthole_core::backend::{self, BackendHealth, BackendId, FirewallBackend};
use porthole_core::clock::{Clock, SystemClock};
use porthole_core::command::{CommandRunner, DryRunRunner, RealRunner};
use porthole_core::engine::{Engine, Status};
use porthole_core::error::{Error, Result};
use porthole_core::net;
use porthole_core::state::StateStore;

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
        Commands::Open(_) | Commands::Close(_) => {
            Err(Error::Unexpected("not implemented yet".to_string()))
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
