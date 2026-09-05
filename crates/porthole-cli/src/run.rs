//! Wiring: build a runner, a backend and an engine, then dispatch.

use crate::cli::{Cli, Commands};
use crate::output;
use porthole_core::backend::{self, FirewallBackend};
use porthole_core::clock::{Clock, SystemClock};
use porthole_core::command::{CommandRunner, DryRunRunner, RealRunner};
use porthole_core::engine::Engine;
use porthole_core::error::{Error, Result};
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
        Commands::Status => {
            let runner = make_runner(cli);
            let backend = backend::detect(runner.as_ref())?;
            let engine = make_engine(backend.as_ref(), runner.as_ref())?;
            let status = engine.status()?;
            let now = SystemClock.now();
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
