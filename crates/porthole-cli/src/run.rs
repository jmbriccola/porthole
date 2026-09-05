//! Wiring: build a runner, a backend and an engine, then dispatch.

use crate::cli::{Cli, Commands};
use crate::output;
use porthole_core::backend::{self, FirewallBackend};
use porthole_core::clock::{Clock, SystemClock};
use porthole_core::command::{CommandRunner, DryRunRunner, RealRunner};
use porthole_core::engine::Engine;
use porthole_core::error::{Error, Result};
use porthole_core::state::StateStore;
use std::path::PathBuf;

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
