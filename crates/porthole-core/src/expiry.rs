//! Automatic close, scheduled with a systemd transient unit.
//!
//! Not an internal timer, for three reasons: the schedule survives a restart of
//! whatever created it, `systemctl list-timers` shows the user exactly when the
//! port closes, and no process has to stay alive. Transient units do not
//! survive a reboot — which is fine, because after a reboot the rules are gone
//! anyway.
//!
//! `AccuracySec=1s` overrides systemd's default minute of slack. On a
//! fifteen-minute opening that default would be a minute of exposure nobody
//! asked for.

use crate::command::{Command, CommandRunner};
use crate::error::Result;
use crate::state::ManagedRule;
use std::path::Path;

/// The transient unit that closes a rule. systemd creates `<name>.timer` and
/// `<name>.service` from this.
pub fn unit_name(id: &str) -> String {
    format!("porthole-close-{id}")
}

/// Schedule the automatic close.
///
/// Failure here must propagate: a rule with no timer is a rule that never
/// closes, which is precisely the situation porthole exists to prevent.
pub fn schedule_close(
    runner: &dyn CommandRunner,
    executable: &Path,
    rule: &ManagedRule,
    seconds: u64,
) -> Result<()> {
    // SAFETY: geteuid takes no arguments, touches no memory and cannot fail.
    let euid = unsafe { libc::geteuid() };
    schedule_close_for(euid, runner, executable, rule, seconds)
}

/// [`schedule_close`], but taking the euid as a parameter instead of calling
/// `geteuid` itself — the same command, computed for a caller (real or a
/// test) that already knows or wants to simulate the privilege level in
/// question. Mirrors `cli_path::resolve_cli_for`.
fn schedule_close_for(
    euid: u32,
    runner: &dyn CommandRunner,
    executable: &Path,
    rule: &ManagedRule,
    seconds: u64,
) -> Result<()> {
    let mut args = vec![
        "--collect".to_string(),
        format!("--unit={}", unit_name(&rule.id)),
        format!("--on-active={seconds}s"),
        "--timer-property=AccuracySec=1s".to_string(),
        // The uid goes in the description so `systemctl list-timers` and
        // `systemctl status` say who asked for the opening, not just which
        // port is due to close.
        format!(
            "--description=porthole: close {}/{} (uid {})",
            rule.port, rule.protocol, rule.uid
        ),
    ];

    // A non-root process cannot create a system unit anyway — systemd would
    // demand `org.freedesktop.systemd1.manage-units`. Asking for a user unit
    // instead makes the timer run as the same user that scheduled it, which
    // is what `cli_path`'s privilege reasoning assumes: when nothing here is
    // root, the binary the timer runs is not a root-execution target.
    if euid != 0 {
        args.push("--user".to_string());
    }

    args.push(executable.display().to_string());
    args.push("close".to_string());
    args.push("--id".to_string());
    args.push(rule.id.clone());
    args.push("--from-timer".to_string());

    let cmd = Command::mutate("systemd-run", args);
    runner.run(&cmd)?.into_ok(&cmd)?;
    Ok(())
}

/// Cancel a scheduled close, for a rule the user closed early.
///
/// Best effort by design: if the timer already fired, systemd has garbage
/// collected the unit and there is nothing to stop. That is the outcome we
/// wanted anyway, so it is not an error.
pub fn cancel_close(runner: &dyn CommandRunner, id: &str) -> Result<()> {
    let cmd = Command::mutate(
        "systemctl",
        ["stop".to_string(), format!("{}.timer", unit_name(id))],
    );
    runner.run(&cmd)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendId, RuleHandle};
    use crate::command::{Effect, Output, RecordingRunner};
    use crate::model::{Protocol, Target};
    use std::path::PathBuf;

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
    fn unit_names_are_derived_from_the_rule_id() {
        assert_eq!(
            unit_name("1f0c8b6e-0000-4000-8000-000000000001"),
            "porthole-close-1f0c8b6e-0000-4000-8000-000000000001"
        );
    }

    #[test]
    fn schedule_close_as_root_builds_a_system_unit_invocation() {
        // Root can create a system unit, and the timer will run as root, so
        // no `--user` is asked for.
        let runner = RecordingRunner::new();
        schedule_close_for(
            0,
            &runner,
            &PathBuf::from("/usr/bin/porthole"),
            &rule(),
            3600,
        )
        .unwrap();

        let commands = runner.recorded();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].effect, Effect::Mutate);
        assert_eq!(
            commands[0].display(),
            "systemd-run --collect \
             --unit=porthole-close-1f0c8b6e-0000-4000-8000-000000000001 \
             --on-active=3600s --timer-property=AccuracySec=1s \
             '--description=porthole: close 5173/tcp (uid 1000)' \
             /usr/bin/porthole close --id 1f0c8b6e-0000-4000-8000-000000000001 --from-timer"
        );
    }

    #[test]
    fn schedule_close_as_non_root_asks_for_a_user_unit() {
        // A non-root caller cannot create a system unit -- systemd would
        // demand `org.freedesktop.systemd1.manage-units` -- so `--user` must
        // be requested instead, which makes the timer run as this same
        // unprivileged user.
        let runner = RecordingRunner::new();
        schedule_close_for(
            1000,
            &runner,
            &PathBuf::from("/usr/bin/porthole"),
            &rule(),
            3600,
        )
        .unwrap();

        let commands = runner.recorded();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].effect, Effect::Mutate);
        assert_eq!(
            commands[0].display(),
            "systemd-run --collect \
             --unit=porthole-close-1f0c8b6e-0000-4000-8000-000000000001 \
             --on-active=3600s --timer-property=AccuracySec=1s \
             '--description=porthole: close 5173/tcp (uid 1000)' --user \
             /usr/bin/porthole close --id 1f0c8b6e-0000-4000-8000-000000000001 --from-timer"
        );
    }

    #[test]
    fn schedule_close_reports_a_failure_rather_than_swallowing_it() {
        // A rule with no timer is a rule that never closes. This must be loud.
        let runner = RecordingRunner::with_responses(vec![Output {
            status: 1,
            stdout: String::new(),
            stderr: "Failed to start transient timer unit".into(),
        }]);
        let err = schedule_close(&runner, &PathBuf::from("/usr/bin/porthole"), &rule(), 3600)
            .unwrap_err();
        assert!(err.to_string().contains("transient timer"), "got: {err}");
    }

    #[test]
    fn cancel_close_stops_the_timer_unit() {
        let runner = RecordingRunner::new();
        cancel_close(&runner, "1f0c8b6e-0000-4000-8000-000000000001").unwrap();

        let commands = runner.recorded();
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0].display(),
            "systemctl stop porthole-close-1f0c8b6e-0000-4000-8000-000000000001.timer"
        );
    }

    #[test]
    fn cancel_close_is_fine_when_the_timer_already_fired() {
        // The unit was garbage collected after firing. Nothing to stop is the
        // desired end state.
        let runner = RecordingRunner::with_responses(vec![Output {
            status: 5,
            stdout: String::new(),
            stderr: "Failed to stop porthole-close-x.timer: Unit not loaded.".into(),
        }]);
        assert!(cancel_close(&runner, "x").is_ok());
    }
}
