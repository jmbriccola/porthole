//! Every external process porthole runs goes through here.
//!
//! Commands declare whether they read or change state. That single distinction
//! is what makes `--dry-run` honest: a dry run still executes reads, so it
//! reports the real backend, the real zone and the real subnet, and it only
//! withholds the commands that would change something.

use crate::error::{Error, Result};
use std::collections::VecDeque;
use std::process::{Command as StdCommand, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Reads state. Always executed, including under dry-run.
    Read,
    /// Changes state. Withheld and recorded under dry-run.
    Mutate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
    pub effect: Effect,
}

impl Command {
    pub fn new(
        effect: Effect,
        program: &str,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Command {
            program: program.to_string(),
            args: args.into_iter().map(Into::into).collect(),
            effect,
        }
    }

    pub fn read(program: &str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Command::new(Effect::Read, program, args)
    }

    pub fn mutate(program: &str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Command::new(Effect::Mutate, program, args)
    }

    /// The command as a single shell-quoted line, suitable for printing under
    /// `--dry-run` and for pasting into a terminal.
    pub fn display(&self) -> String {
        let mut out = shell_quote(&self.program);
        for arg in &self.args {
            out.push(' ');
            out.push_str(&shell_quote(arg));
        }
        out
    }
}

fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// A successful, empty result.
    pub fn empty() -> Self {
        Output {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// A successful result with the given stdout. For tests.
    pub fn stdout(text: &str) -> Self {
        Output {
            status: 0,
            stdout: text.to_string(),
            stderr: String::new(),
        }
    }

    /// A non-zero result with the given text on stderr. For tests.
    pub fn failure(text: &str) -> Self {
        Output {
            status: 1,
            stdout: String::new(),
            stderr: text.to_string(),
        }
    }

    pub fn success(&self) -> bool {
        self.status == 0
    }

    /// Turn a non-zero exit into an error. Callers that want to inspect the
    /// status themselves — `firewall-cmd --state` exits non-zero when the
    /// daemon is stopped — simply do not call this.
    pub fn into_ok(self, cmd: &Command) -> Result<Output> {
        if self.success() {
            Ok(self)
        } else {
            Err(Error::CommandFailed {
                command: cmd.display(),
                status: self.status,
                stderr: self.stderr.trim().to_string(),
            })
        }
    }
}

pub trait CommandRunner {
    fn run(&self, cmd: &Command) -> Result<Output>;

    /// Run `cmd`, giving up on it after `bound`.
    ///
    /// `Ok(None)` is the bound being reached and the child being killed;
    /// the command produced no answer and there is none to report. A
    /// command that finishes in time returns `Ok(Some(output))` with
    /// whatever status it exited with, exactly as [`CommandRunner::run`]
    /// does.
    ///
    /// The default runs `cmd` with no bound at all. It fits the runners
    /// that cannot block -- a scripted one replaying recorded output has
    /// nothing to wait for -- and means a runner only implements this when
    /// waiting is a thing it can really do.
    fn run_within(&self, cmd: &Command, _bound: Duration) -> Result<Option<Output>> {
        self.run(cmd).map(Some)
    }

    /// True when mutations are withheld. Backends use this to skip read-back
    /// steps that cannot work when nothing was actually changed.
    fn is_dry_run(&self) -> bool {
        false
    }

    /// The mutations that were withheld, in order.
    fn recorded(&self) -> Vec<Command> {
        Vec::new()
    }
}

/// How often a bounded run asks whether the child has finished. Short
/// enough that the bound is met closely, long enough that a command
/// answering in milliseconds costs one wake-up.
const BOUNDED_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Runs commands for real.
pub struct RealRunner;

impl CommandRunner for RealRunner {
    fn run(&self, cmd: &Command) -> Result<Output> {
        let output = StdCommand::new(&cmd.program)
            .args(&cmd.args)
            .output()
            .map_err(|source| Error::CommandSpawn {
                command: cmd.display(),
                source,
            })?;
        Ok(Output {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_string(),
            stderr: String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_string(),
        })
    }

    /// Spawns, polls [`Child::try_wait`], and kills the child once `bound`
    /// has passed. Output is read only after the child has exited, so it
    /// suits a command whose output fits the pipe buffer -- a child that
    /// filled 64 KiB and blocked writing would never be seen to exit, and
    /// would be killed at the bound. Every caller here runs a name lookup
    /// that answers in one short line.
    ///
    /// [`Child::try_wait`]: std::process::Child::try_wait
    fn run_within(&self, cmd: &Command, bound: Duration) -> Result<Option<Output>> {
        let spawn_error = |source| Error::CommandSpawn {
            command: cmd.display(),
            source,
        };
        let mut child = StdCommand::new(&cmd.program)
            .args(&cmd.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(spawn_error)?;

        let deadline = Instant::now() + bound;
        while child.try_wait().map_err(spawn_error)?.is_none() {
            if Instant::now() >= deadline {
                // Both are best-effort on a child that is already gone or
                // already reaped; neither failure changes the answer, which
                // is that the bound was reached and there is nothing to
                // report.
                let _ = child.kill();
                let _ = child.wait();
                return Ok(None);
            }
            std::thread::sleep(BOUNDED_POLL_INTERVAL);
        }

        let output = child.wait_with_output().map_err(spawn_error)?;
        Ok(Some(Output {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_string(),
            stderr: String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_string(),
        }))
    }
}

/// Executes reads, records mutations without running them.
pub struct DryRunRunner {
    inner: Box<dyn CommandRunner>,
    recorded: Mutex<Vec<Command>>,
}

impl DryRunRunner {
    pub fn new(inner: Box<dyn CommandRunner>) -> Self {
        DryRunRunner {
            inner,
            recorded: Mutex::new(Vec::new()),
        }
    }
}

impl CommandRunner for DryRunRunner {
    fn run(&self, cmd: &Command) -> Result<Output> {
        match cmd.effect {
            Effect::Read => self.inner.run(cmd),
            Effect::Mutate => {
                self.recorded
                    .lock()
                    .expect("dry-run recorder is not poisoned")
                    .push(cmd.clone());
                Ok(Output::empty())
            }
        }
    }

    fn run_within(&self, cmd: &Command, bound: Duration) -> Result<Option<Output>> {
        match cmd.effect {
            // The bound is the inner runner's to keep: a dry run executes
            // reads for real, so a read that hangs hangs a dry run too.
            Effect::Read => self.inner.run_within(cmd, bound),
            Effect::Mutate => {
                self.recorded
                    .lock()
                    .expect("dry-run recorder is not poisoned")
                    .push(cmd.clone());
                Ok(Some(Output::empty()))
            }
        }
    }

    fn is_dry_run(&self) -> bool {
        true
    }

    fn recorded(&self) -> Vec<Command> {
        self.recorded
            .lock()
            .expect("dry-run recorder is not poisoned")
            .clone()
    }
}

/// Runs nothing. Records every command and replays scripted outputs in order.
/// For tests.
pub struct RecordingRunner {
    responses: Mutex<VecDeque<Output>>,
    recorded: Mutex<Vec<Command>>,
}

impl RecordingRunner {
    pub fn new() -> Self {
        RecordingRunner::with_responses(Vec::new())
    }

    pub fn with_responses(responses: Vec<Output>) -> Self {
        RecordingRunner {
            responses: Mutex::new(responses.into()),
            recorded: Mutex::new(Vec::new()),
        }
    }
}

impl Default for RecordingRunner {
    fn default() -> Self {
        RecordingRunner::new()
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&self, cmd: &Command) -> Result<Output> {
        self.recorded
            .lock()
            .expect("recorder is not poisoned")
            .push(cmd.clone());
        Ok(self
            .responses
            .lock()
            .expect("script is not poisoned")
            .pop_front()
            .unwrap_or_else(Output::empty))
    }

    fn recorded(&self) -> Vec<Command> {
        self.recorded
            .lock()
            .expect("recorder is not poisoned")
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_quotes_only_what_needs_quoting() {
        let cmd = Command::mutate(
            "firewall-cmd",
            [
                "--zone=FedoraWorkstation",
                r#"--add-rich-rule=rule family="ipv4" port port="5173" protocol="tcp" accept"#,
            ],
        );
        assert_eq!(
            cmd.display(),
            "firewall-cmd --zone=FedoraWorkstation \
             '--add-rich-rule=rule family=\"ipv4\" port port=\"5173\" protocol=\"tcp\" accept'"
        );
    }

    #[test]
    fn display_escapes_embedded_single_quotes() {
        let cmd = Command::mutate("echo", ["it's"]);
        assert_eq!(cmd.display(), r#"echo 'it'\''s'"#);
    }

    #[test]
    fn real_runner_executes_and_captures() {
        let runner = RealRunner;
        let out = runner
            .run(&Command::read("printf", ["%s", "hello"]))
            .unwrap();
        assert_eq!(out.status, 0);
        assert_eq!(out.stdout, "hello");
        assert!(out.success());
    }

    #[test]
    fn real_runner_reports_nonzero_status_without_erroring() {
        let runner = RealRunner;
        let out = runner
            .run(&Command::read("false", Vec::<String>::new()))
            .unwrap();
        assert_eq!(out.status, 1);
        assert!(!out.success());
    }

    #[test]
    fn into_ok_turns_a_failure_into_an_error() {
        let cmd = Command::read("false", Vec::<String>::new());
        let out = Output {
            status: 1,
            stdout: String::new(),
            stderr: "boom".into(),
        };
        let err = out.into_ok(&cmd).unwrap_err();
        assert!(err.to_string().contains("status 1"), "got: {err}");
        assert!(err.to_string().contains("boom"), "got: {err}");
    }

    #[test]
    fn missing_program_is_a_spawn_error_not_a_panic() {
        let runner = RealRunner;
        let err = runner
            .run(&Command::read(
                "porthole-no-such-program",
                Vec::<String>::new(),
            ))
            .unwrap_err();
        assert!(err.to_string().contains("could not run"), "got: {err}");
    }

    #[test]
    fn dry_run_executes_reads_but_records_mutations() {
        let runner = DryRunRunner::new(Box::new(RealRunner));
        assert!(runner.is_dry_run());

        let read = runner
            .run(&Command::read("printf", ["%s", "real"]))
            .unwrap();
        assert_eq!(read.stdout, "real", "reads must still run under dry-run");

        let mutate = runner
            .run(&Command::mutate("printf", ["%s", "SHOULD NOT RUN"]))
            .unwrap();
        assert_eq!(mutate.status, 0);
        assert_eq!(mutate.stdout, "");

        let recorded = runner.recorded();
        assert_eq!(recorded.len(), 1, "only mutations are recorded");
        assert_eq!(recorded[0].program, "printf");
        assert_eq!(recorded[0].effect, Effect::Mutate);
    }

    #[test]
    fn recording_runner_replays_scripted_outputs_in_order() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("first"),
            Output::stdout("second"),
        ]);
        assert_eq!(
            runner.run(&Command::read("a", ["1"])).unwrap().stdout,
            "first"
        );
        assert_eq!(
            runner.run(&Command::read("b", ["2"])).unwrap().stdout,
            "second"
        );
        // Past the end of the script, calls succeed with empty output.
        assert_eq!(runner.run(&Command::read("c", ["3"])).unwrap().stdout, "");

        let recorded = runner.recorded();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0].display(), "a 1");
        assert_eq!(recorded[2].display(), "c 3");
    }
}
