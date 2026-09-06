//! Errors and the exit codes they map to.
//!
//! Exit codes are part of porthole's public interface: they are documented in
//! the man page and scripts depend on them. Add new codes at the end; never
//! renumber an existing one.

use crate::model::Protocol;

pub type Result<T> = std::result::Result<T, Error>;

/// Process exit codes. Documented in the README and the man page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// The operation completed.
    Success = 0,
    /// Something went wrong that has no more specific code.
    Failure = 1,
    /// The command line was malformed. Also clap's own parse-failure code.
    InvalidArguments = 2,
    /// No supported firewall is installed, or the installed one is not running.
    BackendUnavailable = 3,
    /// The caller is not allowed to perform the operation.
    NotAuthorized = 4,
    /// The requested port is already open.
    AlreadyOpen = 5,
    /// A saved device could not be resolved to an address on this network.
    DeviceUnreachable = 6,
    /// No porthole-managed rule matches the given port or id.
    RuleNotFound = 7,
    /// There is no usable network interface to open towards.
    NoNetwork = 8,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("{0}")]
    BackendUnavailable(String),

    /// The README's exit-code table says exit 4 means "Polkit refused the
    /// request. Never `sudo`." That sentence is true only because this
    /// variant has exactly one production construction site today —
    /// `polkit.rs`'s `denied()`. Nothing in the type system enforces that; if
    /// a second call site is ever added, either keep the sentence true or go
    /// update the README, because nothing else will notice the two have
    /// drifted apart.
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    #[error("{port}/{protocol} is already open ({detail})")]
    AlreadyOpen {
        port: u16,
        protocol: Protocol,
        detail: String,
    },

    #[error("device not reachable: {0}")]
    DeviceUnreachable(String),

    #[error("no rule matches {0}")]
    RuleNotFound(String),

    #[error("{0}")]
    NoNetwork(String),

    #[error("command `{command}` exited with status {status}: {stderr}")]
    CommandFailed {
        command: String,
        status: i32,
        stderr: String,
    },

    #[error("could not run `{command}`: {source}")]
    CommandSpawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    /// Also what `lock_exclusive` returns when the exclusive state lock could
    /// not be acquired within its bounded wait -- see `state::lock_exclusive`
    /// for why that wait is bounded rather than indefinite in the first
    /// place. Not split into its own variant: nothing today gives a caller
    /// anything useful to do with "the lock was busy" that "a state error
    /// happened" does not already cover, and a dedicated exit code no
    /// invocation could actually produce would be documented for a signal no
    /// one could observe.
    #[error("state file {path}: {detail}")]
    State { path: String, detail: String },

    #[error("{0}")]
    Unexpected(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An error the privileged helper already rendered.
    ///
    /// Carries its own kind slug and exit code so the CLI reports exactly what
    /// the helper said, once. Rebuilding a local variant from a rendered
    /// message doubles every prefixing template — and for `AlreadyOpen`, whose
    /// template names the port, it made the CLI announce a port nobody asked
    /// about.
    #[error("{message}")]
    Remote {
        message: String,
        kind: &'static str,
        code: ExitCode,
    },
}

impl Error {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Error::InvalidArgument(_) => ExitCode::InvalidArguments,
            Error::BackendUnavailable(_) => ExitCode::BackendUnavailable,
            Error::NotAuthorized(_) => ExitCode::NotAuthorized,
            Error::AlreadyOpen { .. } => ExitCode::AlreadyOpen,
            Error::DeviceUnreachable(_) => ExitCode::DeviceUnreachable,
            Error::RuleNotFound(_) => ExitCode::RuleNotFound,
            Error::NoNetwork(_) => ExitCode::NoNetwork,
            Error::Remote { code, .. } => *code,
            Error::CommandFailed { .. }
            | Error::CommandSpawn { .. }
            | Error::State { .. }
            | Error::Unexpected(_)
            | Error::Io(_) => ExitCode::Failure,
        }
    }

    /// A stable machine-readable slug, emitted in `--json` error output.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "invalid_argument",
            Error::BackendUnavailable(_) => "backend_unavailable",
            Error::NotAuthorized(_) => "not_authorized",
            Error::AlreadyOpen { .. } => "already_open",
            Error::DeviceUnreachable(_) => "device_unreachable",
            Error::RuleNotFound(_) => "rule_not_found",
            Error::NoNetwork(_) => "no_network",
            Error::Remote { kind, .. } => kind,
            Error::CommandFailed { .. } => "command_failed",
            Error::CommandSpawn { .. } => "command_spawn_failed",
            Error::State { .. } => "state_error",
            Error::Unexpected(_) => "unexpected",
            Error::Io(_) => "io_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        // These numbers are a public interface. Scripts depend on them.
        assert_eq!(ExitCode::Success as i32, 0);
        assert_eq!(ExitCode::Failure as i32, 1);
        assert_eq!(ExitCode::InvalidArguments as i32, 2);
        assert_eq!(ExitCode::BackendUnavailable as i32, 3);
        assert_eq!(ExitCode::NotAuthorized as i32, 4);
        assert_eq!(ExitCode::AlreadyOpen as i32, 5);
        assert_eq!(ExitCode::DeviceUnreachable as i32, 6);
        assert_eq!(ExitCode::RuleNotFound as i32, 7);
        assert_eq!(ExitCode::NoNetwork as i32, 8);
    }

    #[test]
    fn each_error_maps_to_its_exit_code() {
        assert_eq!(
            Error::InvalidArgument("bad".into()).exit_code(),
            ExitCode::InvalidArguments
        );
        assert_eq!(
            Error::BackendUnavailable("none".into()).exit_code(),
            ExitCode::BackendUnavailable
        );
        assert_eq!(
            Error::NotAuthorized("root required".into()).exit_code(),
            ExitCode::NotAuthorized
        );
        assert_eq!(
            Error::RuleNotFound("5173/tcp".into()).exit_code(),
            ExitCode::RuleNotFound
        );
        assert_eq!(
            Error::NoNetwork("no default route".into()).exit_code(),
            ExitCode::NoNetwork
        );
    }

    #[test]
    fn error_kind_is_a_stable_machine_readable_slug() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "invalid_argument"
        );
        assert_eq!(Error::NoNetwork("x".into()).kind(), "no_network");
    }

    #[test]
    fn a_remote_error_reports_the_helpers_words_once() {
        // The helper sends its message already rendered. Re-wrapping it in a
        // local variant's template doubles the prefix; for AlreadyOpen it also
        // invents a port.
        let e = Error::Remote {
            message: "5173/tcp is already open (open towards 10.10.10.0/24)".to_string(),
            kind: "already_open",
            code: ExitCode::AlreadyOpen,
        };
        assert_eq!(
            e.to_string(),
            "5173/tcp is already open (open towards 10.10.10.0/24)"
        );
        assert_eq!(e.kind(), "already_open");
        assert_eq!(e.exit_code(), ExitCode::AlreadyOpen);
        assert!(!e.to_string().contains("0/tcp"), "no invented port");
    }
}
