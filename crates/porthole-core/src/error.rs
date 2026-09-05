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

    #[error("state file {path}: {detail}")]
    State { path: String, detail: String },

    #[error("{0}")]
    Unexpected(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
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
}
