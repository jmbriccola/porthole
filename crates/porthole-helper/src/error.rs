//! Core errors as distinct D-Bus error names.
//!
//! A client maps the name back to the same exit code the CLI uses locally, so
//! `porthole open` exits 5 for "already open" whether it did the work itself
//! or asked the helper to.

use porthole_core::error::Error;

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "com.jacopobriccola.Porthole")]
pub enum HelperError {
    InvalidArgument(String),
    BackendUnavailable(String),
    NotAuthorized(String),
    AlreadyOpen(String),
    DeviceUnreachable(String),
    RuleNotFound(String),
    NoNetwork(String),
    /// A `firewall-cmd` (or other backend command) invocation that ran but
    /// exited non-zero. Its own D-Bus name, so the client's `kind` slug stays
    /// `command_failed` over the bus exactly as it is locally, rather than
    /// falling into the `Failed` catch-all below and reporting `"unexpected"`.
    CommandFailed(String),
    /// The state file could not be read or written. Same reasoning as
    /// `CommandFailed`: its own name keeps the `state_error` kind slug intact
    /// across the bus.
    State(String),
    /// Everything else: a command that could not even be spawned, a raw I/O
    /// error, or a truly unexpected condition. These have no request-specific
    /// meaning worth distinguishing on the wire, so the client reports them
    /// all as `"unexpected"` -- unlike `CommandFailed` and `State` above,
    /// which are common enough in practice (a stale rich rule, a full disk)
    /// that `docs/json-schema.md`'s promise of an identical `kind` locally
    /// and over the bus has to hold for them too.
    Failed(String),
}

impl From<Error> for HelperError {
    fn from(e: Error) -> Self {
        let text = e.to_string();
        match e {
            Error::InvalidArgument(_) => HelperError::InvalidArgument(text),
            Error::BackendUnavailable(_) => HelperError::BackendUnavailable(text),
            Error::NotAuthorized(_) => HelperError::NotAuthorized(text),
            Error::AlreadyOpen { .. } => HelperError::AlreadyOpen(text),
            Error::DeviceUnreachable(_) => HelperError::DeviceUnreachable(text),
            Error::RuleNotFound(_) => HelperError::RuleNotFound(text),
            Error::NoNetwork(_) => HelperError::NoNetwork(text),
            Error::CommandFailed { .. } => HelperError::CommandFailed(text),
            Error::State { .. } => HelperError::State(text),
            _ => HelperError::Failed(text),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_failure_keeps_its_own_wire_name_rather_than_the_catch_all() {
        let err = Error::CommandFailed {
            command: "firewall-cmd --zone=x".to_string(),
            status: 1,
            stderr: "boom".to_string(),
        };
        assert!(matches!(
            HelperError::from(err),
            HelperError::CommandFailed(_)
        ));
    }

    #[test]
    fn a_state_failure_keeps_its_own_wire_name_rather_than_the_catch_all() {
        let err = Error::State {
            path: "/run/porthole/state.json".to_string(),
            detail: "boom".to_string(),
        };
        assert!(matches!(HelperError::from(err), HelperError::State(_)));
    }

    #[test]
    fn everything_else_still_collapses_to_the_catch_all() {
        assert!(matches!(
            HelperError::from(Error::Unexpected("x".to_string())),
            HelperError::Failed(_)
        ));
        assert!(matches!(
            HelperError::from(Error::Io(std::io::Error::other("x"))),
            HelperError::Failed(_)
        ));
    }
}
