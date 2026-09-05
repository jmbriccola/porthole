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
            _ => HelperError::Failed(text),
        }
    }
}
