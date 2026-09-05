//! Asking polkit whether the caller may do this.
//!
//! polkit is a system service: it tracks names on the **system** bus, and no
//! polkit exists on a session bus. So this type cannot be exercised end to
//! end without root, which is exactly why [`crate::authz::Authorizer`] is a
//! trait and why `AlwaysAllow` exists for tests.
//!
//! The severity difference between the actions is the whole point, and it
//! lives in the installed policy file rather than here: `open-subnet` is
//! `auth_admin_keep` so a user authenticates once per session, `open-any` is
//! `auth_admin` so a bigger choice costs more every time, and `close` is `yes`
//! because closing reduces exposure and must never be the thing a user cannot
//! be bothered to do.
//!
//! # Why the subject is built from the message header, not a pid
//!
//! [`zbus_polkit::policykit1::Subject`] has no constructor that takes a bare
//! bus name string. The two that exist are `new_for_owner(pid, start_time,
//! uid)` and `new_for_message_header(&header)`. A pid-based subject was
//! rejected: looking up the caller's pid first and checking it second leaves
//! a window in which the pid could be reused by a different, unrelated
//! process, so the authorization decision could be made against a process
//! that never asked for anything. The bus name in the message header is
//! stamped by the bus daemon itself and cannot be forged by the sender, so
//! [`Authorizer::check`](crate::authz::Authorizer::check) takes the header
//! rather than a sender string a caller could otherwise have supplied.

use crate::authz::{Action, Authorizer, Details};
use async_trait::async_trait;
use porthole_core::error::{Error, Result};
use porthole_core::model::{Protocol, Target};
use std::collections::HashMap;
use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

/// The `$(key)` substitutions for the two `open-*` policy messages: the port,
/// the protocol and the target porthole actually resolved.
///
/// Without these a person sees only the static sentence in the `.policy`
/// file and cannot tell an expected prompt from an unexpected one, or notice
/// that the resolved target is not what they typed. `close` and `list` need
/// nothing here — their messages name nothing request-specific.
pub fn open_details(port: u16, protocol: Protocol, target: &Target) -> Details {
    let mut details = Details::new();
    details.insert("port", port.to_string());
    details.insert("protocol", protocol.to_string());
    details.insert("target", target.to_string());
    details
}

/// The refusal a caller sees. Separate function so the message is identical
/// whether polkit said no or the subject could not be built.
fn denied(action: Action) -> Error {
    Error::NotAuthorized(format!(
        "polkit refused {}. Opening towards the current subnet asks once per \
         session; opening towards everyone asks every time.",
        action.id()
    ))
}

pub struct PolkitAuthorizer {
    authority: AuthorityProxy<'static>,
}

impl PolkitAuthorizer {
    pub async fn new(conn: &zbus::Connection) -> Result<Self> {
        let authority = AuthorityProxy::new(conn)
            .await
            .map_err(|e| Error::Unexpected(format!("polkit is not reachable: {e}")))?;
        Ok(PolkitAuthorizer { authority })
    }
}

#[async_trait]
impl Authorizer for PolkitAuthorizer {
    async fn check(
        &self,
        action: Action,
        details: &Details,
        header: &zbus::message::Header<'_>,
    ) -> Result<()> {
        // The subject is the caller's *system bus name*, taken from the
        // header the bus daemon stamped. polkit resolves it to a process
        // itself, so nothing the client says about who it is matters.
        let subject = Subject::new_for_message_header(header).map_err(|_| denied(action))?;

        // polkit substitutes `$(key)` in the action's `<message>` from
        // exactly this map — the same mechanism udisks uses to name the
        // drive in its own prompts. `check_authorization` wants borrowed
        // strings; `details` owns them so callers can build them from
        // formatted values.
        let raw: HashMap<&str, &str> = details.iter().map(|(k, v)| (*k, v.as_str())).collect();

        let result = self
            .authority
            .check_authorization(
                &subject,
                action.id(),
                &raw,
                // The user may be asked. That is the point: the whole design
                // is one authentication instead of a sudo per gesture.
                CheckAuthorizationFlags::AllowUserInteraction.into(),
                "",
            )
            .await
            .map_err(|e| Error::Unexpected(format!("polkit would not answer: {e}")))?;

        if result.is_authorized {
            Ok(())
        } else {
            Err(denied(action))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denial_is_not_authorized_rather_than_a_generic_failure() {
        // The CLI maps NotAuthorized to exit code 4, which is documented. A
        // denial that arrived as a generic failure would exit 1 and tell the
        // user nothing about why.
        let err = denied(Action::OpenAny);
        assert_eq!(
            err.exit_code(),
            porthole_core::error::ExitCode::NotAuthorized
        );
        assert!(
            err.to_string().contains("open-any"),
            "the message must name the action that was refused: {err}"
        );
    }

    #[test]
    fn every_action_has_a_denial_message_naming_it() {
        for action in [
            Action::OpenSubnet,
            Action::OpenAny,
            Action::Close,
            Action::List,
        ] {
            let text = denied(action).to_string();
            assert!(
                text.contains(action.id()),
                "{} is not named in its own denial: {text}",
                action.id()
            );
        }
    }
}
