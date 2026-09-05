//! Asking polkit whether the caller may do this.
//!
//! polkit is a system service: it tracks names on the **system** bus, and no
//! polkit exists on a session bus. So a real authorizer here cannot be
//! exercised end to end without root, which is exactly why
//! [`crate::authz::Authorizer`] is a trait and why `AlwaysAllow` exists for
//! tests.
//!
//! The severity difference between the actions is the whole point, and it
//! lives in the installed policy file rather than here: `open-subnet` is
//! `auth_admin_keep` so a user authenticates once per session, `open-any` is
//! `auth_admin` so a bigger choice costs more every time, and `close` is `yes`
//! because closing reduces exposure and must never be the thing a user cannot
//! be bothered to do.
//!
//! # Blocked: building a `Subject` needs more than a bus name string
//!
//! This module was expected to hold `PolkitAuthorizer`, an
//! [`crate::authz::Authorizer`] that asks
//! `zbus_polkit::policykit1::AuthorityProxy::check_authorization` about the
//! caller's system bus name via
//! `zbus_polkit::policykit1::Subject::new_for_system_bus_name(sender)`.
//!
//! That constructor does not exist in `zbus_polkit` 5.1.0. The `Subject`
//! constructors that do exist are:
//!
//! - `Subject::new_for_owner(pid, start_time, uid)` — needs a pid, not a bus
//!   name.
//! - `Subject::new_for_message_header(&zbus::message::Header<'_>)` — builds
//!   the same "system-bus-name" subject kind this module wants, but it needs
//!   the message header, not the `sender: &str` that
//!   [`crate::authz::Authorizer::check`] currently takes.
//!
//! `sender: &str` was already flagged by task 3's reviewer as a loose
//! parameter. This confirms it: polkit's own API wants the header instead.
//! Widening `Authorizer::check` to take `&zbus::message::Header<'_>` is a
//! deliberate design change to a shared trait, so it is reported rather than
//! made unilaterally here — see the task report for the two constructors
//! found and a recommendation. `PolkitAuthorizer` itself is not implemented
//! pending that decision.
//!
//! What follows — the denial mapping every action shares — does not depend
//! on that decision either way, so it is real and tested now.

use crate::authz::Action;
use porthole_core::error::Error;

/// The refusal a caller sees. Separate function so the message is identical
/// whether polkit said no or the subject could not be built.
///
/// Not yet called outside tests: the caller that would call it,
/// `PolkitAuthorizer::check`, is the part blocked above.
#[allow(dead_code)]
fn denied(action: Action) -> Error {
    Error::NotAuthorized(format!(
        "polkit refused {}. Opening towards the current subnet asks once per \
         session; opening towards everyone asks every time.",
        action.id()
    ))
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
