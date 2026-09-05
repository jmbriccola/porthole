//! Talking to the privileged helper.
//!
//! The CLI holds no privilege of its own any more. It asks, polkit decides,
//! and the helper acts. Reads — `list`, `status` — and `--dry-run` stay local
//! and never touch the bus, so they keep working when the helper is absent.

use porthole_core::error::{Error, Result};
use porthole_core::ipc::{PortholeProxy, WireRule};
use porthole_core::state::ManagedRule;

/// One small runtime per invocation. The CLI is a short-lived process that
/// makes one call; a shared runtime would buy nothing.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
        .block_on(f)
}

async fn proxy(session: bool) -> Result<PortholeProxy<'static>> {
    let conn = if session {
        zbus::Connection::session().await
    } else {
        zbus::Connection::system().await
    }
    .map_err(|e| {
        Error::BackendUnavailable(format!(
            "could not reach the porthole helper on the {} bus: {e}. \
             Is porthole installed? `porthole doctor` says what is missing.",
            if session { "session" } else { "system" }
        ))
    })?;
    PortholeProxy::new(&conn)
        .await
        .map_err(|e| Error::Unexpected(format!("could not bind the helper's interface: {e}")))
}

/// Turn a D-Bus error name back into the error the CLI would have produced
/// locally, so `porthole open` exits 5 for "already open" whether it did the
/// work itself or asked the helper to.
fn from_dbus(e: zbus::Error) -> Error {
    if let zbus::Error::MethodError(name, detail, _) = &e {
        let text = detail.clone().unwrap_or_else(|| name.to_string());
        let short = name.as_str().rsplit('.').next().unwrap_or("");
        return match short {
            "InvalidArgument" => Error::InvalidArgument(text),
            "BackendUnavailable" => Error::BackendUnavailable(text),
            "NotAuthorized" => Error::NotAuthorized(text),
            "AlreadyOpen" => Error::AlreadyOpen {
                port: 0,
                protocol: porthole_core::model::Protocol::Tcp,
                detail: text,
            },
            "DeviceUnreachable" => Error::DeviceUnreachable(text),
            "RuleNotFound" => Error::RuleNotFound(text),
            "NoNetwork" => Error::NoNetwork(text),
            // The bus itself answered, but nothing owns `com.jacopobriccola.Porthole`
            // and nothing can be activated to. That is a live system bus with no
            // helper installed — the ordinary "not installed yet" case, and
            // exactly as unprivileged an outcome as failing to reach the bus at
            // all. A real dbus-daemon on an ordinary desktop reports this as
            // `org.freedesktop.DBus.Error.ServiceUnknown` ("The name is not
            // activatable") rather than a connection failure, which is why this
            // cannot simply fall through to `Unexpected`.
            "ServiceUnknown" | "NameHasNoOwner" | "ServiceNotFound" => {
                Error::BackendUnavailable(format!(
                    "the porthole helper is not registered on the bus ({name}: {text}). \
                     Is porthole installed? `porthole doctor` says what is missing."
                ))
            }
            _ => Error::Unexpected(text),
        };
    }
    Error::Unexpected(format!("the helper could not be reached: {e}"))
}

/// A wire rule as the local types, so the CLI's renderers are unchanged.
///
/// The handle is deliberately absent from the wire, so this cannot reconstruct
/// one — and it does not need to: only the helper ever removes a rule.
fn to_local(wire: &WireRule) -> Result<ManagedRule> {
    use porthole_core::backend::{BackendId, RuleHandle};
    use porthole_core::model::Target;

    Ok(ManagedRule {
        id: wire.id.clone(),
        port: wire.port,
        protocol: porthole_core::validate::parse_protocol(&wire.protocol)?,
        target: if wire.scope == "anywhere" {
            Target::Anywhere
        } else {
            Target::Network {
                cidr: wire.target.parse().map_err(|_| {
                    Error::Unexpected(format!("the helper sent `{}` as a network", wire.target))
                })?,
            }
        },
        backend: match wire.backend.as_str() {
            "ufw" => BackendId::Ufw,
            "nftables" => BackendId::Nftables,
            _ => BackendId::Firewalld,
        },
        opened_at: wire.opened_at,
        expires_at: if wire.expires_at == 0 {
            None
        } else {
            Some(wire.expires_at)
        },
        uid: wire.uid,
        // The wire never carries a removal spec. Nothing local removes rules.
        handle: RuleHandle::Firewalld {
            zone: String::new(),
            rich_rule: String::new(),
        },
    })
}

pub fn open(
    session: bool,
    port: u16,
    protocol: &str,
    scope: &str,
    seconds: u32,
) -> Result<ManagedRule> {
    block_on(async {
        let p = proxy(session).await?;
        let wire = p
            .open(port, protocol, scope, seconds)
            .await
            .map_err(from_dbus)?;
        to_local(&wire)
    })
}

pub fn close(session: bool, port: u16, protocol: &str) -> Result<ManagedRule> {
    block_on(async {
        let p = proxy(session).await?;
        let wire = p.close(port, protocol).await.map_err(from_dbus)?;
        to_local(&wire)
    })
}

pub fn close_by_id(session: bool, id: &str) -> Result<ManagedRule> {
    block_on(async {
        let p = proxy(session).await?;
        let wire = p.close_by_id(id).await.map_err(from_dbus)?;
        to_local(&wire)
    })
}

pub fn close_all(session: bool) -> Result<(Vec<ManagedRule>, Vec<Error>)> {
    block_on(async {
        let p = proxy(session).await?;
        let (closed, errors) = p.close_all().await.map_err(from_dbus)?;
        let rules = closed.iter().map(to_local).collect::<Result<Vec<_>>>()?;
        Ok((rules, errors.into_iter().map(Error::Unexpected).collect()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::error::ExitCode;

    fn method_error(name: &str, detail: &str) -> zbus::Error {
        zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(name.to_string()).unwrap(),
            Some(detail.to_string()),
            zbus::message::Message::method_call("/", "Noop")
                .unwrap()
                .build(&())
                .unwrap(),
        )
    }

    #[test]
    fn a_helper_error_name_maps_back_to_the_same_exit_code_the_cli_used_locally() {
        // These numbers are the same public exit codes milestone 1 used when the
        // CLI did the work itself. A client that mapped them differently would
        // silently break every script depending on them.
        assert_eq!(
            from_dbus(method_error(
                "com.jacopobriccola.Porthole.AlreadyOpen",
                "5173/tcp is already open"
            ))
            .exit_code(),
            ExitCode::AlreadyOpen
        );
        assert_eq!(
            from_dbus(method_error(
                "com.jacopobriccola.Porthole.RuleNotFound",
                "no rule matches 5173/tcp"
            ))
            .exit_code(),
            ExitCode::RuleNotFound
        );
        assert_eq!(
            from_dbus(method_error(
                "com.jacopobriccola.Porthole.NotAuthorized",
                "denied"
            ))
            .exit_code(),
            ExitCode::NotAuthorized
        );
        assert_eq!(
            from_dbus(method_error(
                "com.jacopobriccola.Porthole.InvalidArgument",
                "bad port"
            ))
            .exit_code(),
            ExitCode::InvalidArguments
        );
    }

    #[test]
    fn a_service_unknown_error_is_backend_unavailable_not_a_generic_failure() {
        // On an ordinary desktop with a live system bus but no helper installed,
        // dbus-daemon itself answers `ServiceUnknown` — a live bus, an absent
        // helper — rather than failing the connection outright. That is the
        // same situation as not reaching the bus at all, and must exit the same
        // way: 3, not the catch-all 1.
        assert_eq!(
            from_dbus(method_error(
                "org.freedesktop.DBus.Error.ServiceUnknown",
                "The name is not activatable"
            ))
            .exit_code(),
            ExitCode::BackendUnavailable
        );
    }

    #[test]
    fn an_unrecognized_error_name_is_the_catch_all_not_a_crash() {
        assert_eq!(
            from_dbus(method_error("org.freedesktop.DBus.Error.Failed", "boom")).exit_code(),
            ExitCode::Failure
        );
    }
}
