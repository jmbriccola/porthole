//! Talking to the privileged helper.
//!
//! The CLI holds no privilege of its own any more. It asks, polkit decides,
//! and the helper acts. Reads — `list`, `status` — and `--dry-run` stay local
//! and never touch the bus, so they keep working when the helper is absent.

use porthole_core::error::{Error, ExitCode, Result};
use porthole_core::ipc::{PortholeProxy, WireError, WireRule};
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

/// Turn a D-Bus error name back into an error carrying the helper's own text,
/// its `--json` kind slug, and the exit code milestone 1 documented.
///
/// It does **not** rebuild the local variant. The helper sends its error
/// already rendered, and every variant whose `Display` has a prefix would
/// double it — `not authorized: not authorized: …`. `AlreadyOpen` is worse
/// still: its template names the port, so rebuilding it with a placeholder
/// made the CLI announce a port the user never asked about. `Error::Remote`
/// exists so the helper's message is reported once, verbatim.
fn from_dbus(e: zbus::Error) -> Error {
    if let zbus::Error::MethodError(name, detail, _) = &e {
        let message = detail.clone().unwrap_or_else(|| name.to_string());
        let short = name.as_str().rsplit('.').next().unwrap_or("");

        // These slugs are the ones `--json` publishes, and they must stay
        // identical to `Error::kind()`'s — a script cannot tell whether the
        // work happened locally or over the bus, and must not have to.
        let (kind, code) = match short {
            "InvalidArgument" => ("invalid_argument", ExitCode::InvalidArguments),
            "BackendUnavailable" => ("backend_unavailable", ExitCode::BackendUnavailable),
            "NotAuthorized" => ("not_authorized", ExitCode::NotAuthorized),
            "AlreadyOpen" => ("already_open", ExitCode::AlreadyOpen),
            "DeviceUnreachable" => ("device_unreachable", ExitCode::DeviceUnreachable),
            "RuleNotFound" => ("rule_not_found", ExitCode::RuleNotFound),
            "NoNetwork" => ("no_network", ExitCode::NoNetwork),
            "CommandFailed" => ("command_failed", ExitCode::Failure),
            "State" => ("state_error", ExitCode::Failure),
            // Not the helper: the bus itself answered, but nothing owns
            // `com.jacopobriccola.Porthole` and nothing can be activated to.
            // That is a live system bus with no helper installed — the
            // ordinary "not installed yet" case, and exactly as unprivileged
            // an outcome as failing to reach the bus at all. A real
            // dbus-daemon on an ordinary desktop reports this as
            // `org.freedesktop.DBus.Error.ServiceUnknown` ("The name is not
            // activatable") rather than a connection failure, which is why
            // this cannot simply fall through to the catch-all below.
            "ServiceUnknown" | "NameHasNoOwner" | "ServiceNotFound" => {
                return Error::BackendUnavailable(format!(
                    "the porthole helper is not registered on the bus ({name}: {message}). \
                     Is porthole installed? `porthole doctor` says what is missing."
                ))
            }
            _ => ("unexpected", ExitCode::Failure),
        };
        return Error::Remote {
            message,
            kind,
            code,
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

pub fn close_by_id(session: bool, id: &str, from_timer: bool) -> Result<ManagedRule> {
    block_on(async {
        let p = proxy(session).await?;
        let wire = p.close_by_id(id, from_timer).await.map_err(from_dbus)?;
        to_local(&wire)
    })
}

/// The kind slugs a `HelperError` variant can name on the wire, mapped back to
/// the `&'static str` `Error::Remote` needs. Anything this client does not
/// recognise — a slug a newer helper introduced — falls back to
/// `"unexpected"` rather than failing to parse the response at all.
fn static_kind(kind: &str) -> &'static str {
    match kind {
        "invalid_argument" => "invalid_argument",
        "backend_unavailable" => "backend_unavailable",
        "not_authorized" => "not_authorized",
        "already_open" => "already_open",
        "device_unreachable" => "device_unreachable",
        "rule_not_found" => "rule_not_found",
        "no_network" => "no_network",
        "command_failed" => "command_failed",
        "state_error" => "state_error",
        _ => "unexpected",
    }
}

/// The reverse of `ExitCode as i32`. `ExitCode`'s own doc comment says never
/// to renumber an existing value, so this small, closed mapping is safe to
/// hardcode rather than round-trip through a derive.
fn exit_code_from_i32(code: i32) -> ExitCode {
    match code {
        2 => ExitCode::InvalidArguments,
        3 => ExitCode::BackendUnavailable,
        4 => ExitCode::NotAuthorized,
        5 => ExitCode::AlreadyOpen,
        6 => ExitCode::DeviceUnreachable,
        7 => ExitCode::RuleNotFound,
        8 => ExitCode::NoNetwork,
        _ => ExitCode::Failure,
    }
}

/// A `close_all` per-rule failure, as the local `Error` type.
///
/// `Error::Remote`, not a reconstructed local variant: the helper already
/// rendered `message`, and rebuilding a variant from it would double every
/// prefixing template exactly as `from_dbus` above is careful not to.
fn wire_error_to_local(e: WireError) -> Error {
    Error::Remote {
        message: e.message,
        kind: static_kind(&e.kind),
        code: exit_code_from_i32(e.code),
    }
}

pub fn close_all(session: bool) -> Result<(Vec<ManagedRule>, Vec<Error>)> {
    block_on(async {
        let p = proxy(session).await?;
        let (closed, errors) = p.close_all().await.map_err(from_dbus)?;
        let rules = closed.iter().map(to_local).collect::<Result<Vec<_>>>()?;
        Ok((
            rules,
            errors.into_iter().map(wire_error_to_local).collect(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn remote_errors_report_the_helpers_words_once_not_doubled() {
        // The helper sends its message already rendered. Rebuilding a local
        // variant from it ran that variant's own prefixing template a second
        // time over text that had already been through it — and for
        // `AlreadyOpen`, whose template also names the port, it invented a
        // port (0) that nobody asked about, since the wire's `MethodError`
        // carries no structured port field to refill it with. Covers the two
        // names the reviewer's reproduction did not happen to exercise
        // (`NotAuthorized`, `RuleNotFound`) plus every other previously-broken
        // variant, so none of the five can regress unnoticed.
        let cases = [
            (
                "com.jacopobriccola.Porthole.InvalidArgument",
                "invalid argument: bad port",
            ),
            (
                "com.jacopobriccola.Porthole.NotAuthorized",
                "not authorized: denied by policy",
            ),
            (
                "com.jacopobriccola.Porthole.DeviceUnreachable",
                "device not reachable: laptop",
            ),
            (
                "com.jacopobriccola.Porthole.RuleNotFound",
                "no rule matches 5173/tcp",
            ),
            (
                "com.jacopobriccola.Porthole.AlreadyOpen",
                "5173/tcp is already open (open towards 10.10.10.0/24)",
            ),
        ];
        for (name, message) in cases {
            let reported = from_dbus(method_error(name, message)).to_string();
            assert_eq!(reported, message, "doubled or altered for {name}");
            assert!(!reported.contains("0/tcp"), "no invented port for {name}");
        }
    }

    #[test]
    fn every_kind_slug_matches_the_local_variants_own_kind() {
        // `--json` publishes `kind`. A script must not be able to tell whether
        // an error came from the CLI acting locally or from the helper over
        // the bus, so these slugs must be byte-identical to `Error::kind()`'s
        // own — checked here against the real local variants, not retyped.
        //
        // Every `HelperError` variant is covered, not just the ones that
        // happened to round-trip before: `CommandFailed` and `State` used to
        // collapse into the `Failed` catch-all and report `"unexpected"`,
        // which is exactly the drift `docs/json-schema.md`'s slug-equivalence
        // promise cannot afford.
        use porthole_core::model::Protocol;

        let cases: &[(&str, Error)] = &[
            (
                "com.jacopobriccola.Porthole.InvalidArgument",
                Error::InvalidArgument(String::new()),
            ),
            (
                "com.jacopobriccola.Porthole.BackendUnavailable",
                Error::BackendUnavailable(String::new()),
            ),
            (
                "com.jacopobriccola.Porthole.NotAuthorized",
                Error::NotAuthorized(String::new()),
            ),
            (
                "com.jacopobriccola.Porthole.AlreadyOpen",
                Error::AlreadyOpen {
                    port: 0,
                    protocol: Protocol::Tcp,
                    detail: String::new(),
                },
            ),
            (
                "com.jacopobriccola.Porthole.DeviceUnreachable",
                Error::DeviceUnreachable(String::new()),
            ),
            (
                "com.jacopobriccola.Porthole.RuleNotFound",
                Error::RuleNotFound(String::new()),
            ),
            (
                "com.jacopobriccola.Porthole.NoNetwork",
                Error::NoNetwork(String::new()),
            ),
            (
                "com.jacopobriccola.Porthole.CommandFailed",
                Error::CommandFailed {
                    command: String::new(),
                    status: 1,
                    stderr: String::new(),
                },
            ),
            (
                "com.jacopobriccola.Porthole.State",
                Error::State {
                    path: String::new(),
                    detail: String::new(),
                },
            ),
        ];
        for (name, local) in cases {
            let reported = from_dbus(method_error(name, "x"));
            assert_eq!(reported.kind(), local.kind(), "kind slug drifted for {name}");
            assert_eq!(
                reported.exit_code(),
                local.exit_code(),
                "exit code drifted for {name}"
            );
        }
    }

    #[test]
    fn close_all_failures_keep_their_structured_kind_over_the_bus() {
        // I3: close_all's per-rule failures used to be `.to_string()`'d away
        // into `Error::Unexpected`, so `close --all --json` reported
        // `"kind":"unexpected"` for a failure that would have been
        // `"command_failed"` locally. `wire_error_to_local` is what
        // `close_all` maps every `WireError` through before handing failures
        // back to `run.rs`.
        let wire = WireError {
            message: "command `firewall-cmd ...` exited with status 1: boom".to_string(),
            kind: "command_failed".to_string(),
            code: ExitCode::Failure as i32,
        };
        let local = wire_error_to_local(wire);
        assert_eq!(local.kind(), "command_failed");
        assert_eq!(local.exit_code(), ExitCode::Failure);
        assert_eq!(local.to_string(), "command `firewall-cmd ...` exited with status 1: boom");
    }

    #[test]
    fn an_unrecognised_wire_kind_falls_back_to_unexpected_rather_than_panicking() {
        // Forward compatibility: an older client meeting a newer helper's new
        // kind slug must degrade gracefully, not crash.
        let wire = WireError {
            message: "something new".to_string(),
            kind: "brand_new_kind_this_client_has_never_heard_of".to_string(),
            code: 1,
        };
        assert_eq!(wire_error_to_local(wire).kind(), "unexpected");
    }
}
