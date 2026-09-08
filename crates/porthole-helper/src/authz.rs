//! Who is asking, and whether they may.
//!
//! Authorization is a trait for the same reason the firewall backend and the
//! command runner are: without the seam, none of the helper could be tested
//! without a system bus and a polkit agent. [`AlwaysAllow`] exists only for
//! tests; production uses the polkit implementation in `crate::polkit`.

use async_trait::async_trait;
use porthole_core::error::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;

/// The `$(key)` substitutions available to a polkit `<message>`.
///
/// The `open-*` actions and `forward` have something request-specific to
/// say; `close` and `list` pass an empty map. Keys are the static names the
/// installed policy file's messages reference (`port`, `protocol`, `target`,
/// and `published_port` for a forward) — see [`crate::polkit::open_details`]
/// and [`crate::polkit::forward_details`].
pub type Details = HashMap<&'static str, String>;

/// The polkit actions this helper distinguishes.
///
/// The severity difference is the point: opening towards the current subnet
/// authenticates once per session, opening towards everyone authenticates
/// every time, and closing never authenticates at all — closing reduces
/// exposure and must never be the thing a user cannot be bothered to do.
///
/// [`Action::Forward`] authenticates every time as well, and unlike the two
/// `open-*` actions it does not depend on the target: a forward makes a port
/// published on this machine answer to another machine, which is not a thing
/// to be carried along by an authentication given minutes ago for something
/// else. It is the one action chosen unconditionally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    OpenSubnet,
    OpenAny,
    Forward,
    Close,
    List,
}

impl Action {
    /// The action id, which must match the installed polkit policy exactly.
    /// If these drift apart polkit falls back to its default and the whole
    /// severity distinction silently disappears.
    pub fn id(self) -> &'static str {
        match self {
            Action::OpenSubnet => "com.jacopobriccola.Porthole.open-subnet",
            Action::OpenAny => "com.jacopobriccola.Porthole.open-any",
            Action::Forward => "com.jacopobriccola.Porthole.forward",
            Action::Close => "com.jacopobriccola.Porthole.close",
            Action::List => "com.jacopobriccola.Porthole.list",
        }
    }
}

#[async_trait]
pub trait Authorizer: Send + Sync {
    /// `header` is the header of the message making the request. polkit (and
    /// [`caller_uid`]) resolve an identity from the bus daemon's own record
    /// of who sent this exact message; there is nothing else here a client
    /// could claim to be, which is the point of taking the header rather
    /// than a bus name the caller merely asserts.
    ///
    /// `details` is what a polkit `<message>` may interpolate via `$(key)` —
    /// the port, protocol and resolved target for an open, empty for
    /// everything else.
    async fn check(
        &self,
        action: Action,
        details: &Details,
        header: &zbus::message::Header<'_>,
    ) -> Result<()>;
}

/// Allows everything and remembers what it was asked. Tests only.
#[derive(Debug, Default)]
pub struct AlwaysAllow {
    asked: Mutex<Vec<(String, String)>>,
}

impl AlwaysAllow {
    /// Every (action id, sender) pair seen, in order.
    pub fn asked(&self) -> Vec<(String, String)> {
        self.asked.lock().expect("not poisoned").clone()
    }
}

#[async_trait]
impl Authorizer for AlwaysAllow {
    async fn check(
        &self,
        action: Action,
        _details: &Details,
        header: &zbus::message::Header<'_>,
    ) -> Result<()> {
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();
        self.asked
            .lock()
            .expect("not poisoned")
            .push((action.id().to_string(), sender));
        Ok(())
    }
}

/// The uid behind the sender of a message, according to the bus daemon.
///
/// The helper never takes a client's word for who it is: the audit trail the
/// spec requires names the *requesting* uid, and a client could claim any.
/// Taking the header rather than a bus name string means there is nothing
/// else here for a caller to have claimed in the first place.
pub async fn caller_uid(
    conn: &zbus::Connection,
    header: &zbus::message::Header<'_>,
) -> Result<u32> {
    let sender = header
        .sender()
        .ok_or_else(|| Error::Unexpected("the message carried no sender".to_string()))?;
    let dbus = zbus::fdo::DBusProxy::new(conn)
        .await
        .map_err(|e| Error::Unexpected(format!("could not reach the bus daemon: {e}")))?;
    dbus.get_connection_unix_user(sender.clone().into())
        .await
        .map_err(|e| Error::Unexpected(format!("the bus would not name the caller's uid: {e}")))
}
