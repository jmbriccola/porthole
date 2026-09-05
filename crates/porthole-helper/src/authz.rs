//! Who is asking, and whether they may.
//!
//! Authorization is a trait for the same reason the firewall backend and the
//! command runner are: without the seam, none of the helper could be tested
//! without a system bus and a polkit agent. [`AlwaysAllow`] exists only for
//! tests; production uses the polkit implementation in `crate::polkit`.

use async_trait::async_trait;
use porthole_core::error::{Error, Result};
use std::sync::Mutex;

/// The polkit actions this helper distinguishes.
///
/// The severity difference is the point: opening towards the current subnet
/// authenticates once per session, opening towards everyone authenticates
/// every time, and closing never authenticates at all — closing reduces
/// exposure and must never be the thing a user cannot be bothered to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    OpenSubnet,
    OpenAny,
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
            Action::Close => "com.jacopobriccola.Porthole.close",
            Action::List => "com.jacopobriccola.Porthole.list",
        }
    }
}

#[async_trait]
pub trait Authorizer: Send + Sync {
    /// `sender` is the caller's unique bus name, from the message header.
    async fn check(&self, action: Action, sender: &str) -> Result<()>;
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
    async fn check(&self, action: Action, sender: &str) -> Result<()> {
        self.asked
            .lock()
            .expect("not poisoned")
            .push((action.id().to_string(), sender.to_string()));
        Ok(())
    }
}

/// The uid behind a bus name, according to the bus daemon.
///
/// The helper never takes a client's word for who it is: the audit trail the
/// spec requires names the *requesting* uid, and a client could claim any.
pub async fn caller_uid(conn: &zbus::Connection, sender: &str) -> Result<u32> {
    let dbus = zbus::fdo::DBusProxy::new(conn)
        .await
        .map_err(|e| Error::Unexpected(format!("could not reach the bus daemon: {e}")))?;
    let name = zbus::names::BusName::try_from(sender.to_string())
        .map_err(|e| Error::Unexpected(format!("`{sender}` is not a bus name: {e}")))?;
    dbus.get_connection_unix_user(name)
        .await
        .map_err(|e| Error::Unexpected(format!("the bus would not name the caller's uid: {e}")))
}
