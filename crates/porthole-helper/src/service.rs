//! The privileged object clients talk to.
//!
//! Every method follows the same shape, and the order is deliberate:
//!
//! 1. **Validate**, treating everything the client sent as untrusted. The
//!    helper never accepts a rule string and never acts on a value it would
//!    not have accepted from a person.
//! 2. **Resolve the scope**, because which polkit action applies depends on
//!    what the request actually amounts to — `0.0.0.0/0` is "everyone"
//!    however it was spelled.
//! 3. **Authorize**, before touching anything.
//! 4. **Take the state lock and act.** Not before: a polkit check can block
//!    for as long as a human takes to type a password, and the lock would
//!    stall every other writer for that whole time.
//! 5. **Log to the journal with the requesting uid**, which comes from the bus
//!    daemon rather than from the client.

use crate::authz::{caller_uid, Action, Authorizer};
use crate::error::HelperError;
use porthole_core::backend;
use porthole_core::clock::SystemClock;
use porthole_core::command::RealRunner;
use porthole_core::engine::{resolve_scope, Engine};
use porthole_core::error::Error;
use porthole_core::ipc::{WireRule, WireStatus};
use porthole_core::model::{Lifetime, Target};
use porthole_core::state::StateStore;
use porthole_core::validate;
use std::path::PathBuf;

static SYSTEM_CLOCK: SystemClock = SystemClock;

pub struct Porthole {
    authorizer: Box<dyn Authorizer>,
    /// A second connection to the same bus, used only to ask the daemon which
    /// uid is behind a caller's name. Separate from the connection the object
    /// is served on, which the builder owns.
    bus: zbus::Connection,
    state_path: PathBuf,
    executable: PathBuf,
}

impl Porthole {
    pub fn new(
        authorizer: Box<dyn Authorizer>,
        bus: zbus::Connection,
        state_path: PathBuf,
        executable: PathBuf,
    ) -> Self {
        Porthole {
            authorizer,
            bus,
            state_path,
            executable,
        }
    }

    fn sender(header: &zbus::message::Header<'_>) -> Result<String, HelperError> {
        header
            .sender()
            .map(|s| s.to_string())
            .ok_or_else(|| HelperError::Failed("the message carried no sender".to_string()))
    }
}

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl Porthole {
    /// `scope` is what the user typed — `subnet`, `any`, a CIDR, an IP — and
    /// the helper parses it itself. `seconds` is 0 for until-reboot.
    async fn open(
        &self,
        port: u16,
        protocol: &str,
        scope: &str,
        seconds: u32,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<WireRule, HelperError> {
        let sender = Self::sender(&header)?;

        // 1. Validate. Nothing the client sent is trusted.
        if port == 0 {
            return Err(HelperError::InvalidArgument(
                "port 0 is not a port; valid ports are 1-65535".to_string(),
            ));
        }
        let protocol = validate::parse_protocol(protocol).map_err(HelperError::from)?;
        let spec = validate::parse_scope(scope).map_err(HelperError::from)?;
        let lifetime = if seconds == 0 {
            Lifetime::UntilReboot
        } else {
            Lifetime::For(
                validate::parse_duration(&format!("{seconds}s")).map_err(HelperError::from)?,
            )
        };

        // 2. Resolve before choosing the action, and before taking any lock.
        let runner = RealRunner;
        let target = resolve_scope(&runner, &spec).map_err(HelperError::from)?;
        let action = match target {
            Target::Anywhere => Action::OpenAny,
            Target::Network { .. } => Action::OpenSubnet,
        };

        // 3. Authorize.
        self.authorizer
            .check(action, &sender)
            .await
            .map_err(HelperError::from)?;

        let uid = caller_uid(&self.bus, &sender)
            .await
            .map_err(HelperError::from)?;

        // 4. Only now take the lock and act.
        let backend = backend::detect(&runner).map_err(HelperError::from)?;
        let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
        let mut engine = Engine::new(
            backend.as_ref(),
            &runner,
            &SYSTEM_CLOCK,
            state,
            self.executable.clone(),
        );
        let rule = engine
            .open(port, protocol, &spec, lifetime, uid)
            .map_err(HelperError::from)?;

        // 5. The journal. The helper is a system service, so stderr lands there.
        eprintln!(
            "porthole: uid={} opened {}/{} towards {} until {}",
            rule.uid,
            rule.port,
            rule.protocol,
            rule.target,
            rule.expires_at
                .map(|t| t.to_string())
                .unwrap_or_else(|| "reboot".to_string())
        );

        Ok(WireRule::from_rule(&rule))
    }

    async fn close(
        &self,
        port: u16,
        protocol: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<WireRule, HelperError> {
        let sender = Self::sender(&header)?;
        let protocol = validate::parse_protocol(protocol).map_err(HelperError::from)?;
        self.authorizer
            .check(Action::Close, &sender)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        let backend = backend::detect(&runner).map_err(HelperError::from)?;
        let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
        let mut engine = Engine::new(
            backend.as_ref(),
            &runner,
            &SYSTEM_CLOCK,
            state,
            self.executable.clone(),
        );
        let rule = engine
            .close_by_port(port, protocol, false)
            .map_err(HelperError::from)?;
        Self::log_close(&rule);
        Ok(WireRule::from_rule(&rule))
    }

    async fn close_by_id(
        &self,
        id: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<WireRule, HelperError> {
        let sender = Self::sender(&header)?;
        self.authorizer
            .check(Action::Close, &sender)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        let backend = backend::detect(&runner).map_err(HelperError::from)?;
        let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
        let mut engine = Engine::new(
            backend.as_ref(),
            &runner,
            &SYSTEM_CLOCK,
            state,
            self.executable.clone(),
        );
        let rule = engine.close_by_id(id, false).map_err(HelperError::from)?;
        Self::log_close(&rule);
        Ok(WireRule::from_rule(&rule))
    }

    /// Returns what closed and, separately, the failures — so one stuck rule
    /// cannot hide the others.
    async fn close_all(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(Vec<WireRule>, Vec<String>), HelperError> {
        let sender = Self::sender(&header)?;
        self.authorizer
            .check(Action::Close, &sender)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        let backend = backend::detect(&runner).map_err(HelperError::from)?;
        let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
        let mut engine = Engine::new(
            backend.as_ref(),
            &runner,
            &SYSTEM_CLOCK,
            state,
            self.executable.clone(),
        );
        let (closed, errors) = engine.close_all(false);
        for rule in &closed {
            Self::log_close(rule);
        }
        Ok((
            closed.iter().map(WireRule::from_rule).collect(),
            errors.iter().map(|e| e.to_string()).collect(),
        ))
    }

    async fn list(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Vec<WireRule>, HelperError> {
        let sender = Self::sender(&header)?;
        self.authorizer
            .check(Action::List, &sender)
            .await
            .map_err(HelperError::from)?;
        // Read-only: the plain constructor, so a reader never blocks behind a
        // writer and never creates the state directory.
        let state = StateStore::open(&self.state_path).map_err(HelperError::from)?;
        Ok(state.rules().iter().map(WireRule::from_rule).collect())
    }

    async fn status(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<WireStatus, HelperError> {
        let sender = Self::sender(&header)?;
        self.authorizer
            .check(Action::List, &sender)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        let backend = backend::detect(&runner).map_err(HelperError::from)?;
        let state = StateStore::open(&self.state_path).map_err(HelperError::from)?;
        let engine = Engine::new(
            backend.as_ref(),
            &runner,
            &SYSTEM_CLOCK,
            state,
            self.executable.clone(),
        );
        let status = engine.status().map_err(HelperError::from)?;
        Ok(WireStatus::from_status(&status))
    }
}

impl Porthole {
    fn log_close(rule: &porthole_core::state::ManagedRule) {
        eprintln!(
            "porthole: closed {}/{} towards {} (opened by uid={})",
            rule.port, rule.protocol, rule.target, rule.uid
        );
    }
}

// `Box<dyn Authorizer>` from an Arc, so tests can keep a handle on what the
// authorizer was asked while the service owns it.
#[async_trait::async_trait]
impl Authorizer for std::sync::Arc<crate::authz::AlwaysAllow> {
    async fn check(&self, action: Action, sender: &str) -> Result<(), Error> {
        (**self).check(action, sender).await
    }
}
