//! An in-memory backend for tests.
//!
//! It impersonates firewalld, so `RuleHandle` and `BackendId` — both of which
//! are serialised into the state file — need no test-only variants.

use super::{BackendHealth, BackendId, FirewallBackend, Ownership, RuleHandle};
use crate::error::{Error, Result};
use crate::forward::ForwardTo;
use crate::model::OpenRequest;
use std::collections::HashSet;
use std::sync::Mutex;

pub const FAKE_ZONE: &str = "TestZone";

pub struct FakeBackend {
    health: BackendHealth,
    opened: Mutex<Vec<OpenRequest>>,
    /// (request, destination) for every `forward`, in order. Separate from
    /// `opened`: a forward is not an open, and a test asserting what `open`
    /// received must not see one.
    forwarded: Mutex<Vec<(OpenRequest, ForwardTo)>>,
    handles: Mutex<Vec<RuleHandle>>,
    markers: Mutex<Vec<String>>,
    /// (handle, marker) for every rule currently open, kept in sync with
    /// `handles` across a successful `close` -- unlike `markers`, which is a
    /// deliberate append-only history. `close` needs this to look up which
    /// marker a handle belongs to, so `fail_close_for` can inject a failure
    /// by marker rather than by a handle the caller would have to fabricate.
    live: Mutex<Vec<(RuleHandle, String)>>,
    /// Markers whose `close` must fail without removing the rule. Set by
    /// `fail_close_for`, for tests exercising "one stuck rule must not abort
    /// the rest of a sweep or a `close --all`".
    fail_close: Mutex<HashSet<String>>,
    /// Set by `fail_list_rules`. For tests proving a sweep failure must not
    /// fail the operation the caller actually asked for.
    fail_list_rules: Mutex<bool>,
    /// Set by `fail_owned_rules`. For tests proving the safe direction's
    /// write does not depend on the unsafe direction succeeding.
    fail_owned_rules: Mutex<bool>,
}

impl FakeBackend {
    /// A firewall that is installed and running.
    pub fn new() -> Self {
        FakeBackend::with_health(BackendHealth {
            available: true,
            active: true,
            active_unknown: false,
            version: Some("0.0.0-fake".into()),
            detail: "fake backend, running".into(),
            caveat: None,
        })
    }

    /// A firewall that is installed but confirmed stopped.
    pub fn inactive() -> Self {
        FakeBackend::with_health(BackendHealth {
            available: true,
            active: false,
            active_unknown: false,
            version: Some("0.0.0-fake".into()),
            detail: "fake backend, not running".into(),
            caveat: None,
        })
    }

    /// A firewall that is installed, but whose ruleset porthole could not
    /// read -- ufw and nftables' shape for a permission-denied caller. Not
    /// the same fact as [`FakeBackend::inactive`]: distinguishing the two is
    /// the whole point of `active_unknown`, so a caller that treats them the
    /// same defeats the fake meant to catch that.
    pub fn active_unknown() -> Self {
        FakeBackend::with_health(BackendHealth {
            available: true,
            active: false,
            active_unknown: true,
            version: Some("0.0.0-fake".into()),
            detail: "fake backend, needs more privilege to read".into(),
            caveat: None,
        })
    }

    /// No firewall at all.
    pub fn absent() -> Self {
        FakeBackend::with_health(BackendHealth {
            available: false,
            active: false,
            active_unknown: false,
            version: None,
            detail: "fake backend, not installed".into(),
            caveat: None,
        })
    }

    fn with_health(health: BackendHealth) -> Self {
        FakeBackend {
            health,
            opened: Mutex::new(Vec::new()),
            forwarded: Mutex::new(Vec::new()),
            handles: Mutex::new(Vec::new()),
            markers: Mutex::new(Vec::new()),
            live: Mutex::new(Vec::new()),
            fail_close: Mutex::new(HashSet::new()),
            fail_list_rules: Mutex::new(false),
            fail_owned_rules: Mutex::new(false),
        }
    }

    /// Every request passed to `open`, in order.
    pub fn opened(&self) -> Vec<OpenRequest> {
        self.opened.lock().expect("not poisoned").clone()
    }

    /// Every request passed to `forward`, with the destination it was given,
    /// in order.
    pub fn forwarded(&self) -> Vec<(OpenRequest, ForwardTo)> {
        self.forwarded.lock().expect("not poisoned").clone()
    }

    /// Handles that are currently open.
    pub fn handles(&self) -> Vec<RuleHandle> {
        self.handles.lock().expect("not poisoned").clone()
    }

    /// Every marker passed to `open` or `forward`, in order. Lets later
    /// tasks' tests assert the `porthole:<uuid>` marker actually reached the
    /// backend.
    pub fn markers(&self) -> Vec<String> {
        self.markers.lock().expect("not poisoned").clone()
    }

    /// Make the rule opened under `marker` refuse to close, without removing
    /// it. For reconciliation's tests: one stuck rule must not stop the rest
    /// of a sweep, and this is how a test proves that without needing a
    /// handle the backend never issued at all -- `close` already rejects
    /// that for an unrelated reason.
    pub fn fail_close_for(&self, marker: &str) {
        self.fail_close
            .lock()
            .expect("not poisoned")
            .insert(marker.to_string());
    }

    /// Make every subsequent `list_rules` call return an error.
    pub fn fail_list_rules(&self) {
        *self.fail_list_rules.lock().expect("not poisoned") = true;
    }

    /// Make every subsequent `owned_rules` call return an error.
    pub fn fail_owned_rules(&self) {
        *self.fail_owned_rules.lock().expect("not poisoned") = true;
    }
}

impl Default for FakeBackend {
    fn default() -> Self {
        FakeBackend::new()
    }
}

impl FirewallBackend for FakeBackend {
    // This method returns `Firewalld` while `ownership()`, further down this
    // same impl, returns `Marked` -- a pairing no real backend has (the real
    // `Firewalld` is `Unprovable`; the two backends that are `Marked` report
    // `Ufw` or `Nftables`). Deliberate, not an oversight: most of this
    // suite's tests care about the marked-ownership behaviour
    // reconciliation's orphan sweep exercises, not about which id happens to
    // come back, and inventing a fourth `BackendId` just for this fake would
    // need one added everywhere `BackendId` is matched exhaustively
    // (`RuleHandle`, `output.rs`'s `location_label`, this crate's own
    // `ownership_and_owned_rules_agree_for_every_backend` test, and more) for
    // a value nothing serialises or reads meaningfully. Keep this pairing in
    // mind before trusting `FakeBackend` for anything that depends on the two
    // agreeing the way a real backend's do.
    fn id(&self) -> BackendId {
        BackendId::Firewalld
    }

    fn open(&self, req: &OpenRequest, marker: &str) -> Result<RuleHandle> {
        let handle = RuleHandle::Firewalld {
            zone: FAKE_ZONE.to_string(),
            rich_rule: format!(
                "fake rule for {}/{} towards {}",
                req.port, req.protocol, req.target
            ),
        };
        self.opened.lock().expect("not poisoned").push(req.clone());
        self.handles
            .lock()
            .expect("not poisoned")
            .push(handle.clone());
        self.markers
            .lock()
            .expect("not poisoned")
            .push(marker.to_string());
        self.live
            .lock()
            .expect("not poisoned")
            .push((handle.clone(), marker.to_string()));
        Ok(handle)
    }

    /// One rule, and an ordinary handle for it -- the same shape firewalld's
    /// real `forward` produces, so a rule created here closes and reconciles
    /// through exactly the paths an opened one does.
    fn forward(&self, req: &OpenRequest, to: &ForwardTo, marker: &str) -> Result<RuleHandle> {
        let handle = RuleHandle::Firewalld {
            zone: FAKE_ZONE.to_string(),
            rich_rule: format!(
                "fake forward for {}/{} towards {} to {}:{}",
                req.port, req.protocol, req.target, to.container_addr, to.container_port
            ),
        };
        self.forwarded
            .lock()
            .expect("not poisoned")
            .push((req.clone(), to.clone()));
        self.handles
            .lock()
            .expect("not poisoned")
            .push(handle.clone());
        self.markers
            .lock()
            .expect("not poisoned")
            .push(marker.to_string());
        self.live
            .lock()
            .expect("not poisoned")
            .push((handle.clone(), marker.to_string()));
        Ok(handle)
    }

    fn close(&self, handle: &RuleHandle) -> Result<()> {
        let mut live = self.live.lock().expect("not poisoned");
        let Some(index) = live.iter().position(|(h, _)| h == handle) else {
            return Err(Error::Unexpected(format!(
                "fake backend has no such rule: {handle:?}"
            )));
        };
        let marker = live[index].1.clone();
        if self
            .fail_close
            .lock()
            .expect("not poisoned")
            .contains(&marker)
        {
            return Err(Error::Unexpected(format!(
                "fake backend: close forced to fail for {marker}"
            )));
        }
        live.remove(index);
        drop(live);

        let mut handles = self.handles.lock().expect("not poisoned");
        if let Some(index) = handles.iter().position(|h| h == handle) {
            handles.remove(index);
        }
        Ok(())
    }

    fn list_rules(&self) -> Result<Vec<RuleHandle>> {
        if *self.fail_list_rules.lock().expect("not poisoned") {
            return Err(Error::Unexpected(
                "fake backend: list_rules forced to fail".to_string(),
            ));
        }
        Ok(self.handles())
    }

    fn owned_rules(&self) -> Result<Option<Vec<RuleHandle>>> {
        if *self.fail_owned_rules.lock().expect("not poisoned") {
            return Err(Error::Unexpected(
                "fake backend: owned_rules forced to fail".to_string(),
            ));
        }
        Ok(Some(self.handles()))
    }

    fn ownership(&self) -> Ownership {
        Ownership::Marked
    }

    fn health(&self) -> Result<BackendHealth> {
        Ok(self.health.clone())
    }

    fn location(&self) -> Result<Option<String>> {
        Ok(Some(FAKE_ZONE.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Lifetime, OpenRequest, Protocol, Target};
    use std::time::Duration;

    fn request(port: u16) -> OpenRequest {
        OpenRequest {
            port,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            lifetime: Lifetime::For(Duration::from_secs(3600)),
        }
    }

    #[test]
    fn open_records_the_request_and_returns_a_handle() {
        let backend = FakeBackend::new();
        let handle = backend.open(&request(5173), "porthole:test").unwrap();

        assert_eq!(backend.opened(), vec![request(5173)]);
        assert_eq!(backend.handles(), vec![handle]);
    }

    #[test]
    fn open_stores_the_marker_it_was_given() {
        let backend = FakeBackend::new();
        backend.open(&request(5173), "porthole:abc-123").unwrap();
        assert_eq!(backend.markers(), vec!["porthole:abc-123".to_string()]);
    }

    #[test]
    fn forward_records_the_request_and_its_destination_apart_from_opens() {
        let backend = FakeBackend::new();
        let to = ForwardTo {
            container_addr: "172.18.0.2".parse().unwrap(),
            container_port: 8080,
            published_port: 3000,
            protocol: Protocol::Tcp,
        };
        let handle = backend
            .forward(&request(8443), &to, "porthole:abc-123")
            .unwrap();

        assert_eq!(backend.forwarded(), vec![(request(8443), to)]);
        assert!(
            backend.opened().is_empty(),
            "a forward is not an open, and must not show up as one"
        );
        assert_eq!(backend.handles(), vec![handle.clone()]);
        assert_eq!(backend.markers(), vec!["porthole:abc-123".to_string()]);

        // The handle is an ordinary one: closing it works the same way.
        backend.close(&handle).unwrap();
        assert!(backend.handles().is_empty());
    }

    #[test]
    fn close_removes_the_handle() {
        let backend = FakeBackend::new();
        let handle = backend.open(&request(5173), "porthole:test").unwrap();
        backend.close(&handle).unwrap();
        assert!(backend.handles().is_empty());
    }

    #[test]
    fn close_of_an_unknown_handle_is_an_error() {
        let backend = FakeBackend::new();
        let stray = RuleHandle::Firewalld {
            zone: "TestZone".into(),
            rich_rule: "rule nobody added".into(),
        };
        assert!(backend.close(&stray).is_err());
    }

    #[test]
    fn list_rules_returns_open_handles() {
        let backend = FakeBackend::new();
        backend.open(&request(5173), "porthole:test").unwrap();
        backend.open(&request(5174), "porthole:test").unwrap();
        assert_eq!(backend.list_rules().unwrap().len(), 2);
    }

    #[test]
    fn owned_rules_returns_the_same_handles_as_list_rules() {
        let backend = FakeBackend::new();
        backend.open(&request(5173), "porthole:test").unwrap();
        assert_eq!(
            backend.owned_rules().unwrap().unwrap(),
            backend.list_rules().unwrap()
        );
    }

    #[test]
    fn a_backend_that_can_prove_ownership_says_so() {
        assert_eq!(FakeBackend::new().ownership(), Ownership::Marked);
    }

    #[test]
    fn health_variants_describe_the_four_states() {
        let healthy = FakeBackend::new().health().unwrap();
        assert!(healthy.available && healthy.active && !healthy.active_unknown);

        let stopped = FakeBackend::inactive().health().unwrap();
        assert!(stopped.available && !stopped.active && !stopped.active_unknown);

        let unknown = FakeBackend::active_unknown().health().unwrap();
        assert!(unknown.available && !unknown.active && unknown.active_unknown);

        let missing = FakeBackend::absent().health().unwrap();
        assert!(!missing.available && !missing.active && !missing.active_unknown);
    }
}
