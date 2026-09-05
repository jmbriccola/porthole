//! An in-memory backend for tests.
//!
//! It impersonates firewalld, so `RuleHandle` and `BackendId` — both of which
//! are serialised into the state file — need no test-only variants.

use super::{BackendHealth, BackendId, FirewallBackend, Ownership, RuleHandle};
use crate::error::{Error, Result};
use crate::model::OpenRequest;
use std::sync::Mutex;

pub const FAKE_ZONE: &str = "TestZone";

pub struct FakeBackend {
    health: BackendHealth,
    opened: Mutex<Vec<OpenRequest>>,
    handles: Mutex<Vec<RuleHandle>>,
    markers: Mutex<Vec<String>>,
}

impl FakeBackend {
    /// A firewall that is installed and running.
    pub fn new() -> Self {
        FakeBackend::with_health(BackendHealth {
            available: true,
            active: true,
            version: Some("0.0.0-fake".into()),
            detail: "fake backend, running".into(),
        })
    }

    /// A firewall that is installed but stopped.
    pub fn inactive() -> Self {
        FakeBackend::with_health(BackendHealth {
            available: true,
            active: false,
            version: Some("0.0.0-fake".into()),
            detail: "fake backend, not running".into(),
        })
    }

    /// No firewall at all.
    pub fn absent() -> Self {
        FakeBackend::with_health(BackendHealth {
            available: false,
            active: false,
            version: None,
            detail: "fake backend, not installed".into(),
        })
    }

    fn with_health(health: BackendHealth) -> Self {
        FakeBackend {
            health,
            opened: Mutex::new(Vec::new()),
            handles: Mutex::new(Vec::new()),
            markers: Mutex::new(Vec::new()),
        }
    }

    /// Every request passed to `open`, in order.
    pub fn opened(&self) -> Vec<OpenRequest> {
        self.opened.lock().expect("not poisoned").clone()
    }

    /// Handles that are currently open.
    pub fn handles(&self) -> Vec<RuleHandle> {
        self.handles.lock().expect("not poisoned").clone()
    }

    /// Every marker passed to `open`, in order. Lets later tasks' tests assert
    /// the `porthole:<uuid>` marker actually reached the backend.
    pub fn markers(&self) -> Vec<String> {
        self.markers.lock().expect("not poisoned").clone()
    }
}

impl Default for FakeBackend {
    fn default() -> Self {
        FakeBackend::new()
    }
}

impl FirewallBackend for FakeBackend {
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
        Ok(handle)
    }

    fn close(&self, handle: &RuleHandle) -> Result<()> {
        let mut handles = self.handles.lock().expect("not poisoned");
        match handles.iter().position(|h| h == handle) {
            Some(index) => {
                handles.remove(index);
                Ok(())
            }
            None => Err(Error::Unexpected(format!(
                "fake backend has no such rule: {handle:?}"
            ))),
        }
    }

    fn list_rules(&self) -> Result<Vec<RuleHandle>> {
        Ok(self.handles())
    }

    fn owned_rules(&self) -> Result<Option<Vec<RuleHandle>>> {
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
    fn health_variants_describe_the_three_states() {
        let healthy = FakeBackend::new().health().unwrap();
        assert!(healthy.available && healthy.active);

        let stopped = FakeBackend::inactive().health().unwrap();
        assert!(stopped.available && !stopped.active);

        let missing = FakeBackend::absent().health().unwrap();
        assert!(!missing.available && !missing.active);
    }
}
