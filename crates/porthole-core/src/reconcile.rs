//! Bringing the firewall and the state file back into agreement.
//!
//! Two things pull them apart: `firewall-cmd --reload` and a reboot wipe
//! runtime rules while the state file survives on tmpfs only until reboot;
//! and ufw's rules survive a reboot while the state file does not. So the
//! drift runs in both directions depending on the backend, and both are
//! handled here.
//!
//! # When this runs, and why not only at start-up
//!
//! The obvious moment is "when the helper starts". That is not reliable: the
//! helper is D-Bus activated, so it can start, serve one call and exit long
//! before the next `firewall-cmd --reload` happens. [`sweep`] instead runs
//! before every operation that reads or writes state -- see `Engine`'s own
//! callers -- which costs one listing command the operation was already
//! going to make, and covers a reload, a reboot, or a rule removed by hand,
//! with no signal subscription and no long-lived process.
//!
//! The residual staleness is unobserved staleness: between two porthole
//! commands, the state file can claim a port is open that the firewall has
//! already dropped. That is the safe direction -- porthole over-reports
//! exposure rather than under-reporting it -- and the next command corrects
//! it.
//!
//! # The direction that does not exist on firewalld
//!
//! Removing "rules the firewall has that state does not know about" is only
//! safe when porthole can prove which rules are its own. firewalld rich rules
//! carry no marker, so on firewalld that sweep would delete every rich rule
//! the user ever wrote by hand. [`FirewallBackend::owned_rules`] returns
//! `None` there, which is why this module cannot perform that direction
//! rather than merely declining to: there is no list to sweep.

use crate::backend::{FirewallBackend, Ownership, RuleHandle};
use crate::error::{Error, Result};
use crate::state::{ManagedRule, StateStore};

/// What one sweep found and did.
#[derive(Debug)]
pub struct Report {
    /// State entries whose rule the firewall no longer has.
    pub dropped_from_state: Vec<ManagedRule>,
    /// Marked rules the firewall had and state did not.
    pub removed_orphans: Vec<RuleHandle>,
    /// Set when the backend cannot prove ownership, so the orphan sweep did
    /// not run. `None` means it ran.
    ///
    /// This is reported rather than left implicit: "found no orphans" and
    /// "could not look for orphans" are different facts, and a caller that
    /// cannot tell them apart will eventually present the second as the
    /// first.
    pub skipped_orphan_sweep: Option<Ownership>,
    /// Orphans that could not be removed. Never fatal: one stuck rule must
    /// not stop the rest of the cleanup.
    pub failures: Vec<Error>,
}

/// Bring `store` back into agreement with what `backend` actually holds.
///
/// 1. `backend.list_rules()`, once.
/// 2. Every state entry whose handle is not in that list is stale -- the
///    firewall no longer has it -- so it is dropped from `store` and
///    recorded in [`Report::dropped_from_state`]. Safe on every backend: it
///    never touches the firewall, only porthole's own bookkeeping.
/// 3. `backend.owned_rules()`. `None` means this backend cannot prove which
///    rules are its own -- see the module docs -- so the orphan direction is
///    skipped and [`Report::skipped_orphan_sweep`] says why. `Some(owned)`
///    closes every owned handle that no state entry claims, recording each
///    success in [`Report::removed_orphans`] and each failure in
///    [`Report::failures`] without letting one stop the rest.
/// 4. `store` is saved only if step 2 actually removed something: every
///    porthole command runs a sweep, and rewriting the state file on each
///    one would churn `/run` for nothing and widen the window in which a
///    concurrent reader sees a half-written file.
///
/// A failure here -- to list rules, to check ownership, or to save the
/// reduced state -- returns `Err` rather than being absorbed into the
/// report. That is deliberate: this function has no way to know whether its
/// caller can tolerate losing the sweep, so it reports the failure honestly
/// and leaves the decision to the caller. `Engine`'s own callers make that
/// decision by logging and continuing: the user asked to open a port, not to
/// tidy up, and refusing their request because an unrelated stale rule would
/// not delete is a worse outcome than a rule left behind.
pub fn sweep(backend: &dyn FirewallBackend, store: &mut StateStore) -> Result<Report> {
    let mut report = Report {
        dropped_from_state: Vec::new(),
        removed_orphans: Vec::new(),
        skipped_orphan_sweep: None,
        failures: Vec::new(),
    };

    // state -> firewall: drop anything the firewall no longer has.
    let present = backend.list_rules()?;
    let stale_ids: Vec<String> = store
        .rules()
        .iter()
        .filter(|rule| !present.contains(&rule.handle))
        .map(|rule| rule.id.clone())
        .collect();
    for id in stale_ids {
        if let Some(rule) = store.remove(&id) {
            report.dropped_from_state.push(rule);
        }
    }

    // firewall -> state: remove what porthole can prove is its own and state
    // no longer claims. Never attempted where ownership cannot be proven.
    match backend.owned_rules()? {
        None => {
            report.skipped_orphan_sweep = Some(backend.ownership());
        }
        Some(owned) => {
            let known: Vec<RuleHandle> = store
                .rules()
                .iter()
                .map(|rule| rule.handle.clone())
                .collect();
            for handle in owned {
                if known.contains(&handle) {
                    continue;
                }
                match backend.close(&handle) {
                    Ok(()) => report.removed_orphans.push(handle),
                    Err(e) => report.failures.push(e),
                }
            }
        }
    }

    if !report.dropped_from_state.is_empty() {
        store.save()?;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::fake::FakeBackend;
    use crate::backend::firewalld;
    use crate::backend::firewalld::tests::{ROUTE_JSON, ZONE};
    use crate::backend::BackendId;
    use crate::command::{CommandRunner, Effect, Output, RecordingRunner};
    use crate::model::{Lifetime, OpenRequest, Protocol, Target};
    use std::time::Duration;
    use tempfile::TempDir;

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

    fn managed(id: &str, port: u16) -> ManagedRule {
        ManagedRule {
            id: id.to_string(),
            port,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            backend: BackendId::Firewalld,
            opened_at: 1_757_000_000,
            expires_at: None,
            uid: 1000,
            handle: RuleHandle::Firewalld {
                zone: "TestZone".to_string(),
                // Distinct per port, so two entries never collide as equal.
                rich_rule: format!("a rule no backend in this test actually has, for {port}"),
            },
        }
    }

    fn managed_with_handle(id: &str, port: u16, handle: RuleHandle) -> ManagedRule {
        ManagedRule {
            handle,
            ..managed(id, port)
        }
    }

    /// A state store backed by a real, throwaway file. `saved_generation`
    /// reads the file's mtime, so the file has to actually exist on disk for
    /// that to mean anything -- hence the `save()` here, not just an
    /// in-memory store.
    fn store_with(rules: Vec<ManagedRule>) -> StateStore {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let mut store = StateStore::open(&path).unwrap();
        for rule in rules {
            store.insert(rule);
        }
        store.save().unwrap();
        // `store` remembers only the path, not this guard; every test here
        // needs the directory to outlive this function.
        std::mem::forget(dir);
        store
    }

    #[test]
    fn a_rule_the_firewall_no_longer_has_is_dropped_from_state() {
        // What a `firewall-cmd --reload` looks like from porthole's side.
        let backend = FakeBackend::new();
        let mut store = store_with(vec![managed("a", 5173), managed("b", 6000)]);
        // The backend knows about neither: the reload wiped them.
        let report = sweep(&backend, &mut store).unwrap();
        assert_eq!(report.dropped_from_state.len(), 2);
        assert!(store.rules().is_empty());
    }

    #[test]
    fn a_marked_rule_state_does_not_know_about_is_removed() {
        let backend = FakeBackend::new();
        backend.open(&request(5173), "porthole:orphan").unwrap();
        let mut store = store_with(vec![]);
        let report = sweep(&backend, &mut store).unwrap();
        assert_eq!(report.removed_orphans.len(), 1);
        assert!(backend.handles().is_empty(), "the orphan is gone");
    }

    #[test]
    fn on_firewalld_no_rule_is_ever_removed_from_the_firewall() {
        // The test that would have caught the bug. A firewalld zone holding a
        // rich rule the user wrote by hand must come through a sweep
        // untouched: porthole cannot prove the rule is not its own, so it
        // must not act.
        const USER_RULE: &str = r#"rule family="ipv4" source address="192.168.0.0/16" port port="22" protocol="tcp" accept"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(USER_RULE),
        ]);
        let backend = firewalld::Firewalld::new(&runner);
        let mut store = store_with(vec![]);

        let report = sweep(&backend, &mut store).unwrap();

        assert!(report.removed_orphans.is_empty());
        assert_eq!(
            report.skipped_orphan_sweep,
            Some(Ownership::Unprovable),
            "the report must say the sweep was skipped, not imply it found nothing"
        );
        for cmd in runner.recorded() {
            assert_eq!(
                cmd.effect,
                Effect::Read,
                "a firewalld sweep must never mutate: {}",
                cmd.display()
            );
        }
    }

    #[test]
    fn a_rule_present_on_both_sides_is_left_alone() {
        let backend = FakeBackend::new();
        let handle = backend.open(&request(5173), "porthole:a").unwrap();
        let mut store = store_with(vec![managed_with_handle("a", 5173, handle)]);
        let report = sweep(&backend, &mut store).unwrap();
        assert!(report.dropped_from_state.is_empty());
        assert!(report.removed_orphans.is_empty());
        assert_eq!(store.rules().len(), 1);
    }

    #[test]
    fn a_failed_orphan_removal_does_not_abort_the_rest_of_the_sweep() {
        // One stuck rule must not stop porthole from cleaning up the others,
        // and must not be silently forgotten either.
        let backend = FakeBackend::new();
        backend.open(&request(5173), "porthole:x").unwrap();
        backend.open(&request(6000), "porthole:y").unwrap();
        backend.fail_close_for("porthole:x");
        let mut store = store_with(vec![]);
        let report = sweep(&backend, &mut store).unwrap();
        assert_eq!(report.removed_orphans.len(), 1);
        assert_eq!(report.failures.len(), 1);
    }

    #[test]
    fn the_sweep_saves_state_only_when_it_changed_something() {
        // Every porthole command runs a sweep. Rewriting the state file on
        // each one would churn /run for nothing and widen the window in
        // which a concurrent reader sees a half-written file.
        let backend = FakeBackend::new();
        let handle = backend.open(&request(5173), "porthole:a").unwrap();
        let mut store = store_with(vec![managed_with_handle("a", 5173, handle)]);
        let before = store.saved_generation();
        sweep(&backend, &mut store).unwrap();
        assert_eq!(
            store.saved_generation(),
            before,
            "nothing changed, nothing written"
        );
    }
}
