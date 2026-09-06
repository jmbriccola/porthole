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
//!
//! # Read paths must not be able to mutate
//!
//! `status` and `Engine::rules` reconcile too, so their answer does not claim
//! a port is open that the firewall already dropped. But the direction that
//! removes an orphan *mutates the firewall*, and `status` is gated by the
//! `List` polkit action, not `Close` -- a caller authorised only to look must
//! never be able to cause a close. [`SweepMode::ReadOnly`] exists for exactly
//! this: it computes and reflects the safe direction in memory, and never
//! even calls [`FirewallBackend::owned_rules`], let alone
//! [`FirewallBackend::close`]. See [`SweepMode`].

use crate::backend::{FirewallBackend, Ownership, RuleHandle};
use crate::error::{Error, Result};
use crate::state::{ManagedRule, StateStore};

/// How much of reconciliation a caller is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepMode {
    /// Reconcile both directions and persist the safe one. What every
    /// state-changing operation (`open`, `close_by_id`, `close_by_port`,
    /// `close_all`) uses.
    ///
    /// `dry_run` mirrors the caller's own dry run: the safe direction's drops
    /// are still computed and reflected in `store`'s in-memory view (so a
    /// dry-run report tells the truth about what is actually open), but
    /// never written to disk. The orphan direction's `close` calls are not
    /// specially withheld here -- they are ordinary [`crate::command::Effect::Mutate`]
    /// commands, which the caller's own [`crate::command::CommandRunner`]
    /// withholds under dry-run exactly as it would for the operation's own
    /// mutations.
    Apply { dry_run: bool },
    /// Compute the safe direction only, reflect it in `store`'s in-memory
    /// view, and stop there: never saves, and never even calls
    /// [`FirewallBackend::owned_rules`] -- the orphan direction is the only
    /// one that mutates the firewall, so a read path must never reach it.
    /// What `status` and `Engine::rules` use.
    ReadOnly,
}

/// What one sweep found and did.
#[derive(Debug)]
pub struct Report {
    /// State entries whose rule the firewall no longer has.
    pub dropped_from_state: Vec<ManagedRule>,
    /// Marked rules the firewall had and state did not.
    pub removed_orphans: Vec<RuleHandle>,
    /// Set when the backend cannot prove ownership, so the orphan sweep did
    /// not run. `None` means it ran. Only ever set under [`SweepMode::Apply`]
    /// -- under [`SweepMode::ReadOnly`] the orphan sweep is never attempted
    /// at all, for a reason that has nothing to do with ownership, so this
    /// stays `None` there regardless.
    ///
    /// This is reported rather than left implicit: "found no orphans" and
    /// "could not look for orphans" are different facts, and a caller that
    /// cannot tell them apart will eventually present the second as the
    /// first.
    pub skipped_orphan_sweep: Option<Ownership>,
    /// Things that went wrong while sweeping orphans: an individual rule that
    /// could not be removed, or -- see [`sweep`]'s doc comment -- a failure
    /// of [`FirewallBackend::owned_rules`] itself. Never fatal to the sweep:
    /// one stuck rule, or a backend that cannot currently enumerate its own
    /// rules, must not stop the rest of the cleanup, and must not cost the
    /// safe direction its write (see [`sweep`]'s ordering).
    pub failures: Vec<Error>,
}

/// Bring `store` back into agreement with what `backend` actually holds.
///
/// 1. `backend.list_rules()`, once.
/// 2. Every state entry whose handle is not in that list is stale -- the
///    firewall no longer has it -- so it is dropped from `store` and
///    recorded in [`Report::dropped_from_state`]. Safe on every backend and
///    under every [`SweepMode`]: it never touches the firewall, only
///    porthole's own bookkeeping.
/// 3. Under [`SweepMode::Apply { dry_run: false }`], if step 2 removed
///    anything, `store` is saved **now** -- before the orphan direction is
///    even consulted. The state-firewall direction is safe on every backend;
///    making its persistence contingent on the firewall-state direction
///    succeeding would let an unrelated failure (nftables' ambiguous-chain
///    refusal, say) throw away drops already known to be correct.
/// 4. Under [`SweepMode::Apply`] only: `backend.owned_rules()`. `None` means
///    this backend cannot prove which rules are its own -- see the module
///    docs -- so the orphan direction is skipped and
///    [`Report::skipped_orphan_sweep`] says why. `Some(owned)` closes every
///    owned handle that no state entry claims, recording each success in
///    [`Report::removed_orphans`] and each failure in [`Report::failures`]
///    without letting one stop the rest. An `Err` from `owned_rules` itself
///    is folded into [`Report::failures`] rather than aborting the sweep --
///    step 3 already ran, so this failure costs nothing that was already
///    safe. [`SweepMode::ReadOnly`] never reaches this step at all.
///
/// A failure to list rules (step 1) or to save the reduced state (step 3)
/// still returns `Err` rather than being absorbed into the report: nothing
/// downstream of either can be trusted once it fails. That is deliberate,
/// and it is not this function's job to decide whether its caller can
/// tolerate it -- `Engine`'s own callers make that decision by logging and
/// continuing: the user asked to open a port, not to tidy up, and refusing
/// their request because an unrelated stale rule would not delete is a worse
/// outcome than a rule left behind.
pub fn sweep(
    backend: &dyn FirewallBackend,
    store: &mut StateStore,
    mode: SweepMode,
) -> Result<Report> {
    let mut report = Report {
        dropped_from_state: Vec::new(),
        removed_orphans: Vec::new(),
        skipped_orphan_sweep: None,
        failures: Vec::new(),
    };

    // state -> firewall: drop anything the firewall no longer has. Safe
    // under every mode -- it only ever shrinks porthole's own bookkeeping.
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

    // Persist the safe direction before ever consulting the unsafe one --
    // see the doc comment above. Under ReadOnly this never runs at all: a
    // read path must not write, full stop, not even the safe half.
    if matches!(mode, SweepMode::Apply { dry_run: false }) && !report.dropped_from_state.is_empty()
    {
        store.save()?;
    }

    // firewall -> state: remove what porthole can prove is its own and state
    // no longer claims. Only attempted under Apply: this is the direction
    // that mutates the firewall, and a read path must never reach it, no
    // matter who is authorised to call it.
    if matches!(mode, SweepMode::Apply { .. }) {
        match backend.owned_rules() {
            Ok(None) => {
                report.skipped_orphan_sweep = Some(backend.ownership());
            }
            Ok(Some(owned)) => {
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
            Err(e) => {
                // The safe direction's write already happened above, so this
                // costs nothing that was already known to be correct.
                report.failures.push(e);
            }
        }
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

    const APPLY: SweepMode = SweepMode::Apply { dry_run: false };

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

    /// A state store backed by a real, throwaway file, plus the guard that
    /// keeps the directory alive. Saved once up front so a real file exists
    /// on disk before a test ever calls `sweep`, matching how a store this
    /// old is actually found in production. Returning the `TempDir` rather
    /// than leaking it (a prior version of this helper called
    /// `std::mem::forget` on it) keeps this suite from scattering throwaway
    /// directories into `/tmp` on every run.
    fn store_with(rules: Vec<ManagedRule>) -> (TempDir, StateStore) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let mut store = StateStore::open(&path).unwrap();
        for rule in rules {
            store.insert(rule);
        }
        store.save().unwrap();
        (dir, store)
    }

    #[test]
    fn a_rule_the_firewall_no_longer_has_is_dropped_from_state() {
        // What a `firewall-cmd --reload` looks like from porthole's side.
        let backend = FakeBackend::new();
        let (_dir, mut store) = store_with(vec![managed("a", 5173), managed("b", 6000)]);
        // The backend knows about neither: the reload wiped them.
        let report = sweep(&backend, &mut store, APPLY).unwrap();
        assert_eq!(report.dropped_from_state.len(), 2);
        assert!(store.rules().is_empty());
    }

    #[test]
    fn a_marked_rule_state_does_not_know_about_is_removed() {
        let backend = FakeBackend::new();
        backend.open(&request(5173), "porthole:orphan").unwrap();
        let (_dir, mut store) = store_with(vec![]);
        let report = sweep(&backend, &mut store, APPLY).unwrap();
        assert_eq!(report.removed_orphans.len(), 1);
        assert!(backend.handles().is_empty(), "the orphan is gone");
    }

    #[test]
    fn on_firewalld_no_rule_is_ever_removed_from_the_firewall() {
        // The test that would have caught the bug. A firewalld zone holding a
        // rich rule the user wrote by hand must come through a sweep
        // untouched: porthole cannot prove the rule is not its own, so it
        // must not act. Porthole's own still-live rule (PORTHOLE_RULE) is
        // seeded into state alongside it, so this test exercises both
        // directions in one pass: the state->firewall direction must leave
        // it alone (it is not stale), and the firewall->state direction must
        // never touch the user's rule beside it.
        const USER_RULE: &str = r#"rule family="ipv4" source address="192.168.0.0/16" port port="22" protocol="tcp" accept"#;
        const PORTHOLE_RULE: &str = r#"rule family="ipv4" source address="10.10.10.0/24" port port="5173" protocol="tcp" accept"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(&format!("{PORTHOLE_RULE}\n{USER_RULE}")),
        ]);
        let backend = firewalld::Firewalld::new(&runner);
        let (_dir, mut store) = store_with(vec![managed_with_handle(
            "a",
            5173,
            RuleHandle::Firewalld {
                zone: ZONE.to_string(),
                rich_rule: PORTHOLE_RULE.to_string(),
            },
        )]);

        let report = sweep(&backend, &mut store, APPLY).unwrap();

        assert!(
            report.dropped_from_state.is_empty(),
            "porthole's own still-present rule must not be dropped as stale"
        );
        assert!(report.removed_orphans.is_empty());
        assert_eq!(
            report.skipped_orphan_sweep,
            Some(Ownership::Unprovable),
            "the report must say the sweep was skipped, not imply it found nothing"
        );
        assert_eq!(
            store.rules().len(),
            1,
            "porthole's own entry survives untouched"
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
        let (_dir, mut store) = store_with(vec![managed_with_handle("a", 5173, handle)]);
        let report = sweep(&backend, &mut store, APPLY).unwrap();
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
        let (_dir, mut store) = store_with(vec![]);
        let report = sweep(&backend, &mut store, APPLY).unwrap();
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
        let (_dir, mut store) = store_with(vec![managed_with_handle("a", 5173, handle)]);
        let before = store.saved_generation();
        sweep(&backend, &mut store, APPLY).unwrap();
        assert_eq!(
            store.saved_generation(),
            before,
            "nothing changed, nothing written"
        );
    }

    #[test]
    fn the_safe_directions_write_survives_an_owned_rules_failure() {
        // I1: an ambiguous nftables chain count (or any other reason
        // `owned_rules` might fail) must not cost porthole the drops the
        // state->firewall direction already knows are correct. Modelled here
        // with FakeBackend's own failure injection rather than a real
        // nftables ambiguity, since the point is `sweep`'s ordering, not
        // nftables' refusal (which has its own tests).
        let backend = FakeBackend::new();
        backend.fail_owned_rules();
        let (_dir, mut store) = store_with(vec![managed("stale", 5173)]);
        let before = store.saved_generation();

        let report = sweep(&backend, &mut store, APPLY).unwrap();

        assert_eq!(
            report.dropped_from_state.len(),
            1,
            "the safe direction must still run and be reported"
        );
        assert_eq!(
            report.failures.len(),
            1,
            "owned_rules's own failure must be visible, not silently swallowed"
        );
        assert!(
            store.rules().is_empty(),
            "the drop must be applied in memory regardless"
        );
        assert_eq!(
            store.saved_generation(),
            before + 1,
            "and persisted to disk, not thrown away because owned_rules failed"
        );
    }

    #[test]
    fn read_only_never_touches_owned_rules_or_the_firewall() {
        // C2: status and Engine::rules must never be able to close a rule,
        // no matter who is authorised to call them. ReadOnly mode is how:
        // it must not even call owned_rules, let alone close.
        let backend = FakeBackend::new();
        let handle = backend.open(&request(5173), "porthole:orphan").unwrap();
        // Nothing in state claims this rule -- under Apply mode this would
        // be removed as an orphan. Under ReadOnly it must survive untouched.
        let (_dir, mut store) = store_with(vec![]);

        let report = sweep(&backend, &mut store, SweepMode::ReadOnly).unwrap();

        assert!(report.removed_orphans.is_empty());
        assert!(report.failures.is_empty());
        assert_eq!(
            backend.handles(),
            vec![handle],
            "a read-only sweep must never close a rule the firewall holds"
        );
    }

    #[test]
    fn read_only_still_reflects_a_stale_entry_in_memory_but_never_saves() {
        // status must not claim a port is open that the firewall already
        // dropped, so the safe direction still has to run under ReadOnly --
        // it just must never reach disk on this path.
        let backend = FakeBackend::new();
        let (_dir, mut store) = store_with(vec![managed("stale", 5173)]);
        let before = store.saved_generation();

        let report = sweep(&backend, &mut store, SweepMode::ReadOnly).unwrap();

        assert_eq!(report.dropped_from_state.len(), 1);
        assert!(
            store.rules().is_empty(),
            "the in-memory view must reflect the drift for an accurate answer"
        );
        assert_eq!(
            store.saved_generation(),
            before,
            "a read path must never write the state file"
        );
    }
}
