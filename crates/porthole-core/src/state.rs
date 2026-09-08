//! What porthole has open right now.
//!
//! The file lives on tmpfs, so it disappears on reboot — deliberately, because
//! the runtime firewall rules disappear then too. If the state outlived the
//! rules it would describe a firewall that no longer exists.
//!
//! Each record carries the exact handle needed to remove its rule, so closing
//! never depends on being able to reconstruct the rule from its parameters.

use crate::backend::{BackendId, RuleHandle};
use crate::error::{Error, Result};
use crate::model::{Protocol, Target};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const STATE_DIR: &str = "/run/porthole";
pub const STATE_FILE: &str = "/run/porthole/state.json";

/// Bump this when the on-disk shape changes. An older binary meeting a newer
/// file must refuse rather than misread it.
pub const SCHEMA_VERSION: u32 = 1;

/// Test-only override of the state path. Honoured in debug builds only: a
/// release binary runs privileged and must not take its state location from
/// the environment.
pub const STATE_FILE_ENV: &str = "PORTHOLE_STATE_FILE";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedRule {
    pub id: String,
    pub port: u16,
    pub protocol: Protocol,
    pub target: Target,
    pub backend: BackendId,
    /// Seconds since the Unix epoch.
    pub opened_at: u64,
    /// Seconds since the Unix epoch, or `None` for `--until-reboot`.
    pub expires_at: Option<u64>,
    /// The uid that asked for this. Logged, and shown by `porthole list`.
    pub uid: u32,
    pub handle: RuleHandle,
    /// Present when this rule redirects rather than merely permits. `None`
    /// for every rule `open` creates.
    #[serde(default)]
    pub forward: Option<crate::forward::ForwardTo>,
}

impl ManagedRule {
    /// Seconds until automatic close, saturating at zero. `None` means the rule
    /// has no timer and lives until the machine reboots.
    pub fn expires_in(&self, now: u64) -> Option<u64> {
        self.expires_at.map(|at| at.saturating_sub(now))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub schema_version: u32,
    pub rules: Vec<ManagedRule>,
}

impl Default for State {
    fn default() -> Self {
        State {
            schema_version: SCHEMA_VERSION,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct StateStore {
    path: PathBuf,
    state: State,
    /// Held from before the read until this store is dropped, so the whole
    /// read-modify-write is atomic against other porthole processes. `None`
    /// for a read-only view.
    _lock: Option<File>,
    /// See [`StateStore::saved_generation`]. Interior mutability because
    /// `save` takes `&self`, not `&mut self`.
    #[cfg(test)]
    save_count: std::cell::Cell<u64>,
}

impl StateStore {
    /// Where the state lives. `PORTHOLE_STATE_FILE` overrides it in debug
    /// builds so integration tests do not need root or a real `/run`.
    pub fn default_path() -> PathBuf {
        state_path_from(std::env::var(STATE_FILE_ENV).ok().as_deref())
    }

    /// Load the state, or start empty if the file does not exist yet.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let state = Self::read(&path)?;
        Ok(StateStore {
            path,
            state,
            _lock: None,
            #[cfg(test)]
            save_count: std::cell::Cell::new(0),
        })
    }

    /// A view for anything that will write.
    ///
    /// Takes an advisory lock *before* reading and holds it until the store is
    /// dropped, so a read-modify-write cannot interleave with another
    /// porthole process. This is not theoretical: the expiry timer is a
    /// separate process by design, and without the lock a timer firing during
    /// an `open` silently discards one of the two rules — leaving a port open
    /// in the firewall with nothing recorded that could ever close it.
    pub fn open_exclusive(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            ensure_dir(parent)?;
        }
        let lock = lock_exclusive(&path)?;
        let state = Self::read(&path)?;
        Ok(StateStore {
            path,
            state,
            _lock: Some(lock),
            #[cfg(test)]
            save_count: std::cell::Cell::new(0),
        })
    }

    fn read(path: &Path) -> Result<State> {
        match fs::read_to_string(path) {
            Ok(text) => {
                let parsed: State = serde_json::from_str(&text).map_err(|e| Error::State {
                    path: path.display().to_string(),
                    detail: format!("could not be parsed: {e}"),
                })?;
                if parsed.schema_version != SCHEMA_VERSION {
                    return Err(Error::State {
                        path: path.display().to_string(),
                        detail: format!(
                            "has schema version {} but this porthole understands version {}",
                            parsed.schema_version, SCHEMA_VERSION
                        ),
                    });
                }
                Ok(parsed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(Error::State {
                path: path.display().to_string(),
                detail: e.to_string(),
            }),
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn rules(&self) -> &[ManagedRule] {
        &self.state.rules
    }

    pub fn find_by_id(&self, id: &str) -> Option<&ManagedRule> {
        self.state.rules.iter().find(|r| r.id == id)
    }

    pub fn find_by_port(&self, port: u16, protocol: Protocol) -> Option<&ManagedRule> {
        self.state
            .rules
            .iter()
            .find(|r| r.port == port && r.protocol == protocol)
    }

    pub fn insert(&mut self, rule: ManagedRule) {
        self.state.rules.push(rule);
    }

    pub fn remove(&mut self, id: &str) -> Option<ManagedRule> {
        let index = self.state.rules.iter().position(|r| r.id == id)?;
        Some(self.state.rules.remove(index))
    }

    /// Write atomically: a temporary file in the same directory, then a rename.
    /// A torn state file would leave rules that nothing knows how to close.
    pub fn save(&self) -> Result<()> {
        let parent = self.path.parent().ok_or_else(|| Error::State {
            path: self.path.display().to_string(),
            detail: "has no parent directory".to_string(),
        })?;
        ensure_dir(parent)?;

        let temp = self.path.with_extension("json.tmp");
        let mut text = serde_json::to_string_pretty(&self.state).map_err(|e| Error::State {
            path: self.path.display().to_string(),
            detail: format!("could not be serialised: {e}"),
        })?;
        text.push('\n');

        fs::write(&temp, &text).map_err(|e| Error::State {
            path: temp.display().to_string(),
            detail: e.to_string(),
        })?;
        // World readable so `porthole list` needs no privileges; writable only
        // by the owner, which is root.
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o644)).map_err(|e| {
            Error::State {
                path: temp.display().to_string(),
                detail: e.to_string(),
            }
        })?;
        fs::rename(&temp, &self.path).map_err(|e| Error::State {
            path: self.path.display().to_string(),
            detail: e.to_string(),
        })?;
        #[cfg(test)]
        self.save_count.set(self.save_count.get() + 1);
        Ok(())
    }

    /// How many times [`StateStore::save`] has actually written the file
    /// through this handle.
    ///
    /// A real counter (`save_count`), not the file's mtime: mtime resolution
    /// is not guaranteed finer than a second on every filesystem this could
    /// run on, so two saves landing in the same tick would compare equal and
    /// falsely read as "nothing was written". Test-only: reconciliation's
    /// "nothing changed, nothing written" test is the reason this exists.
    #[cfg(test)]
    pub fn saved_generation(&self) -> u64 {
        self.save_count.get()
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| Error::State {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).map_err(|e| Error::State {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    Ok(())
}

/// How long [`lock_exclusive`] retries before giving up with [`Error::State`].
///
/// Bounded on purpose, not merely as a tuning knob: the D-Bus helper serves
/// every method call from one internal driver thread (zbus runs with default
/// features, so it is not backed by tokio's worker pool), and a blocked
/// `flock` there wedges the whole service -- including the call that would
/// release the lock. An indefinite wait is the failure mode this guards
/// against; the exact bound only needs to comfortably exceed how long this
/// codebase's own critical sections take (a handful of backend commands and
/// a `systemd-run`), which is on the order of tens of milliseconds, not
/// hundreds.
///
/// **Why not the real fix.** The actual hazard is that every handler shares
/// one driver thread at all. The complete fix is enabling zbus's `tokio`
/// feature and running each handler's blocking work inside
/// `tokio::task::spawn_blocking`, so a stalled handler occupies one of
/// tokio's dedicated blocking threads rather than the one thread that also
/// has to keep dispatching every other incoming call. That is a cross-cutting
/// change to the `zbus` dependency shared by all three crates in this
/// workspace (not just the helper) and to `porthole-helper`'s own runtime,
/// with real feature-unification and client-connection risk (does `zbus`'s
/// `tokio` feature coexist with the `async-io` feature `porthole-core`'s own
/// `#[zbus::proxy]` client still pulls in by default? does `porthole-cli`'s
/// `block_on`-over-a-current-thread-runtime pattern still connect once
/// zbus's I/O type changes?) that this task could not retire without
/// actually running it end to end -- work belonging to its own reviewed
/// change, not a side effect of adding reconciliation.
///
/// This bound is accepted as a genuine fix for the specific hazard, not a
/// half-measure that merely shortens it: when the lock's holder is the very
/// thread that is stuck waiting for it, nothing will ever release it, so an
/// infinite wedge is exactly what a blocking `flock` would produce here, and
/// turning that into a bounded, terminating, recoverable error removes the
/// hazard rather than delaying it.
const LOCK_TIMEOUT: Duration = Duration::from_millis(500);
/// How often [`lock_exclusive`] retries within [`LOCK_TIMEOUT`].
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Take an exclusive advisory lock on a sidecar file next to the state.
///
/// A sidecar rather than the state file itself, because `save` replaces the
/// state file by rename — a lock held on the old inode would protect nothing.
///
/// Non-blocking and bounded, not a single blocking `flock(LOCK_EX)`: see
/// [`LOCK_TIMEOUT`]. Contention is rare enough in practice — today's only
/// other taker is the expiry timer's own `close`, arriving as a fresh D-Bus
/// call into the same already-serialised helper — that this is expected to
/// never actually retry; it exists so a helper that somehow does meet
/// contention degrades to "try again" instead of hanging.
///
/// Reconciliation's own sweep never calls this directly. Its only write --
/// `reconcile::SweepMode::Apply`'s save, itself gated on the caller not being
/// a dry run -- always runs inside a lock a caller already holds: every
/// production path that can reach a real (non-dry-run) `Apply` sweep does so
/// from behind the helper's own `open_exclusive`, because the CLI's own
/// non-dry-run `open`/`close` never construct a local `Engine` at all -- they
/// go over the bus. `reconcile::SweepMode::ReadOnly` (`status`,
/// `Engine::rules`) never saves at all, lock or no lock. See `reconcile.rs`.
fn lock_exclusive(path: &Path) -> Result<File> {
    let lock_path = path.with_extension("lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| Error::State {
            path: lock_path.display().to_string(),
            detail: e.to_string(),
        })?;

    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        // SAFETY: flock takes a valid file descriptor and a flag constant. It
        // cannot touch memory, and the descriptor is owned by `file` above.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::WouldBlock {
            return Err(Error::State {
                path: lock_path.display().to_string(),
                detail: err.to_string(),
            });
        }
        if Instant::now() >= deadline {
            return Err(Error::State {
                path: lock_path.display().to_string(),
                detail: "is held by another porthole process; try again".to_string(),
            });
        }
        std::thread::sleep(LOCK_POLL_INTERVAL);
    }
}

/// The state path implied by a given `PORTHOLE_STATE_FILE` value.
///
/// Split out from [`StateStore::default_path`] so the decision can be tested
/// without mutating process-global environment state, which is racy under a
/// parallel test runner. The override is honoured only in debug builds: a
/// release binary runs privileged and must never take its state location from
/// the environment.
fn state_path_from(override_value: Option<&str>) -> PathBuf {
    if cfg!(debug_assertions) {
        if let Some(path) = override_value {
            if !path.is_empty() {
                return PathBuf::from(path);
            }
        }
    }
    PathBuf::from(STATE_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn rule(id: &str, port: u16) -> ManagedRule {
        ManagedRule {
            id: id.to_string(),
            port,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            backend: BackendId::Firewalld,
            opened_at: 1_757_000_000,
            expires_at: Some(1_757_003_600),
            uid: 1000,
            handle: RuleHandle::Firewalld {
                zone: "FedoraWorkstation".into(),
                rich_rule: format!(
                    r#"rule family="ipv4" port port="{port}" protocol="tcp" accept"#
                ),
            },
            forward: None,
        }
    }

    #[test]
    fn a_missing_state_file_reads_as_empty() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        assert!(store.rules().is_empty());
    }

    #[test]
    fn rules_round_trip_through_the_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");

        let mut store = StateStore::open(&path).unwrap();
        store.insert(rule("abc", 5173));
        store.insert(rule("def", 5432));
        store.save().unwrap();

        let reopened = StateStore::open(&path).unwrap();
        assert_eq!(reopened.rules().len(), 2);
        assert_eq!(reopened.find_by_id("abc").unwrap().port, 5173);
    }

    #[test]
    fn the_file_is_written_atomically_and_leaves_no_temporary() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let mut store = StateStore::open(&path).unwrap();
        store.insert(rule("abc", 5173));
        store.save().unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("state.json")]);
    }

    #[test]
    fn the_file_is_world_readable_and_root_writable() {
        // `porthole list` must work without privileges; writing must not.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let mut store = StateStore::open(&path).unwrap();
        store.insert(rule("abc", 5173));
        store.save().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "got {mode:o}");
    }

    #[test]
    fn save_creates_a_missing_parent_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("porthole").join("state.json");
        let mut store = StateStore::open(&path).unwrap();
        store.insert(rule("abc", 5173));
        store.save().unwrap();

        let mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "got {mode:o}");
    }

    #[test]
    fn an_unknown_schema_version_is_refused_rather_than_guessed_at() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, r#"{"schema_version":99,"rules":[]}"#).unwrap();

        let err = StateStore::open(&path).unwrap_err();
        assert!(err.to_string().contains("99"), "got: {err}");
    }

    #[test]
    fn corrupt_json_names_the_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, "{not json").unwrap();

        let err = StateStore::open(&path).unwrap_err();
        assert!(err.to_string().contains("state.json"), "got: {err}");
    }

    #[test]
    fn finds_and_removes_by_port_and_by_id() {
        let dir = TempDir::new().unwrap();
        let mut store = StateStore::open(dir.path().join("state.json")).unwrap();
        store.insert(rule("abc", 5173));

        assert!(store.find_by_port(5173, Protocol::Tcp).is_some());
        assert!(store.find_by_port(5173, Protocol::Udp).is_none());
        assert!(store.find_by_port(5174, Protocol::Tcp).is_none());

        assert_eq!(store.remove("abc").unwrap().port, 5173);
        assert!(store.remove("abc").is_none());
        assert!(store.rules().is_empty());
    }

    #[test]
    fn expires_in_counts_down_and_stops_at_zero() {
        let r = rule("abc", 5173); // expires at 1_757_003_600
        assert_eq!(r.expires_in(1_757_000_000), Some(3600));
        assert_eq!(r.expires_in(1_757_003_599), Some(1));
        assert_eq!(r.expires_in(1_757_003_600), Some(0));
        assert_eq!(r.expires_in(1_757_999_999), Some(0));

        let forever = ManagedRule {
            expires_at: None,
            ..rule("def", 5174)
        };
        assert_eq!(forever.expires_in(1_757_000_000), None);
    }

    #[test]
    fn an_unset_or_empty_override_falls_back_to_the_real_path() {
        assert_eq!(state_path_from(None), PathBuf::from(STATE_FILE));
        assert_eq!(state_path_from(Some("")), PathBuf::from(STATE_FILE));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn the_state_path_override_is_honoured_in_debug_builds() {
        // The end-to-end tests depend on this: without it they would need root
        // and a real /run to exercise the CLI at all.
        assert_eq!(
            state_path_from(Some("/tmp/porthole-test/state.json")),
            PathBuf::from("/tmp/porthole-test/state.json")
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn the_state_path_override_is_ignored_in_release_builds() {
        // A release binary runs privileged. It must never take its state
        // location from the environment, so `cargo test --release` proves the
        // guard from the other side.
        assert_eq!(
            state_path_from(Some("/tmp/somewhere-else/state.json")),
            PathBuf::from(STATE_FILE)
        );
    }

    #[test]
    fn a_state_file_written_before_forwards_existed_still_loads() {
        // Shipped state files have no `forward` key. Failing to read one would
        // strand every rule a running helper had open, with nothing able to
        // close them.
        let json = r#"{"schema_version":1,"rules":[{
            "id":"abc","port":5173,"protocol":"tcp",
            "target":{"kind":"network","cidr":"10.10.10.0/24"},
            "backend":"firewalld","opened_at":1757000000,"expires_at":1757003600,
            "uid":1000,
            "handle":{"backend":"firewalld","zone":"FedoraWorkstation","rich_rule":"rule x"}
        }]}"#;
        let parsed: State = serde_json::from_str(json).expect("old state file must load");
        assert_eq!(parsed.rules.len(), 1);
        assert!(parsed.rules[0].forward.is_none());
    }

    #[test]
    fn the_serialised_shape_is_the_documented_one() {
        let mut store = StateStore::open("/nonexistent/state.json").unwrap();
        store.insert(rule("abc", 5173));
        let json: serde_json::Value = serde_json::to_value(store.state()).unwrap();

        assert_eq!(json["schema_version"], 1);
        let r = &json["rules"][0];
        assert_eq!(r["id"], "abc");
        assert_eq!(r["port"], 5173);
        assert_eq!(r["protocol"], "tcp");
        assert_eq!(r["target"]["kind"], "network");
        assert_eq!(r["target"]["cidr"], "10.10.10.0/24");
        assert_eq!(r["backend"], "firewalld");
        assert_eq!(r["uid"], 1000);
        assert_eq!(r["handle"]["backend"], "firewalld");
        assert_eq!(r["handle"]["zone"], "FedoraWorkstation");
    }

    #[test]
    fn two_writers_do_not_discard_each_others_rules() {
        // The expiry timer is a separate process by design, so two porthole
        // processes writing at once is not hypothetical. Before the lock, the
        // later save silently dropped the earlier one's rule, leaving a port
        // open in the firewall with nothing recorded that could close it.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");

        let first_path = path.clone();
        let holder = std::thread::spawn(move || {
            let mut first = StateStore::open_exclusive(&first_path).unwrap();
            first.insert(rule("first", 5173));
            std::thread::sleep(std::time::Duration::from_millis(200));
            first.save().unwrap();
            // The lock is released when `first` is dropped here.
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut second = StateStore::open_exclusive(&path).unwrap();
        second.insert(rule("second", 5432));
        second.save().unwrap();
        holder.join().unwrap();

        let reloaded = StateStore::open(&path).unwrap();
        assert_eq!(
            reloaded.rules().len(),
            2,
            "neither writer may lose the other's rule"
        );
    }

    #[test]
    fn open_exclusive_gives_up_rather_than_blocking_forever() {
        // The whole reason `lock_exclusive` polls instead of taking a single
        // blocking `flock`: on the D-Bus helper's one driver thread, an
        // indefinite wait there wedges the entire service, including the
        // call that would release the lock. This proves the bound is real,
        // not just documented -- the holder here releases the lock long
        // after the second attempt must already have given up.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");

        let held_path = path.clone();
        let holder = std::thread::spawn(move || {
            let _first = StateStore::open_exclusive(&held_path).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(700));
            // The lock is released when `_first` is dropped here.
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        let started = std::time::Instant::now();
        let err = StateStore::open_exclusive(&path).unwrap_err();

        assert!(
            started.elapsed() < std::time::Duration::from_millis(900),
            "must give up well before the holder releases the lock, got {:?}",
            started.elapsed()
        );
        assert_eq!(
            err.exit_code(),
            crate::error::ExitCode::Failure,
            "got: {err}"
        );
        assert!(
            err.to_string().contains("held by another porthole process"),
            "got: {err}"
        );

        holder.join().unwrap();
    }
}
