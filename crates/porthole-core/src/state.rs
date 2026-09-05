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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
        let state = match fs::read_to_string(&path) {
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
                parsed
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => {
                return Err(Error::State {
                    path: path.display().to_string(),
                    detail: e.to_string(),
                })
            }
        };
        Ok(StateStore { path, state })
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
        Ok(())
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
}
