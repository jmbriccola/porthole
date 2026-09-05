//! Which CLI binary the expiry timer will invoke.
//!
//! Shared between the helper binary itself and `porthole doctor`, so doctor's
//! report of what the timer will run can never be a second opinion that
//! disagrees with what the helper actually decides — it calls exactly this.
//!
//! It lives in `porthole-core` rather than in the helper because both sides
//! need it, and the alternative — the unprivileged CLI depending on the
//! privileged helper's crate — would make `porthole` link the helper's polkit
//! and authorization code to answer one diagnostic question. `expiry`, the
//! other consumer of this path, is already here.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Where the helper will look for the CLI it hands to the expiry timer.
///
/// Ordered: a packaged install first, a hand-built one second.
pub const CLI_CANDIDATES: [&str; 2] = ["/usr/bin/porthole", "/usr/local/bin/porthole"];

/// Pick the CLI binary the expiry timer will run.
///
/// When the helper runs as root — the real deployment — `systemd-run` executes
/// this path as root, so it is a root-execution target: it must be a regular
/// file owned by uid 0 and not group- or world-writable, or an attacker who
/// can write it gets root through a mechanism the user never sees.
///
/// When the helper is *not* root, `expiry::schedule_close` asks `systemd-run`
/// for a *user* unit rather than a system one — a non-root process could not
/// create a system unit anyway, since systemd would demand
/// `org.freedesktop.systemd1.manage-units` for that. So the timer runs as that
/// same unprivileged user, and there is nothing for the ownership check above
/// to protect: it does not apply, and the CLI built alongside this helper is a
/// legitimate candidate. This is what lets the end-to-end tests drive a real
/// helper without installing anything, and it is a statement about privilege,
/// not a concession to the tests.
pub fn resolve_cli() -> Result<PathBuf, String> {
    // SAFETY: geteuid takes no arguments, touches no memory and cannot fail.
    let euid = unsafe { libc::geteuid() };
    resolve_cli_for(euid)
}

/// [`resolve_cli`], but taking the euid as a parameter instead of calling
/// `geteuid` itself — the same answer, computed for a caller (real or a test)
/// that already knows or wants to simulate the privilege level in question.
pub fn resolve_cli_for(euid: u32) -> Result<PathBuf, String> {
    // The binary built alongside whichever process is asking. In production
    // this is only ever consulted when unprivileged, which the real
    // `porthole-helper` never is — systemd always starts it as root. It
    // matters for the session-bus helper the end-to-end tests spawn, and for
    // `porthole doctor` simulating that same unprivileged case: both are the
    // same `porthole` binary built by the same `cargo build`/`cargo test`,
    // sitting next to `porthole-helper` in the same output directory.
    let sibling = std::env::current_exe()
        .ok()
        .map(|p| p.with_file_name("porthole"));
    let base: Vec<PathBuf> = CLI_CANDIDATES.iter().map(PathBuf::from).collect();
    resolve_cli_among(euid, &base, sibling.as_deref())
}

/// The testable core: takes the candidate lists explicitly, so both branches
/// of the privilege condition can be exercised with synthetic paths rather
/// than the real `/usr/bin` and `/usr/local/bin`, and without actually being
/// root.
fn resolve_cli_among(
    euid: u32,
    base_candidates: &[PathBuf],
    unprivileged_extra: Option<&Path>,
) -> Result<PathBuf, String> {
    let privileged = euid == 0;

    let mut candidates: Vec<PathBuf> = base_candidates.to_vec();
    if !privileged {
        if let Some(path) = unprivileged_extra {
            candidates.push(path.to_path_buf());
        }
    }

    for path in &candidates {
        // fs::metadata, not symlink_metadata: a symlink whose target passes
        // every check below is fine to run, so it is the target we check.
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }
        if privileged {
            if metadata.uid() != 0 {
                continue;
            }
            // Group- or world-writable (022) bits: writable by anyone but root.
            if metadata.mode() & 0o022 != 0 {
                continue;
            }
        }
        return Ok(path.clone());
    }

    Err(format!(
        "no usable CLI binary found among {candidates:?} — {}. Timed closes \
         cannot run without one.",
        if privileged {
            "each must exist, be a regular file, be owned by root, and not be \
             group- or world-writable"
        } else {
            "each must exist and be a regular file"
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_refuses_a_candidate_not_owned_by_root() {
        // A file this test process owns is never uid 0, so the privileged
        // branch's ownership check must reject it even though it exists and
        // is a plain regular file.
        let file = tempfile::NamedTempFile::new().unwrap();
        let err = resolve_cli_among(0, &[file.path().to_path_buf()], None).unwrap_err();
        assert!(err.contains("owned by root"), "got: {err}");
    }

    #[test]
    fn privileged_ignores_the_unprivileged_only_candidate_even_if_it_exists() {
        // The sibling CLI is only a legitimate candidate when the helper is
        // not root. A privileged resolution must not fall back to it just
        // because the two real candidates are both missing.
        let file = tempfile::NamedTempFile::new().unwrap();
        let err = resolve_cli_among(0, &[], Some(file.path())).unwrap_err();
        assert!(err.contains("no usable CLI binary"), "got: {err}");
    }

    #[test]
    fn unprivileged_accepts_the_sibling_cli_with_no_ownership_check() {
        // Owned by the current, non-root user, and (being a NamedTempFile)
        // not even necessarily executable — none of that matters, because the
        // ownership check the privileged branch enforces does not apply here:
        // the timer would run as this same unprivileged user regardless.
        let file = tempfile::NamedTempFile::new().unwrap();
        let resolved = resolve_cli_among(1000, &[], Some(file.path())).unwrap();
        assert_eq!(resolved, file.path());
    }

    #[test]
    fn unprivileged_with_nothing_usable_still_refuses() {
        let err = resolve_cli_among(1000, &[], None).unwrap_err();
        assert!(err.contains("no usable CLI binary"), "got: {err}");
    }

    #[test]
    fn a_missing_candidate_is_skipped_not_an_error() {
        // /nonexistent does not exist; the real candidate after it must still
        // be picked rather than the whole search failing on the first miss.
        let file = tempfile::NamedTempFile::new().unwrap();
        let resolved = resolve_cli_among(
            1000,
            &[PathBuf::from("/nonexistent/porthole")],
            Some(file.path()),
        )
        .unwrap();
        assert_eq!(resolved, file.path());
    }
}
