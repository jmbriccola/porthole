//! Core errors as distinct D-Bus error names.
//!
//! A client maps the name back to the same exit code the CLI uses locally, so
//! `porthole open` exits 5 for "already open" whether it did the work itself
//! or asked the helper to.

use porthole_core::error::Error;

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "com.jacopobriccola.Porthole")]
pub enum HelperError {
    InvalidArgument(String),
    BackendUnavailable(String),
    NotAuthorized(String),
    AlreadyOpen(String),
    DeviceUnreachable(String),
    RuleNotFound(String),
    NoNetwork(String),
    /// A `firewall-cmd` (or other backend command) invocation that ran but
    /// exited non-zero. Its own D-Bus name, so the client's `kind` slug stays
    /// `command_failed` over the bus exactly as it is locally, rather than
    /// falling into the `Failed` catch-all below and reporting `"unexpected"`.
    CommandFailed(String),
    /// The state file could not be read or written. Same reasoning as
    /// `CommandFailed`: its own name keeps the `state_error` kind slug intact
    /// across the bus.
    State(String),
    // The refusals `forward` has of its own, each under a name of its own
    // for the reason `CommandFailed` and `State` have theirs: the client maps
    // the name back to the code and the kind slug the same failure carries
    // locally. Both ends are checked --
    // `every_forward_refusal_crosses_under_a_name_of_its_own` below for the
    // names sent, and `porthole-cli`'s own
    // `every_refusal_a_forward_has_survives_the_bus_with_its_own_code_and_kind`
    // for what they map back to.
    /// The detected firewall cannot redirect a port at all.
    ForwardUnsupported(String),
    /// No container publishes the port `forward` was given, and something is
    /// listening on it — or porthole could not find out whether anything is.
    /// Shares a code with `NothingListening` and `DockerUnreadable` below and
    /// differs from both by kind, exactly as the three local variants do.
    NotPublishedByContainer(String),
    /// No container publishes the port `forward` was given, and nothing on
    /// the machine is listening on it either. The narrower half of the pair
    /// above: a mistyped port or an unstarted service, rather than something
    /// that is there and cannot be redirected to.
    NothingListening(String),
    /// Docker's table could not be read, so whether the port is published is
    /// unknown. The third of the set above, and the one that is the absence
    /// of an answer rather than an answer.
    DockerUnreadable(String),
    /// The port a forward would give the local network is already carrying
    /// something a redirect would take traffic from.
    ExternalPortInUse(String),
    /// A check `forward` makes before creating a redirect has no answer for
    /// what was asked.
    ForwardCheckUnavailable(String),
    /// The container is already reachable from the network because Docker
    /// published it there. Not `AlreadyOpen`: there is no porthole rule to
    /// close.
    AlreadyReachable(String),
    /// This helper had already decided to retire when the request arrived, so
    /// it did not act on it -- see [`crate::retire`]. **The one refusal here
    /// that is not about the request at all**, and the one a client should
    /// answer by asking again rather than by telling anybody anything: the
    /// CLI, the agent and the GUI all retry once on this name, through
    /// `porthole_core::ipc::once_more_if_worth_asking_again`, and the retry
    /// is served by the fresh instance the bus activates.
    ///
    /// The message still names the remedy in words, because a client without
    /// that retry -- an older `porthole`, or a script driving the bus
    /// directly -- shows it to a person verbatim.
    ///
    /// It has no counterpart in [`Error`], because nothing in
    /// `porthole-core` can be retiring; it is constructed by the admission
    /// check and nowhere else.
    Retiring(String),
    /// Everything else: a command that could not even be spawned, a raw I/O
    /// error, or a truly unexpected condition. These have no request-specific
    /// meaning worth distinguishing on the wire, so the client reports them
    /// all as `"unexpected"` -- unlike `CommandFailed` and `State` above,
    /// which are common enough in practice (a stale rich rule, a full disk)
    /// that `docs/json-schema.md`'s promise of an identical `kind` locally
    /// and over the bus has to hold for them too.
    Failed(String),
}

/// Every core error, named one at a time.
///
/// **No wildcard arm, deliberately.** The refusals `forward` has of its
/// own were all added to [`Error`] with a code and a kind slug of their own,
/// and every one of them arrived at a client as exit 1 and the kind
/// `unexpected`, because a `_ => Failed` arm absorbed them silently. With
/// the wildcard gone, the next variant [`Error`] gains stops this file from
/// compiling until somebody decides which name it crosses the bus under --
/// which is the only way an omission of that shape becomes visible at all,
/// since nothing about the old arm was wrong to read.
///
/// Variants that map to [`HelperError::Failed`] are listed rather than
/// collapsed for the same reason: each is a decision, and a decision is what
/// a reader should be able to see.
impl From<Error> for HelperError {
    fn from(e: Error) -> Self {
        let text = e.to_string();
        match e {
            Error::InvalidArgument(_) => HelperError::InvalidArgument(text),
            Error::BackendUnavailable(_) => HelperError::BackendUnavailable(text),
            Error::NotAuthorized(_) => HelperError::NotAuthorized(text),
            Error::AlreadyOpen { .. } => HelperError::AlreadyOpen(text),
            Error::DeviceUnreachable(_) => HelperError::DeviceUnreachable(text),
            Error::RuleNotFound(_) => HelperError::RuleNotFound(text),
            Error::NoNetwork(_) => HelperError::NoNetwork(text),
            Error::CommandFailed { .. } => HelperError::CommandFailed(text),
            Error::State { .. } => HelperError::State(text),
            Error::ForwardUnsupported(_) => HelperError::ForwardUnsupported(text),
            Error::NotPublishedByContainer(_) => HelperError::NotPublishedByContainer(text),
            Error::NothingListening(_) => HelperError::NothingListening(text),
            Error::DockerUnreadable(_) => HelperError::DockerUnreadable(text),
            Error::ExternalPortInUse { .. } => HelperError::ExternalPortInUse(text),
            Error::ForwardCheckUnavailable(_) => HelperError::ForwardCheckUnavailable(text),
            Error::AlreadyReachable(_) => HelperError::AlreadyReachable(text),
            // `NothingToOffer` is `porthole devices add`'s, and that command
            // is unprivileged and local; nothing here constructs one. It is
            // named anyway because this match has no wildcard to fall into.
            Error::NothingToOffer(_)
            | Error::CommandSpawn { .. }
            | Error::Unexpected(_)
            | Error::Io(_)
            // Already rendered by some other helper, with its own kind and
            // code. Nothing in this process builds one.
            | Error::Remote { .. }
            // A client that could not read what this helper sent. It is a
            // fact about the pair rather than about anything the helper
            // decided, and the helper is the half that cannot observe it:
            // nothing here builds one, and one arriving here would mean a
            // client's error had been handed to the server.
            | Error::VersionMismatch(_) => HelperError::Failed(text),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_failure_keeps_its_own_wire_name_rather_than_the_catch_all() {
        let err = Error::CommandFailed {
            command: "firewall-cmd --zone=x".to_string(),
            status: 1,
            stderr: "boom".to_string(),
        };
        assert!(matches!(
            HelperError::from(err),
            HelperError::CommandFailed(_)
        ));
    }

    #[test]
    fn a_state_failure_keeps_its_own_wire_name_rather_than_the_catch_all() {
        let err = Error::State {
            path: "/run/porthole/state.json".to_string(),
            detail: "boom".to_string(),
        };
        assert!(matches!(HelperError::from(err), HelperError::State(_)));
    }

    /// The wire name every forward refusal now travels under.
    ///
    /// The names, not just the variants: `porthole-cli`'s `from_dbus` reads
    /// the last dotted segment of the name and nothing else, so a variant
    /// renamed here silently stops being recognised there. These strings are
    /// the contract between the two files.
    #[test]
    fn every_forward_refusal_crosses_under_a_name_of_its_own() {
        use zbus::DBusError as _;

        let cases: Vec<(Error, &str)> = vec![
            (
                Error::ForwardUnsupported("x".into()),
                "com.jacopobriccola.Porthole.ForwardUnsupported",
            ),
            (
                Error::NotPublishedByContainer("x".into()),
                "com.jacopobriccola.Porthole.NotPublishedByContainer",
            ),
            (
                Error::NothingListening("x".into()),
                "com.jacopobriccola.Porthole.NothingListening",
            ),
            (
                Error::DockerUnreadable("x".into()),
                "com.jacopobriccola.Porthole.DockerUnreadable",
            ),
            (
                Error::ExternalPortInUse {
                    port: 8443,
                    detail: "x".into(),
                },
                "com.jacopobriccola.Porthole.ExternalPortInUse",
            ),
            (
                Error::ForwardCheckUnavailable("x".into()),
                "com.jacopobriccola.Porthole.ForwardCheckUnavailable",
            ),
            (
                Error::AlreadyReachable("x".into()),
                "com.jacopobriccola.Porthole.AlreadyReachable",
            ),
        ];
        for (core, expected) in cases {
            let wire = HelperError::from(core);
            assert_eq!(
                wire.name().as_str(),
                expected,
                "a forward refusal must not travel as anything else"
            );
        }
    }

    #[test]
    fn a_retiring_helper_refuses_under_a_name_of_its_own() {
        use zbus::DBusError as _;

        // The name, not the variant: `porthole-cli` reads the last dotted
        // segment and retries on it, so a rename here silently turns the one
        // refusal a client is supposed to answer by asking again into one it
        // reports to a person.
        assert_eq!(
            HelperError::Retiring("x".into()).name().as_str(),
            porthole_core::ipc::RETIRING_ERROR,
            "the name zbus derives from this variant and the one \
             `porthole_core::ipc::worth_asking_again` matches on are two \
             spellings of one wire fact, and nothing makes a rename of \
             either fail to compile"
        );
    }

    #[test]
    fn everything_else_still_collapses_to_the_catch_all() {
        assert!(matches!(
            HelperError::from(Error::Unexpected("x".to_string())),
            HelperError::Failed(_)
        ));
        assert!(matches!(
            HelperError::from(Error::Io(std::io::Error::other("x"))),
            HelperError::Failed(_)
        ));
    }
}
