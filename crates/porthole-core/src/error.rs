//! Errors and the exit codes they map to.
//!
//! Exit codes are part of porthole's public interface: they are documented in
//! the man page and scripts depend on them. Add new codes at the end; never
//! renumber an existing one.

use crate::model::Protocol;

pub type Result<T> = std::result::Result<T, Error>;

/// Process exit codes. Documented in the README and the man page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// The operation completed.
    Success = 0,
    /// Something went wrong that has no more specific code.
    Failure = 1,
    /// The command line was malformed. Also clap's own parse-failure code.
    InvalidArguments = 2,
    /// No supported firewall is installed, or the installed one is not running.
    BackendUnavailable = 3,
    /// The caller is not allowed to perform the operation.
    NotAuthorized = 4,
    /// The requested port is already open.
    AlreadyOpen = 5,
    /// A saved device could not be resolved to an address on this network.
    DeviceUnreachable = 6,
    /// No porthole-managed rule matches the given port or id.
    RuleNotFound = 7,
    /// There is no usable network interface to open towards.
    NoNetwork = 8,
    /// A command that offers a choice had nothing to offer.
    NothingToOffer = 9,
    /// The port named is not published by a container, or Docker could not be
    /// read at all. One code for two facts: the exit status does not say
    /// which, and [`Error::kind`] and the variant are what do.
    NotForwardable = 10,
    /// The external port a forward would use is already carrying something a
    /// redirect would take traffic from.
    ExternalPortInUse = 11,
    /// The detected backend has no way to redirect a port.
    ForwardUnsupported = 12,
    /// A check porthole makes before creating a forward does not cover what
    /// was asked for.
    ForwardCheckUnavailable = 13,
    /// Docker publishes the container on an address other than loopback, so
    /// the local network may already reach the port a forward was asked to
    /// redirect to.
    ///
    /// What is read to decide it is one DNAT rule's own `-d` flag: no `-d` is
    /// every interface, and a `-d` naming an address outside `127.0.0.0/8` is
    /// that one address. Which interface carries that address has not been
    /// looked at.
    ///
    /// Its own code rather than one of 10-13 above, because it is a
    /// different answer from every one of them: [`ExitCode::NotForwardable`]
    /// covers the two shapes of "porthole has no container to redirect to"
    /// (not published, or Docker unreadable) and here the container is
    /// published and Docker was read; [`ExitCode::ForwardUnsupported`] is
    /// about what the firewall can express; and
    /// [`ExitCode::ForwardCheckUnavailable`] is about a check porthole could
    /// not make, where this one is a check that was made and failed. Not
    /// [`ExitCode::AlreadyOpen`] either: that code means porthole has a rule
    /// of its own on the port, which a script may close. Nothing porthole can
    /// close is involved here.
    AlreadyReachable = 14,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("{0}")]
    BackendUnavailable(String),

    /// The README's exit-code table says exit 4 means "Polkit refused the
    /// request. Never `sudo`." That sentence is true only because this
    /// variant has exactly one production construction site today —
    /// `polkit.rs`'s `denied()`. Nothing in the type system enforces that; if
    /// a second call site is ever added, either keep the sentence true or go
    /// update the README, because nothing else will notice the two have
    /// drifted apart.
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    #[error("{port}/{protocol} is already open ({detail})")]
    AlreadyOpen {
        port: u16,
        protocol: Protocol,
        detail: String,
    },

    #[error("device not reachable: {0}")]
    DeviceUnreachable(String),

    #[error("no rule matches {0}")]
    RuleNotFound(String),

    #[error("{0}")]
    NoNetwork(String),

    /// A command that offers a choice looked and found nothing to offer:
    /// `porthole devices add` on a machine whose neighbour table is empty.
    ///
    /// Anticipated and refused deliberately, which is why it is not
    /// `Unexpected`. Constructed in one place, `porthole-cli`'s `add_device`;
    /// nothing in `porthole-helper` builds it, so it has no D-Bus error name
    /// of its own and never crosses the bus.
    #[error("{0}")]
    NothingToOffer(String),

    /// The detected backend has no way to redirect a port to a container.
    ///
    /// Constructed in one place, `FirewallBackend::forward`'s trait default,
    /// which every backend that does not implement a forward inherits.
    #[error("{0}")]
    ForwardUnsupported(String),

    /// No container publishes the port a forward was asked for.
    ///
    /// Docker's table was read and the port is not in it. That is an answer.
    /// [`Error::DockerUnreadable`] is the absence of one. The two share an
    /// exit code, so a caller that needs to tell them apart reads
    /// [`Error::kind`] or matches the variant; the message of each says only
    /// what that one knows.
    #[error("{0}")]
    NotPublishedByContainer(String),

    /// Docker's table could not be read, so whether the port is published is
    /// unknown.
    ///
    /// The other half of the pair described on
    /// [`Error::NotPublishedByContainer`].
    #[error("{0}")]
    DockerUnreadable(String),

    /// The external port a forward would use is already carrying something a
    /// redirect would take traffic from.
    ///
    /// Two situations reach this, and `detail` is where they differ: porthole
    /// already has a rule on that port, or a socket bound to an address the
    /// local network reaches is listening on it. A socket bound only to a
    /// loopback address is neither, and does not refuse -- see
    /// [`crate::engine::Engine::forward`].
    #[error("port {port} is already in use ({detail})")]
    ExternalPortInUse { port: u16, detail: String },

    /// A forward was refused because the port it names is already reachable
    /// from the network: Docker's own DNAT rule for it is not restricted to
    /// a loopback address.
    ///
    /// The message is [`crate::docker::already_reachable`]'s, which is
    /// [`crate::docker::advise`]'s own sentence for the same fact, so that
    /// the refusal `forward` returns and the warning `open` prints read as
    /// one voice rather than two.
    #[error("{0}")]
    AlreadyReachable(String),

    /// A forward was refused because one of the checks porthole makes before
    /// creating one has no coverage for what was asked.
    ///
    /// Not [`Error::ForwardUnsupported`], which is about what the firewall
    /// can express. This one is about what porthole can verify, and the
    /// message says which check and what it does not reach.
    #[error("{0}")]
    ForwardCheckUnavailable(String),

    #[error("command `{command}` exited with status {status}: {stderr}")]
    CommandFailed {
        command: String,
        status: i32,
        stderr: String,
    },

    #[error("could not run `{command}`: {source}")]
    CommandSpawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    /// Also what `lock_exclusive` returns when the exclusive state lock could
    /// not be acquired within its bounded wait -- see `state::lock_exclusive`
    /// for why that wait is bounded rather than indefinite in the first
    /// place. Not split into its own variant: nothing today gives a caller
    /// anything useful to do with "the lock was busy" that "a state error
    /// happened" does not already cover, and a dedicated exit code no
    /// invocation could actually produce would be documented for a signal no
    /// one could observe.
    #[error("state file {path}: {detail}")]
    State { path: String, detail: String },

    #[error("{0}")]
    Unexpected(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An error the privileged helper already rendered.
    ///
    /// Carries its own kind slug and exit code so the CLI reports exactly what
    /// the helper said, once. Rebuilding a local variant from a rendered
    /// message doubles every prefixing template — and for `AlreadyOpen`, whose
    /// template names the port, it made the CLI announce a port nobody asked
    /// about.
    #[error("{message}")]
    Remote {
        message: String,
        kind: &'static str,
        code: ExitCode,
    },
}

impl Error {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Error::InvalidArgument(_) => ExitCode::InvalidArguments,
            Error::BackendUnavailable(_) => ExitCode::BackendUnavailable,
            Error::NotAuthorized(_) => ExitCode::NotAuthorized,
            Error::AlreadyOpen { .. } => ExitCode::AlreadyOpen,
            Error::DeviceUnreachable(_) => ExitCode::DeviceUnreachable,
            Error::RuleNotFound(_) => ExitCode::RuleNotFound,
            Error::NoNetwork(_) => ExitCode::NoNetwork,
            Error::NothingToOffer(_) => ExitCode::NothingToOffer,
            Error::ForwardUnsupported(_) => ExitCode::ForwardUnsupported,
            Error::NotPublishedByContainer(_) | Error::DockerUnreadable(_) => {
                ExitCode::NotForwardable
            }
            Error::ExternalPortInUse { .. } => ExitCode::ExternalPortInUse,
            Error::ForwardCheckUnavailable(_) => ExitCode::ForwardCheckUnavailable,
            Error::AlreadyReachable(_) => ExitCode::AlreadyReachable,
            Error::Remote { code, .. } => *code,
            Error::CommandFailed { .. }
            | Error::CommandSpawn { .. }
            | Error::State { .. }
            | Error::Unexpected(_)
            | Error::Io(_) => ExitCode::Failure,
        }
    }

    /// A stable machine-readable slug, emitted in `--json` error output.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "invalid_argument",
            Error::BackendUnavailable(_) => "backend_unavailable",
            Error::NotAuthorized(_) => "not_authorized",
            Error::AlreadyOpen { .. } => "already_open",
            Error::DeviceUnreachable(_) => "device_unreachable",
            Error::RuleNotFound(_) => "rule_not_found",
            Error::NoNetwork(_) => "no_network",
            Error::NothingToOffer(_) => "nothing_to_offer",
            Error::ForwardUnsupported(_) => "forward_unsupported",
            Error::NotPublishedByContainer(_) => "not_published_by_container",
            Error::DockerUnreadable(_) => "docker_unreadable",
            Error::ExternalPortInUse { .. } => "external_port_in_use",
            Error::ForwardCheckUnavailable(_) => "forward_check_unavailable",
            Error::AlreadyReachable(_) => "already_reachable",
            Error::Remote { kind, .. } => kind,
            Error::CommandFailed { .. } => "command_failed",
            Error::CommandSpawn { .. } => "command_spawn_failed",
            Error::State { .. } => "state_error",
            Error::Unexpected(_) => "unexpected",
            Error::Io(_) => "io_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        // These numbers are a public interface. Scripts depend on them.
        assert_eq!(ExitCode::Success as i32, 0);
        assert_eq!(ExitCode::Failure as i32, 1);
        assert_eq!(ExitCode::InvalidArguments as i32, 2);
        assert_eq!(ExitCode::BackendUnavailable as i32, 3);
        assert_eq!(ExitCode::NotAuthorized as i32, 4);
        assert_eq!(ExitCode::AlreadyOpen as i32, 5);
        assert_eq!(ExitCode::DeviceUnreachable as i32, 6);
        assert_eq!(ExitCode::RuleNotFound as i32, 7);
        assert_eq!(ExitCode::NoNetwork as i32, 8);
        assert_eq!(ExitCode::NothingToOffer as i32, 9);
        assert_eq!(ExitCode::NotForwardable as i32, 10);
        assert_eq!(ExitCode::ExternalPortInUse as i32, 11);
        assert_eq!(ExitCode::ForwardUnsupported as i32, 12);
        assert_eq!(ExitCode::ForwardCheckUnavailable as i32, 13);
        assert_eq!(ExitCode::AlreadyReachable as i32, 14);
    }

    /// Every `Name = N,` inside `pub enum ExitCode { ... }`, read out of this
    /// file's own source.
    ///
    /// Rust has no way to enumerate a plain enum's variants, and a hand-kept
    /// list of them is exactly the thing that goes stale while the enum
    /// grows -- this feature added five codes to an enum whose README table
    /// stopped at 9, and an earlier draft of the plan for it said three.
    /// Reading the source is the one way to make the list grow by itself:
    /// adding a variant adds a line here with no second edit to remember.
    ///
    /// `include_str!` rather than a runtime read, so a path that stops
    /// resolving is a compile error rather than a test that quietly finds
    /// nothing.
    fn declared_exit_codes() -> Vec<(String, i32)> {
        let source = include_str!("error.rs");
        let body = source
            .split_once("pub enum ExitCode {")
            .expect("this file declares `pub enum ExitCode`")
            .1
            .split_once("\n}")
            .expect("the enum's body ends at a closing brace in column 0")
            .0;
        let found: Vec<(String, i32)> = body
            .lines()
            .map(str::trim)
            .filter_map(|line| {
                let (name, rest) = line.split_once(" = ")?;
                let value = rest.strip_suffix(',')?.parse().ok()?;
                name.chars()
                    .all(|c| c.is_ascii_alphanumeric())
                    .then(|| (name.to_string(), value))
            })
            .collect();
        // The floor, and it is a ratchet: raise it whenever the enum grows,
        // never lower it. Codes are a public interface and are only ever
        // appended, so the count can only go up -- which means a parse that
        // has stopped matching the source is the *only* thing that can bring
        // it down, and that is exactly what this catches.
        //
        // It was `>= 10` and that was the wrong size: with 15 variants, the
        // five codes this feature added could all have silently stopped being
        // parsed and both guards below would have gone on passing, checking
        // codes 0-9 and calling it a table. A floor whose slack is precisely
        // the subject of the work is not a floor.
        const LOWEST_TOLERABLE: usize = 15;
        assert!(
            found.len() >= LOWEST_TOLERABLE,
            "the enum body was parsed as {} variants, fewer than the {LOWEST_TOLERABLE} \
             it had when this assertion was last raised. Codes are only ever appended, \
             so the enum cannot have shrunk: the parse above has stopped matching the \
             source. Parsed: {found:?}",
            found.len()
        );
        // The other way a parse can go wrong without shrinking: dropping a
        // variant from the middle. Codes run 0..n with none missing and none
        // repeated (`exit_codes_are_stable` pins each individual number), so
        // a gap here is a variant the parse lost.
        let mut values: Vec<i32> = found.iter().map(|(_, v)| *v).collect();
        values.sort_unstable();
        assert_eq!(
            values,
            (0..found.len() as i32).collect::<Vec<_>>(),
            "the parsed codes are not the contiguous run 0..{}, so either the parse \
             dropped a variant from the middle or a code was renumbered -- both of \
             which this file's own header forbids: {found:?}",
            found.len()
        );
        found
    }

    /// The body of README.md's `## Exit codes` section, and nothing else.
    ///
    /// **Scoped to the one section deliberately.** Two guards in this project
    /// were found reading a whole document and being satisfied by a
    /// neighbouring sentence about something else -- a search for "12" over
    /// the whole README finds the eight-hour ceiling, a port number, a
    /// version. Ending at the next `## ` is what makes a hit here mean the
    /// table.
    fn readme_exit_code_section() -> &'static str {
        let readme = include_str!("../../../README.md");
        let after = readme
            .split_once("\n## Exit codes\n")
            .expect("README.md has an `## Exit codes` section")
            .1;
        match after.split_once("\n## ") {
            Some((section, _)) => section,
            None => after,
        }
    }

    #[test]
    fn the_readme_exit_code_table_names_every_variant_of_the_enum() {
        let section = readme_exit_code_section();
        for (name, value) in declared_exit_codes() {
            let row = format!("| {value} |");
            assert!(
                section.contains(&row),
                "README.md's `## Exit codes` table has no row `{row}` for \
                 ExitCode::{name}. Exit codes are a public interface; a code the enum \
                 has and the README does not name is a code nobody can look up."
            );
        }
    }

    #[test]
    fn the_readme_exit_code_table_invents_no_code_the_enum_does_not_have() {
        // The other direction, which the test above cannot see: a row left
        // behind by a variant that was removed or renumbered documents an
        // exit status no invocation can produce.
        let declared: Vec<i32> = declared_exit_codes().into_iter().map(|(_, v)| v).collect();
        for line in readme_exit_code_section().lines() {
            let Some(rest) = line.strip_prefix("| ") else {
                continue;
            };
            let Some((first, _)) = rest.split_once(" |") else {
                continue;
            };
            let Ok(value) = first.parse::<i32>() else {
                continue; // the header row, and its `|---|---|` separator.
            };
            assert!(
                declared.contains(&value),
                "README.md's `## Exit codes` table documents exit {value}, which \
                 `ExitCode` does not have. Codes are never renumbered, so this is a row \
                 left behind rather than one that moved."
            );
        }
    }

    #[test]
    fn each_error_maps_to_its_exit_code() {
        assert_eq!(
            Error::InvalidArgument("bad".into()).exit_code(),
            ExitCode::InvalidArguments
        );
        assert_eq!(
            Error::BackendUnavailable("none".into()).exit_code(),
            ExitCode::BackendUnavailable
        );
        assert_eq!(
            Error::NotAuthorized("root required".into()).exit_code(),
            ExitCode::NotAuthorized
        );
        assert_eq!(
            Error::RuleNotFound("5173/tcp".into()).exit_code(),
            ExitCode::RuleNotFound
        );
        assert_eq!(
            Error::NoNetwork("no default route".into()).exit_code(),
            ExitCode::NoNetwork
        );
        assert_eq!(
            Error::NothingToOffer("nothing seen".into()).exit_code(),
            ExitCode::NothingToOffer
        );
        assert_eq!(
            Error::ForwardUnsupported("ufw cannot".into()).exit_code(),
            ExitCode::ForwardUnsupported
        );
        assert_eq!(
            Error::ExternalPortInUse {
                port: 8443,
                detail: "something is listening on it".into()
            }
            .exit_code(),
            ExitCode::ExternalPortInUse
        );
        assert_eq!(
            Error::ForwardCheckUnavailable("no udp check".into()).exit_code(),
            ExitCode::ForwardCheckUnavailable
        );
        assert_eq!(
            Error::AlreadyReachable("docker published it on 0.0.0.0".into()).exit_code(),
            ExitCode::AlreadyReachable
        );
    }

    #[test]
    fn an_already_reachable_port_is_not_reported_as_an_already_open_one() {
        // Both are "that port is already carrying something", and collapsing
        // them would tell a script there is a porthole rule to close. There
        // is not: what makes the port reachable is Docker's own rule, which
        // porthole cannot remove.
        let reachable = Error::AlreadyReachable("docker published it on 0.0.0.0".into());
        let open = Error::AlreadyOpen {
            port: 3000,
            protocol: Protocol::Tcp,
            detail: "open towards 10.10.10.0/24".into(),
        };
        assert_ne!(reachable.exit_code(), open.exit_code());
        assert_ne!(reachable.kind(), open.kind());
        assert_eq!(reachable.kind(), "already_reachable");
    }

    #[test]
    fn an_unread_docker_and_an_unpublished_port_share_a_code_but_not_a_kind() {
        // One exit status covers both, so a script reading `$?` alone cannot
        // tell "no container publishes that port" from "porthole never found
        // out". `kind` is what carries the difference to a caller, and this
        // is the assertion that keeps the two slugs from collapsing into one.
        let unpublished = Error::NotPublishedByContainer("3000/tcp is not published".into());
        let unreadable = Error::DockerUnreadable("could not read Docker's table".into());

        assert_eq!(unpublished.exit_code(), ExitCode::NotForwardable);
        assert_eq!(unreadable.exit_code(), ExitCode::NotForwardable);
        assert_ne!(unpublished.kind(), unreadable.kind());
        assert_eq!(unpublished.kind(), "not_published_by_container");
        assert_eq!(unreadable.kind(), "docker_unreadable");
    }

    #[test]
    fn error_kind_is_a_stable_machine_readable_slug() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "invalid_argument"
        );
        assert_eq!(Error::NoNetwork("x".into()).kind(), "no_network");
        assert_eq!(Error::NothingToOffer("x".into()).kind(), "nothing_to_offer");
        assert_eq!(
            Error::ForwardUnsupported("x".into()).kind(),
            "forward_unsupported"
        );
        assert_eq!(
            Error::ExternalPortInUse {
                port: 8443,
                detail: "x".into()
            }
            .kind(),
            "external_port_in_use"
        );
        assert_eq!(
            Error::ForwardCheckUnavailable("x".into()).kind(),
            "forward_check_unavailable"
        );
        assert_eq!(
            Error::AlreadyReachable("x".into()).kind(),
            "already_reachable"
        );
    }

    #[test]
    fn a_remote_error_reports_the_helpers_words_once() {
        // The helper sends its message already rendered. Re-wrapping it in a
        // local variant's template doubles the prefix; for AlreadyOpen it also
        // invents a port.
        let e = Error::Remote {
            message: "5173/tcp is already open (open towards 10.10.10.0/24)".to_string(),
            kind: "already_open",
            code: ExitCode::AlreadyOpen,
        };
        assert_eq!(
            e.to_string(),
            "5173/tcp is already open (open towards 10.10.10.0/24)"
        );
        assert_eq!(e.kind(), "already_open");
        assert_eq!(e.exit_code(), ExitCode::AlreadyOpen);
        assert!(!e.to_string().contains("0/tcp"), "no invented port");
    }
}
