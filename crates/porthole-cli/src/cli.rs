//! The command line.
//!
//! Arguments arrive as strings and are validated by `porthole_core::validate`
//! rather than by clap's own parsers, so the CLI and the future D-Bus helper
//! reject the same things with the same words.
//!
//! The clap command itself lives one file over, in `cli_def.rs`, and is
//! re-exported below. `build.rs` `include!`s that same file to render
//! `porthole.1` and the shell completions, so the man page, the completions
//! and `--help` are three renderings of one definition.
//!
//! A module with `#[path]` rather than an `include!` here, even though
//! `build.rs` has to use `include!` (a build script cannot depend on a
//! library target of its own package, and this one is a binary): rustfmt
//! walks `mod` declarations and does not expand macros, so as an `include!`
//! the whole clap definition was reached by no `cargo fmt --all --check`.
//! The `#[path]` is what puts it back inside that gate.

#[path = "cli_def.rs"]
mod cli_def;
pub use cli_def::*;

/// What `--to` named, before a saved device's name (if any) is resolved to
/// an address.
///
/// Kept out of `porthole_core::validate` on purpose: that module's
/// `parse_scope` is also what the privileged helper runs on its own copy of
/// the wire string, and the helper must never gain a reason to know saved
/// devices exist -- see `porthole_core::devices`'s own module doc for why
/// resolution happens client-side, before either the bus or the local engine
/// ever sees the string.
#[derive(Debug)]
pub enum ToSpec {
    Scope(porthole_core::model::ScopeSpec),
    Device(String),
    /// `--to` was rejected, and not as a candidate device name either --
    /// see `parse_to`'s own doc comment.
    Invalid(porthole_core::error::Error),
}

/// Parse `--to`. The ordinary scope grammar (`subnet`, `any`, a CIDR, an IP)
/// takes priority; when that grammar rejects the string, this still checks
/// whether the string looks like it was an attempt at that grammar rather
/// than a name -- containing a `/` or a `:` (a CIDR or an IPv6 address, e.g.
/// `fe80::1`), or being empty -- and keeps `parse_scope`'s own error for
/// that case, since it is far more specific than "no such device" (naming
/// IPv6 explicitly, for instance). Anything else is treated as a candidate
/// saved-device name instead -- `porthole_core::devices::resolve` is what
/// actually decides whether that name exists.
///
/// A name this branch keeps for `parse_scope`, and a name `parse_scope`
/// accepts outright, can never reach a saved device through `--to`. Both are
/// refused when a device is named and when the book is read back, by
/// `porthole_core::devices::validate_device_name` and `Book::load`.
pub fn parse_to(raw: &str) -> ToSpec {
    match porthole_core::validate::parse_scope(raw) {
        Ok(scope) => ToSpec::Scope(scope),
        Err(err) => {
            if raw.is_empty() || raw.contains('/') || raw.contains(':') {
                ToSpec::Invalid(err)
            } else {
                ToSpec::Device(raw.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::model::ScopeSpec;

    /// `--to` has exactly three outcomes and they are decided here, before
    /// `porthole_core::devices` ever sees the string. `devices::resolve` is
    /// well covered; which of the three branches a string lands in was not
    /// covered at all.
    fn spec(raw: &str) -> ToSpec {
        parse_to(raw)
    }

    #[test]
    fn the_scope_grammar_wins_wherever_it_applies() {
        assert!(matches!(
            spec("subnet"),
            ToSpec::Scope(ScopeSpec::CurrentSubnet)
        ));
        assert!(matches!(spec("any"), ToSpec::Scope(ScopeSpec::Anywhere)));
        assert!(matches!(
            spec("10.10.10.0/24"),
            ToSpec::Scope(ScopeSpec::Network(_))
        ));
        assert!(matches!(spec("10.10.10.5"), ToSpec::Scope(_)));
    }

    #[test]
    fn a_failed_attempt_at_the_scope_grammar_keeps_the_scope_error() {
        // These are attempts at a CIDR or an address, not names, and
        // `parse_scope`'s own error is far more specific than "no such
        // device" -- it names IPv6 explicitly, for one.
        for raw in ["", "10.10.10.0/33", "fe80::1", "not/a/network"] {
            assert!(
                matches!(spec(raw), ToSpec::Invalid(_)),
                "`{raw}` must keep the scope error"
            );
        }
    }

    #[test]
    fn the_ipv6_error_survives_rather_than_becoming_no_such_device() {
        // The specific case the `/`-and-`:` branch exists for: telling a
        // user porthole is IPv4-only beats telling them they have no device
        // called `fe80::1`.
        let ToSpec::Invalid(err) = spec("fe80::1") else {
            panic!("an IPv6 address must not be read as a device name");
        };
        assert!(
            err.to_string().to_lowercase().contains("ipv6"),
            "got: {err}"
        );
    }

    #[test]
    fn anything_else_is_a_candidate_device_name() {
        for raw in ["phone", "office pc", "printer-2", "Jacopo's laptop"] {
            let ToSpec::Device(name) = spec(raw) else {
                panic!("`{raw}` should be a candidate device name");
            };
            assert_eq!(name, raw, "the name must be passed through unchanged");
        }
    }

    #[test]
    fn every_name_this_accepts_is_one_a_device_may_be_saved_under() {
        // The two halves have to agree, or a name is saveable and then
        // unreachable -- which is exactly what happened with `office:pc`.
        // `validate_device_name` is the save-time gate; this is the
        // lookup-time one.
        for raw in ["phone", "office pc", "printer-2"] {
            assert!(matches!(spec(raw), ToSpec::Device(_)));
            assert!(porthole_core::devices::validate_device_name(raw).is_ok());
        }
        for raw in ["subnet", "any", "office:pc", "home/laptop", "10.0.0.5"] {
            assert!(
                !matches!(spec(raw), ToSpec::Device(_)),
                "`{raw}` must not reach a device lookup"
            );
            assert!(
                porthole_core::devices::validate_device_name(raw).is_err(),
                "`{raw}` must not be saveable either"
            );
        }
    }
}
