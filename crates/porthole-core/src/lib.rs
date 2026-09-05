//! Core library for porthole.
//!
//! porthole opens a port towards the local network temporarily, explicitly and
//! reversibly. This crate holds everything that is not a user interface: the
//! domain model, input validation, the firewall backend abstraction, the
//! runtime state store and the orchestration engine.
//!
//! Two invariants run through the whole crate:
//!
//! 1. No permanent firewall rules are ever written. A reboot closes everything.
//! 2. Every external command goes through [`command::CommandRunner`], which is
//!    what makes dry-run and unit testing possible.

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_builds() {
        assert_eq!(2 + 2, 4);
    }
}
