//! The domain model.
//!
//! The distinction between [`ScopeSpec`] and [`Target`] is deliberate and is a
//! security boundary: `ScopeSpec` is what the user asked for and may need
//! resolving (the current subnet, a saved device); `Target` is what is actually
//! handed to a firewall backend and is always an already-resolved IPv4 network.
//! The privileged side only ever sees a `Target`.

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Duration used when the user gives no `--for`.
pub const DEFAULT_DURATION: Duration = Duration::from_secs(60 * 60);

/// Hard ceiling on any timed opening. Beyond this only `--until-reboot` exists.
///
/// This is not a configuration detail: a low ceiling is what makes porthole's
/// promise true. Without it the tool could be used to open ports permanently
/// while pretending to be temporary.
pub const MAX_DURATION: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => f.write_str("tcp"),
            Protocol::Udp => f.write_str("udp"),
        }
    }
}

/// What the user asked to open towards, before resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSpec {
    /// The subnet of the interface carrying the default route. The default.
    CurrentSubnet,
    /// Everyone the interface can reach. Requires the stronger authorisation.
    Anywhere,
    /// An explicit network, e.g. `10.10.10.0/24`.
    Network(Ipv4Net),
    /// A single host, e.g. `10.10.10.42`. Becomes a `/32`.
    Host(Ipv4Addr),
}

/// A resolved target: exactly what a backend turns into a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Network { cidr: Ipv4Net },
    Anywhere,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Network { cidr } => write!(f, "{cidr}"),
            Target::Anywhere => f.write_str("anywhere"),
        }
    }
}

/// How long an opening lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// A bounded duration, always `<= MAX_DURATION`.
    For(Duration),
    /// Until the machine reboots. No timer is scheduled: the rule is runtime
    /// only, so a reboot removes it by itself.
    UntilReboot,
}

/// A fully validated, fully resolved request. This is the only shape the
/// privileged side accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    pub port: u16,
    pub protocol: Protocol,
    pub target: Target,
    pub lifetime: Lifetime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_displays_and_serialises_lowercase() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
        assert_eq!(serde_json::to_string(&Protocol::Tcp).unwrap(), "\"tcp\"");
    }

    #[test]
    fn target_serialises_with_a_kind_tag() {
        let net = Target::Network {
            cidr: "10.10.10.0/24".parse().unwrap(),
        };
        assert_eq!(
            serde_json::to_string(&net).unwrap(),
            r#"{"kind":"network","cidr":"10.10.10.0/24"}"#
        );
        assert_eq!(
            serde_json::to_string(&Target::Anywhere).unwrap(),
            r#"{"kind":"anywhere"}"#
        );
    }

    #[test]
    fn target_round_trips_through_json() {
        let original = Target::Network {
            cidr: "192.168.177.0/24".parse().unwrap(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: Target = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn target_displays_readably() {
        let net = Target::Network {
            cidr: "10.10.10.0/24".parse().unwrap(),
        };
        assert_eq!(net.to_string(), "10.10.10.0/24");
        assert_eq!(Target::Anywhere.to_string(), "anywhere");
    }

    #[test]
    fn duration_bounds_match_the_spec() {
        assert_eq!(DEFAULT_DURATION.as_secs(), 3600);
        assert_eq!(MAX_DURATION.as_secs(), 8 * 3600);
    }
}
