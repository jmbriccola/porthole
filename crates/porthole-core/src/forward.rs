//! Where a forward sends traffic, and the Docker mapping it was built from.
//!
//! The mapping is stored rather than re-derived because the question asked
//! later is not "does this address exist" but "is this still the same
//! service": a restarted container can take an address a different container
//! used to hold.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::docker::Published;
use crate::model::Protocol;
use crate::state::ManagedRule;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardTo {
    pub container_addr: Ipv4Addr,
    pub container_port: u16,
    /// The loopback port Docker published, which is what the user named.
    pub published_port: u16,
    pub protocol: Protocol,
}

impl ForwardTo {
    pub fn from_published(p: &Published) -> Self {
        ForwardTo {
            container_addr: p.container_addr,
            container_port: p.container_port,
            published_port: p.host_port,
            protocol: p.protocol,
        }
    }
}

/// The ids of every forward whose stored mapping no longer appears in
/// `published`.
///
/// All four fields must still match. Matching on the container address alone
/// would accept a restarted container that took the address the forward was
/// created against, which is the case this function exists for: the address
/// is the same and the service behind it is not.
///
/// `published` is Docker's current answer, never the absence of one. A caller
/// that could not read Docker's table has nothing to pass here and must not
/// pass an empty slice -- every forward would be named. See
/// [`crate::engine::Engine::close_stale_forwards`], which is where that case
/// is decided.
///
/// Rules with no forward are never named: an ordinary `open` records no
/// mapping, so there is nothing about it for Docker's table to contradict.
pub fn stale_forwards(rules: &[ManagedRule], published: &[Published]) -> Vec<String> {
    rules
        .iter()
        .filter_map(|r| {
            let f = r.forward.as_ref()?;
            let still_there = published.iter().any(|p| {
                p.host_port == f.published_port
                    && p.protocol == f.protocol
                    && p.container_addr == f.container_addr
                    && p.container_port == f.container_port
            });
            (!still_there).then(|| r.id.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendId, RuleHandle};
    use crate::model::{Protocol, Target};
    use std::net::Ipv4Addr;

    fn published() -> crate::docker::Published {
        crate::docker::Published {
            host_addr: Some(Ipv4Addr::new(127, 0, 0, 1)),
            host_port: 3000,
            protocol: Protocol::Tcp,
            container_addr: Ipv4Addr::new(172, 18, 0, 2),
            container_port: 8080,
        }
    }

    #[test]
    fn a_forward_remembers_the_mapping_it_was_created_from() {
        // Without this, a later check can only ask whether the address still
        // exists -- not whether it is still the same service.
        let f = ForwardTo::from_published(&published());
        assert_eq!(f.container_addr, Ipv4Addr::new(172, 18, 0, 2));
        assert_eq!(f.container_port, 8080);
        assert_eq!(f.published_port, 3000);
        assert_eq!(f.protocol, Protocol::Tcp);
    }

    /// A rule that redirects `port` on this machine to `to`. Built here
    /// rather than through the engine: nothing below needs a firewall, a
    /// state file or a runner, which is the whole point of the split.
    fn rule_forwarding(port: u16, to: Ipv4Addr) -> ManagedRule {
        ManagedRule {
            id: format!("rule-{port}"),
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
                rich_rule: "a forward".to_string(),
            },
            forward: Some(ForwardTo {
                container_addr: to,
                container_port: 8080,
                published_port: port,
                protocol: Protocol::Tcp,
            }),
        }
    }

    fn published_at(port: u16, to: Ipv4Addr) -> Published {
        Published {
            host_addr: Some(Ipv4Addr::new(127, 0, 0, 1)),
            host_port: port,
            protocol: Protocol::Tcp,
            container_addr: to,
            container_port: 8080,
        }
    }

    #[test]
    fn a_forward_whose_container_moved_is_named_for_closing() {
        // The same host port, published again, by a container at a different
        // address. Docker assigns addresses at start, so this is what a
        // restart looks like -- and the traffic the forward carries would
        // reach whatever now answers at the old address.
        let rules = vec![rule_forwarding(3000, Ipv4Addr::new(172, 18, 0, 2))];
        let now = vec![published_at(3000, Ipv4Addr::new(172, 18, 0, 9))];
        assert_eq!(stale_forwards(&rules, &now), vec!["rule-3000".to_string()]);
    }

    #[test]
    fn a_forward_whose_container_is_unchanged_is_left_alone() {
        let rules = vec![rule_forwarding(3000, Ipv4Addr::new(172, 18, 0, 2))];
        let now = vec![published_at(3000, Ipv4Addr::new(172, 18, 0, 2))];
        assert!(stale_forwards(&rules, &now).is_empty());
    }

    #[test]
    fn a_forward_whose_container_is_gone_entirely_is_named_for_closing() {
        let rules = vec![rule_forwarding(3000, Ipv4Addr::new(172, 18, 0, 2))];
        assert_eq!(stale_forwards(&rules, &[]), vec!["rule-3000".to_string()]);
    }

    #[test]
    fn an_ordinary_rule_is_never_named() {
        let mut r = rule_forwarding(3000, Ipv4Addr::new(172, 18, 0, 2));
        r.forward = None;
        assert!(stale_forwards(&[r], &[]).is_empty());
    }

    #[test]
    fn a_forward_is_named_when_any_one_of_the_four_fields_stops_matching() {
        // The address is the field this whole check exists for, and it is
        // also the one a test could pass on by itself. Each case below holds
        // three fields equal and moves the fourth, so a comparison that
        // dropped any one of them fails here rather than only in the case
        // nobody wrote.
        let stored = rule_forwarding(3000, Ipv4Addr::new(172, 18, 0, 2));
        let addr = Ipv4Addr::new(172, 18, 0, 2);

        let mut different_container_port = published_at(3000, addr);
        different_container_port.container_port = 8081;

        let mut different_protocol = published_at(3000, addr);
        different_protocol.protocol = Protocol::Udp;

        for (what, now) in [
            ("the published port", published_at(3001, addr)),
            (
                "the container address",
                published_at(3000, Ipv4Addr::new(172, 18, 0, 9)),
            ),
            ("the container port", different_container_port),
            ("the protocol", different_protocol),
        ] {
            assert_eq!(
                stale_forwards(std::slice::from_ref(&stored), &[now]),
                vec!["rule-3000".to_string()],
                "{what} changed and the forward was left open"
            );
        }
    }

    #[test]
    fn one_forward_going_stale_does_not_name_another_that_is_still_current() {
        // The list is per rule, not all-or-nothing: a container that
        // restarted must not take a forward towards a different, untouched
        // container with it.
        let rules = vec![
            rule_forwarding(3000, Ipv4Addr::new(172, 18, 0, 2)),
            rule_forwarding(5432, Ipv4Addr::new(172, 18, 0, 3)),
        ];
        let now = vec![
            published_at(3000, Ipv4Addr::new(172, 18, 0, 9)),
            published_at(5432, Ipv4Addr::new(172, 18, 0, 3)),
        ];
        assert_eq!(stale_forwards(&rules, &now), vec!["rule-3000".to_string()]);
    }
}
