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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;
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
    }
}
