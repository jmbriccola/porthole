//! Which network are we actually on?
//!
//! porthole's default scope is "the subnet I am connected to right now", so
//! getting this wrong means opening a port towards the wrong network. Two
//! things matter: pick the interface that carries the default route (not just
//! the first one with an address), and exclude the virtual interfaces that
//! Docker, libvirt, VPNs and podman leave lying around.

use crate::command::{Command, CommandRunner};
use crate::error::{Error, Result};
use ipnet::Ipv4Net;
use serde::Deserialize;
use std::net::Ipv4Addr;

/// Interface name prefixes that are never "the network I am on".
const VIRTUAL_PREFIXES: &[&str] = &[
    "lo",
    "docker",
    "br-",
    "virbr",
    "tun",
    "tap",
    "veth",
    "cni",
    "podman",
    "vboxnet",
    "wg",
    "zt",
    "tailscale",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNetwork {
    pub interface: String,
    pub address: Ipv4Addr,
    pub cidr: Ipv4Net,
}

pub fn is_virtual_interface(name: &str) -> bool {
    VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p))
}

#[derive(Debug, Deserialize)]
struct RouteEntry {
    dst: String,
    dev: Option<String>,
    #[serde(default)]
    metric: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct AddrEntry {
    ifname: String,
    #[serde(default)]
    addr_info: Vec<AddrInfo>,
}

#[derive(Debug, Deserialize)]
struct AddrInfo {
    family: String,
    local: String,
    prefixlen: u8,
    #[serde(default)]
    scope: String,
}

fn parse_default_route(json: &str) -> Result<String> {
    let routes: Vec<RouteEntry> = serde_json::from_str(json)
        .map_err(|e| Error::Unexpected(format!("could not parse `ip -j route` output: {e}")))?;

    routes
        .into_iter()
        .filter(|r| r.dst == "default")
        // An absent `metric` means zero, not unknown: the kernel only emits
        // RTA_PRIORITY when fib_priority is non-zero, so a statically
        // configured default route (`ip route add default via ...`) arrives
        // with no metric key at all. Treating that as u32::MAX would rank the
        // most-preferred route last and hand back the wrong subnet.
        .filter_map(|r| r.dev.map(|dev| (dev, r.metric.unwrap_or(0))))
        .filter(|(dev, _)| !is_virtual_interface(dev))
        // Lowest metric wins, exactly as the kernel decides.
        .min_by_key(|(_, metric)| *metric)
        .map(|(dev, _)| dev)
        .ok_or_else(|| {
            Error::NoNetwork(
                "no default route on a physical interface: this machine does not appear to be \
                 connected to a network, so there is nothing to open a port towards"
                    .to_string(),
            )
        })
}

fn parse_addresses(json: &str, interface: &str) -> Result<LocalNetwork> {
    let entries: Vec<AddrEntry> = serde_json::from_str(json)
        .map_err(|e| Error::Unexpected(format!("could not parse `ip -j addr` output: {e}")))?;

    let entry = entries
        .into_iter()
        .find(|e| e.ifname == interface)
        .ok_or_else(|| Error::NoNetwork(format!("interface {interface} disappeared")))?;

    let info = entry
        .addr_info
        .into_iter()
        .find(|a| a.family == "inet" && a.scope == "global")
        .ok_or_else(|| {
            Error::NoNetwork(format!(
                "{interface} has no global IPv4 address; porthole v1 only manages IPv4"
            ))
        })?;

    let address: Ipv4Addr = info.local.parse().map_err(|_| {
        Error::Unexpected(format!("`ip` reported `{}` as an IPv4 address", info.local))
    })?;
    let cidr = Ipv4Net::new(address, info.prefixlen)
        .map_err(|e| Error::Unexpected(format!("invalid prefix length from `ip`: {e}")))?
        .trunc();

    Ok(LocalNetwork {
        interface: entry.ifname,
        address,
        cidr,
    })
}

/// The interface carrying the default route.
pub fn default_route_interface(runner: &dyn CommandRunner) -> Result<String> {
    let cmd = Command::read("ip", ["-j", "route", "show", "default"]);
    let out = runner.run(&cmd)?.into_ok(&cmd)?;
    parse_default_route(&out.stdout)
}

/// One entry in the kernel's neighbour (ARP) table: an IPv4 address this
/// machine has actually seen on some interface, and the link-layer address it
/// answered with, when the kernel still has one recorded for it.
///
/// Used to resolve a saved device's MAC address to whatever IPv4 address it
/// currently holds -- see `devices.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    pub address: Ipv4Addr,
    pub interface: String,
    /// Lower-case, e.g. `bc:24:11:5e:1c:6e`.
    pub mac: String,
}

/// Parse `ip -4 neigh show`'s text output.
///
/// Not a positional parse: `dev <iface>` and `lladdr <mac>` are found by
/// their own keyword, not by column index. That distinction is load-bearing
/// here specifically because an `INCOMPLETE` entry has no `lladdr` field at
/// all -- a parse that assumed a fixed column held the MAC would read the
/// state word `INCOMPLETE` itself as one. `STALE` (and any other state word)
/// still carries a usable link-layer address and is kept; only an entry with
/// no `lladdr` token anywhere on its line is skipped.
fn parse_neighbours(text: &str) -> Result<Vec<Neighbour>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(address) = fields.first().and_then(|f| f.parse::<Ipv4Addr>().ok()) else {
            continue;
        };

        let mut interface = None;
        let mut mac = None;
        for i in 1..fields.len().saturating_sub(1) {
            match fields[i] {
                "dev" => interface = Some(fields[i + 1].to_string()),
                "lladdr" => mac = Some(fields[i + 1].to_ascii_lowercase()),
                _ => {}
            }
        }

        if let (Some(interface), Some(mac)) = (interface, mac) {
            out.push(Neighbour {
                address,
                interface,
                mac,
            });
        }
    }
    Ok(out)
}

/// The kernel's IPv4 neighbour table.
pub fn neighbours(runner: &dyn CommandRunner) -> Result<Vec<Neighbour>> {
    let cmd = Command::read("ip", ["-4", "neigh", "show"]);
    let out = runner.run(&cmd)?.into_ok(&cmd)?;
    parse_neighbours(&out.stdout)
}

/// The subnet porthole opens towards by default.
pub fn current_network(runner: &dyn CommandRunner) -> Result<LocalNetwork> {
    let interface = default_route_interface(runner)?;
    let cmd = Command::read("ip", ["-j", "-4", "addr", "show", "dev", &interface]);
    let out = runner.run(&cmd)?.into_ok(&cmd)?;
    parse_addresses(&out.stdout, &interface)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CommandRunner, Output, RecordingRunner};
    use std::net::Ipv4Addr;

    const ROUTE_JSON: &str = r#"[{"dst":"default","gateway":"10.10.10.1","dev":"wlo1","protocol":"dhcp","prefsrc":"10.10.10.119","metric":600,"flags":[]}]"#;

    const ADDR_JSON: &str = r#"[
      {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,
       "addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo"}]},
      {"ifindex":2,"ifname":"wlo1","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,
       "addr_info":[{"family":"inet","local":"10.10.10.119","prefixlen":24,"broadcast":"10.10.10.255","scope":"global","dynamic":true,"label":"wlo1"}]},
      {"ifindex":3,"ifname":"docker0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,
       "addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"broadcast":"172.17.255.255","scope":"global","label":"docker0"}]},
      {"ifindex":4,"ifname":"br-5b772196d2da","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,
       "addr_info":[{"family":"inet","local":"172.18.0.1","prefixlen":16,"broadcast":"172.18.255.255","scope":"global","label":"br-5b772196d2da"}]}
    ]"#;

    #[test]
    fn recognises_virtual_interfaces() {
        for name in [
            "docker0",
            "br-5b772196d2da",
            "virbr0",
            "tun0",
            "tap0",
            "veth1a2b3c",
            "podman0",
            "cni-podman0",
            "wg0",
            "vboxnet0",
            "tailscale0",
            "lo",
        ] {
            assert!(is_virtual_interface(name), "{name} should be virtual");
        }
        for name in ["wlo1", "eth0", "enp0s31f6", "wlan0", "eno1"] {
            assert!(!is_virtual_interface(name), "{name} should be physical");
        }
    }

    #[test]
    fn finds_the_default_route_interface() {
        assert_eq!(parse_default_route(ROUTE_JSON).unwrap(), "wlo1");
    }

    #[test]
    fn prefers_the_lowest_metric_when_several_interfaces_are_up() {
        // Wired and wireless both up: the kernel prefers the lower metric, and
        // so must we.
        let json = r#"[
          {"dst":"default","dev":"wlo1","metric":600},
          {"dst":"default","dev":"enp0s31f6","metric":100}
        ]"#;
        assert_eq!(parse_default_route(json).unwrap(), "enp0s31f6");
    }

    #[test]
    fn ignores_default_routes_on_virtual_interfaces() {
        let json = r#"[
          {"dst":"default","dev":"tun0","metric":50},
          {"dst":"default","dev":"wlo1","metric":600}
        ]"#;
        assert_eq!(parse_default_route(json).unwrap(), "wlo1");
    }

    #[test]
    fn a_route_with_no_metric_key_outranks_one_with_a_metric() {
        // The kernel omits RTA_PRIORITY when the metric is zero, so an absent
        // "metric" is the most-preferred route, not the least. A statically
        // configured wired default route looks exactly like this, and it must
        // beat NetworkManager's metric-600 wifi route — otherwise porthole
        // opens the port towards the wrong network without saying a word.
        let json = r#"[
          {"dst":"default","dev":"wlo1","metric":600},
          {"dst":"default","dev":"enp0s31f6"}
        ]"#;
        assert_eq!(parse_default_route(json).unwrap(), "enp0s31f6");
    }

    #[test]
    fn no_default_route_is_a_no_network_error() {
        let err = parse_default_route("[]").unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::NoNetwork);
        assert!(err.to_string().contains("default route"), "got: {err}");
    }

    #[test]
    fn reads_the_subnet_of_the_chosen_interface() {
        let network = parse_addresses(ADDR_JSON, "wlo1").unwrap();
        assert_eq!(network.interface, "wlo1");
        assert_eq!(network.address, "10.10.10.119".parse::<Ipv4Addr>().unwrap());
        assert_eq!(network.cidr, "10.10.10.0/24".parse::<Ipv4Net>().unwrap());
    }

    #[test]
    fn an_interface_without_a_global_ipv4_address_is_a_no_network_error() {
        let err = parse_addresses(ADDR_JSON, "lo").unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::NoNetwork);
    }

    #[test]
    fn an_unknown_interface_is_a_no_network_error() {
        assert!(parse_addresses(ADDR_JSON, "wlo9").is_err());
    }

    #[test]
    fn current_network_issues_read_only_commands() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let network = current_network(&runner).unwrap();
        assert_eq!(network.cidr, "10.10.10.0/24".parse::<Ipv4Net>().unwrap());

        let commands = runner.recorded();
        assert_eq!(commands[0].display(), "ip -j route show default");
        assert_eq!(commands[1].display(), "ip -j -4 addr show dev wlo1");
        assert!(
            commands
                .iter()
                .all(|c| c.effect == crate::command::Effect::Read),
            "network detection must never mutate anything"
        );
    }

    /// Captured from `ip -4 neigh show` on this machine. The third line is
    /// the case that matters: an `INCOMPLETE` entry has no `lladdr` field at
    /// all, so a positional parse that assumed field 5 held the MAC would
    /// read the state word itself as one.
    const IP_NEIGH: &str = "\
10.10.10.1 dev wlo1 lladdr 50:e6:36:51:42:fd REACHABLE
10.10.10.245 dev wlo1 lladdr bc:24:11:5e:1c:6e STALE
10.10.10.101 dev wlo1 INCOMPLETE
10.10.10.17 dev wlo1 lladdr bc:24:11:99:5d:f3 STALE
";

    #[test]
    fn an_incomplete_neighbour_has_no_mac_and_is_skipped_not_misread() {
        let found = parse_neighbours(IP_NEIGH).unwrap();
        assert_eq!(found.len(), 3);
        assert!(found.iter().all(|n| n.mac != "incomplete"));
    }

    #[test]
    fn a_stale_neighbour_still_resolves() {
        // STALE means the kernel has not confirmed the entry recently, not
        // that it is wrong. Requiring REACHABLE would make a phone that has
        // been idle for a minute "unreachable", which is most of the time.
        let found = parse_neighbours(IP_NEIGH).unwrap();
        let phone = found.iter().find(|n| n.mac == "bc:24:11:5e:1c:6e").unwrap();
        assert_eq!(phone.address, "10.10.10.245".parse::<Ipv4Addr>().unwrap());
        assert_eq!(phone.interface, "wlo1");
    }

    #[test]
    fn a_mac_is_lower_cased_regardless_of_how_ip_printed_it() {
        let found =
            parse_neighbours("10.10.10.1 dev wlo1 lladdr AA:BB:CC:DD:EE:FF REACHABLE\n").unwrap();
        assert_eq!(found[0].mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn a_blank_line_is_skipped_not_an_error() {
        assert!(parse_neighbours("\n").unwrap().is_empty());
        assert!(parse_neighbours("").unwrap().is_empty());
    }

    #[test]
    fn neighbours_reads_the_ipv4_only_table() {
        let runner = RecordingRunner::with_responses(vec![Output::stdout(IP_NEIGH)]);
        let found = neighbours(&runner).unwrap();
        assert_eq!(found.len(), 3);

        let commands = runner.recorded();
        assert_eq!(commands[0].display(), "ip -4 neigh show");
        assert_eq!(commands[0].effect, crate::command::Effect::Read);
    }
}
