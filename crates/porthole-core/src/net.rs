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

/// Neighbour states whose entry carries no mapping worth acting on,
/// whatever else the line holds.
///
/// `INCOMPLETE` has no `lladdr` at all: address resolution is still in
/// flight, and there is nothing to read. `FAILED` is the kernel's own record
/// that it probed this address and got no answer -- the entry may still
/// carry the `lladdr` it last knew, and that is exactly the mapping the
/// probe disproved. Neither is a state a saved device should resolve
/// through.
const UNUSABLE_NEIGHBOUR_STATES: [&str; 2] = ["FAILED", "INCOMPLETE"];

/// Parse `ip -4 neigh show`'s text output.
///
/// Not a positional parse: `dev <iface>` and `lladdr <mac>` are found by
/// their own keyword, not by column index, and this loop steps over the
/// value it just consumed so a state word is never confused with an
/// interface name or a MAC.
///
/// An entry is kept when it names a non-virtual interface
/// ([`is_virtual_interface`]) and an `lladdr`, and its state is not one of
/// [`UNUSABLE_NEIGHBOUR_STATES`]. `STALE` is kept -- see [`neighbours`] for
/// what that does and does not mean.
///
/// The interface test is here, at the one place a [`Neighbour`] is built
/// from the kernel's table, rather than at each caller. Nothing else in the
/// crate turns `ip -4 neigh show` into `Neighbour` values, and there is no
/// unfiltered variant to reach for, so a virtual interface's entry cannot be
/// offered or resolved through by a caller that forgot to exclude it.
fn parse_neighbours(text: &str) -> Result<Vec<Neighbour>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(address) = fields.first().and_then(|f| f.parse::<Ipv4Addr>().ok()) else {
            continue;
        };

        let mut interface = None;
        let mut mac = None;
        let mut unusable = false;
        let mut i = 1;
        while i < fields.len() {
            match fields[i] {
                "dev" => {
                    interface = fields.get(i + 1).map(|f| f.to_string());
                    i += 2;
                }
                "lladdr" => {
                    mac = fields.get(i + 1).map(|f| f.to_ascii_lowercase());
                    i += 2;
                }
                word => {
                    if UNUSABLE_NEIGHBOUR_STATES.contains(&word) {
                        unusable = true;
                    }
                    i += 1;
                }
            }
        }

        if unusable {
            continue;
        }

        if let (Some(interface), Some(mac)) = (interface, mac) {
            // Docker containers, libvirt guests, VPN peers and podman pods
            // all leave entries here, on interfaces that are not the network
            // this machine is on. `parse_all_subnets` excludes the same
            // interfaces from subnet detection; the neighbour table is the
            // other half of the same question.
            if is_virtual_interface(&interface) {
                continue;
            }
            out.push(Neighbour {
                address,
                interface,
                mac,
            });
        }
    }
    Ok(out)
}

/// The kernel's IPv4 neighbour table, minus the entries that carry no
/// mapping ([`UNUSABLE_NEIGHBOUR_STATES`]) and those on a virtual interface
/// ([`is_virtual_interface`]).
///
/// What a returned entry means, stated narrowly, because a saved device is
/// resolved through this and a port is opened towards the address it gives:
/// the kernel has an IP-to-MAC mapping recorded, and has not disproved it.
/// It is not a reachability test, and nothing here sends a packet to make
/// one.
///
/// Every entry is on an interface that carries a real network. A Docker
/// container on a user-created bridge, a libvirt guest and a VPN peer are
/// all in the kernel's table and none of them is on the network porthole
/// opens a port towards, which is the same set of interfaces
/// [`present_networks`] reports subnets for. The exclusion applies to
/// resolution as well as to the two pickers: a MAC that is only in the
/// table on a virtual interface does not resolve, and
/// [`crate::devices::resolve`] reports it as not on this network rather
/// than returning an address outside every subnet this machine holds.
///
/// `STALE` entries are included. The kernel marks an entry `STALE` once it
/// has not been confirmed recently -- roughly 30s of idleness on this
/// machine's `base_reachable_time_ms` -- which is the ordinary condition of
/// a phone in a pocket, not a sign that anything is wrong. Excluding them
/// would refuse a large share of a quiet network's devices: on this
/// machine's own table, two of five entries were `STALE` at rest.
///
/// The cost of including them is real and worth naming. A `STALE` entry can
/// be wrong -- the device left, its DHCP lease expired, and the address was
/// handed to something else -- and on a small network the kernel may not
/// correct it soon, because it garbage-collects the table only above
/// `gc_thresh1` entries (128 by default, against five here). In practice a
/// new lease-holder that announces itself by ARP causes the kernel to
/// rewrite the entry for that address, after which the saved MAC no longer
/// maps to it and the device stops resolving; that is the usual, and
/// self-correcting, path.
///
/// Requiring `REACHABLE` would narrow that window but not close it, and the
/// reason is not about neighbour states at all: a rule outlives the check
/// that authorized it. A device may leave one second after the rule is
/// written, and porthole re-examines nothing for as long as the rule stands.
/// So a stricter gate here buys confidence at the moment of opening, on a
/// rule that may live for hours, in exchange for refusing devices that are
/// merely idle. That trade was judged not worth making; the limitation it
/// would have narrowed is documented rather than hidden, in
/// `docs/json-schema.md` alongside `resolvable`.
pub fn neighbours(runner: &dyn CommandRunner) -> Result<Vec<Neighbour>> {
    let cmd = Command::read("ip", ["-4", "neigh", "show"]);
    let out = runner.run(&cmd)?.into_ok(&cmd)?;
    parse_neighbours(&out.stdout)
}

/// Every subnet this machine currently holds on a non-virtual interface,
/// alongside the one the default route names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentNetworks {
    /// The default route's own subnet -- exactly what [`current_network`]
    /// returns, and what "the network I am on" means wherever one answer is
    /// wanted.
    pub primary: LocalNetwork,
    /// Every non-virtual interface's subnet, `primary`'s included,
    /// de-duplicated and in the order `ip` listed them.
    pub all: Vec<Ipv4Net>,
}

/// Both facts, from the same two reads [`current_network`] already makes.
///
/// A machine can hold several subnets at once -- a docked laptop with wifi
/// and ethernet both up is the ordinary case -- and the default route names
/// only one of them. A caller asking "is this subnet still up?" cannot get
/// that from the default route, because a still-connected interface that
/// does not carry the route is invisible to it.
///
/// The only difference from [`current_network`]'s own second command is that
/// the address read is unfiltered (`ip -j -4 addr show`, no `dev`), so the
/// same output answers both questions.
pub fn present_networks(runner: &dyn CommandRunner) -> Result<PresentNetworks> {
    let interface = default_route_interface(runner)?;
    let cmd = Command::read("ip", ["-j", "-4", "addr", "show"]);
    let out = runner.run(&cmd)?.into_ok(&cmd)?;
    let primary = parse_addresses(&out.stdout, &interface)?;
    let all = parse_all_subnets(&out.stdout)?;
    Ok(PresentNetworks { primary, all })
}

/// Every non-virtual interface's global IPv4 subnet, from one unfiltered
/// `ip -j -4 addr show`.
///
/// An interface with no global IPv4 address contributes nothing rather than
/// failing the whole read: unlike [`parse_addresses`], which is asked about
/// one named interface and must say when that interface has no address,
/// this is a sweep, and a machine routinely carries interfaces that are up
/// with nothing global on them.
fn parse_all_subnets(json: &str) -> Result<Vec<Ipv4Net>> {
    let entries: Vec<AddrEntry> = serde_json::from_str(json)
        .map_err(|e| Error::Unexpected(format!("could not parse `ip -j addr` output: {e}")))?;

    let mut out: Vec<Ipv4Net> = Vec::new();
    for entry in entries {
        if is_virtual_interface(&entry.ifname) {
            continue;
        }
        for info in entry.addr_info {
            if info.family != "inet" || info.scope != "global" {
                continue;
            }
            let Ok(address) = info.local.parse::<Ipv4Addr>() else {
                continue;
            };
            let Ok(cidr) = Ipv4Net::new(address, info.prefixlen) else {
                continue;
            };
            let cidr = cidr.trunc();
            if !out.contains(&cidr) {
                out.push(cidr);
            }
        }
    }
    Ok(out)
}

/// The subnet porthole opens towards by default.
pub fn current_network(runner: &dyn CommandRunner) -> Result<LocalNetwork> {
    let interface = default_route_interface(runner)?;
    let cmd = Command::read("ip", ["-j", "-4", "addr", "show", "dev", &interface]);
    let out = runner.run(&cmd)?.into_ok(&cmd)?;
    parse_addresses(&out.stdout, &interface)
}

#[cfg(test)]
pub(crate) mod tests {
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
    ///
    /// Shared with `devices`' own tests, which resolve saved devices against
    /// it -- the same arrangement `backend::firewalld::tests::ROUTE_JSON`
    /// already has with `reconcile`. One captured table, so a device test
    /// and a parser test cannot drift apart on what `ip` prints.
    pub(crate) const IP_NEIGH: &str = "\
10.10.10.1 dev wlo1 lladdr 50:e6:36:51:42:fd REACHABLE
10.10.10.245 dev wlo1 lladdr bc:24:11:5e:1c:6e STALE
10.10.10.101 dev wlo1 INCOMPLETE
10.10.10.17 dev wlo1 lladdr bc:24:11:99:5d:f3 STALE
";

    /// `ip -j -4 addr show`, verbatim from this machine (Fedora 44,
    /// iproute2): one real wifi interface plus the three virtual ones this
    /// machine actually carries -- loopback, `docker0`, and a `br-` bridge
    /// left by an unrelated project. Captured rather than written, so the
    /// virtual-exclusion test below runs against interfaces that really
    /// exist and really have global IPv4 addresses.
    const ADDR_JSON_ALL: &str = r#"[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"qdisc":"noqueue","operstate":"UNKNOWN","group":"default","txqlen":1000,"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo","valid_life_time":4294967295,"preferred_life_time":4294967295}]},{"ifindex":2,"ifname":"wlo1","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","group":"default","txqlen":1000,"altnames":["wlp0s20f3","wlxe8bfb85d9152"],"addr_info":[{"family":"inet","local":"10.10.10.119","prefixlen":24,"broadcast":"10.10.10.255","scope":"global","dynamic":true,"noprefixroute":true,"label":"wlo1","valid_life_time":726888,"preferred_life_time":726888}]},{"ifindex":3,"ifname":"docker0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"qdisc":"noqueue","operstate":"DOWN","group":"default","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"broadcast":"172.17.255.255","scope":"global","label":"docker0","valid_life_time":4294967295,"preferred_life_time":4294967295}]},{"ifindex":4,"ifname":"br-5b772196d2da","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"qdisc":"noqueue","operstate":"DOWN","group":"default","addr_info":[{"family":"inet","local":"172.18.0.1","prefixlen":16,"broadcast":"172.18.255.255","scope":"global","label":"br-5b772196d2da","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]"#;

    #[test]
    fn every_subnet_sweep_keeps_the_real_interface_and_drops_the_virtual_ones() {
        // `docker0` and `br-5b772196d2da` both carry a global IPv4 address
        // on this machine, so "has a global address" is not on its own
        // enough to make a subnet one porthole is on.
        let found = parse_all_subnets(ADDR_JSON_ALL).unwrap();
        assert_eq!(found, vec!["10.10.10.0/24".parse::<Ipv4Net>().unwrap()]);
    }

    #[test]
    fn every_subnet_sweep_reports_both_interfaces_of_a_docked_laptop() {
        // The case the default route cannot express: two physical
        // interfaces up at once, only one of which carries the route.
        let two = ADDR_JSON_ALL.replace(
            r#"{"ifindex":3,"ifname":"docker0""#,
            r#"{"ifindex":5,"ifname":"enp0s31f6","addr_info":[{"family":"inet","local":"192.168.1.50","prefixlen":24,"scope":"global"}]},{"ifindex":3,"ifname":"docker0""#,
        );
        let found = parse_all_subnets(&two).unwrap();
        assert_eq!(
            found,
            vec![
                "10.10.10.0/24".parse::<Ipv4Net>().unwrap(),
                "192.168.1.0/24".parse::<Ipv4Net>().unwrap(),
            ]
        );
    }

    #[test]
    fn a_host_scoped_address_is_not_a_subnet_the_machine_is_on() {
        // Loopback's 127.0.0.1/8 is `scope: host`, and `lo` is excluded by
        // name as well -- checked here so neither guard is the only one.
        let only_lo = r#"[{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]}]"#;
        assert!(parse_all_subnets(only_lo).unwrap().is_empty());
    }

    #[test]
    fn present_networks_names_the_default_route_subnet_and_still_lists_the_others() {
        let two_routes = r#"[{"dst":"default","dev":"enp0s31f6","metric":100},{"dst":"default","dev":"wlo1","metric":600}]"#;
        let two_addrs = ADDR_JSON_ALL.replace(
            r#"{"ifindex":3,"ifname":"docker0""#,
            r#"{"ifindex":5,"ifname":"enp0s31f6","addr_info":[{"family":"inet","local":"192.168.1.50","prefixlen":24,"scope":"global"}]},{"ifindex":3,"ifname":"docker0""#,
        );
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(two_routes),
            Output::stdout(&two_addrs),
        ]);
        let present = present_networks(&runner).unwrap();

        assert_eq!(present.primary.interface, "enp0s31f6");
        assert_eq!(
            present.primary.cidr,
            "192.168.1.0/24".parse::<Ipv4Net>().unwrap()
        );
        assert!(
            present.all.contains(&"10.10.10.0/24".parse().unwrap()),
            "the interface that does not carry the route is still up"
        );

        let commands = runner.recorded();
        assert_eq!(commands[1].display(), "ip -j -4 addr show");
        assert!(commands
            .iter()
            .all(|c| c.effect == crate::command::Effect::Read));
    }

    /// The shape this machine's own table held while the picker was
    /// offering Docker containers to open a firewall port towards: two
    /// entries on the wifi interface and two on a user-created Docker
    /// bridge. `br-5b772196d2da` is the interface name verbatim, and the
    /// two `172.18.0.x` MACs are the locally-administered ones Docker
    /// generates; the two `wlo1` rows use this module's other fixtures'
    /// addresses rather than the real network's.
    const IP_NEIGH_WITH_BRIDGE: &str = "\
172.18.0.2 dev br-5b772196d2da lladdr 6a:df:71:ff:3c:e4 STALE
10.10.10.1 dev wlo1 lladdr 50:e6:36:51:42:fd REACHABLE
172.18.0.3 dev br-5b772196d2da lladdr 8e:3a:fc:5b:5c:dc STALE
10.10.10.245 dev wlo1 lladdr bc:24:11:5e:1c:6e REACHABLE
";

    #[test]
    fn a_docker_container_is_not_offered_as_a_device_on_this_network() {
        let found = parse_neighbours(IP_NEIGH_WITH_BRIDGE).unwrap();
        assert_eq!(
            found.len(),
            2,
            "only the two wifi entries are on the network this machine is on"
        );
        assert!(
            found.iter().all(|n| n.interface == "wlo1"),
            "a `br-` entry is a container on a bridge, not a device to open a port towards: {found:?}"
        );
        assert!(
            !found
                .iter()
                .any(|n| n.mac == "6a:df:71:ff:3c:e4" || n.mac == "8e:3a:fc:5b:5c:dc"),
            "neither container MAC may reach a picker or a resolution"
        );
    }

    #[test]
    fn every_virtual_interface_kind_is_excluded_from_the_table_not_just_docker() {
        // The same list subnet detection uses. A VPN peer, a libvirt guest
        // and a podman container each land in the kernel's table under
        // their own prefix.
        let found = parse_neighbours(
            "10.0.0.2 dev virbr0 lladdr aa:00:00:00:00:01 REACHABLE\n\
             10.0.0.3 dev wg0 lladdr aa:00:00:00:00:02 REACHABLE\n\
             10.0.0.4 dev podman0 lladdr aa:00:00:00:00:03 REACHABLE\n\
             10.0.0.5 dev veth1234 lladdr aa:00:00:00:00:04 REACHABLE\n\
             10.0.0.6 dev docker0 lladdr aa:00:00:00:00:05 REACHABLE\n\
             10.0.0.7 dev tailscale0 lladdr aa:00:00:00:00:06 REACHABLE\n\
             10.0.0.8 dev enp0s31f6 lladdr aa:00:00:00:00:07 REACHABLE\n",
        )
        .unwrap();
        assert_eq!(
            found.len(),
            1,
            "only the ethernet entry survives: {found:?}"
        );
        assert_eq!(found[0].interface, "enp0s31f6");
    }

    #[test]
    fn a_bridge_over_the_physical_nic_is_still_a_real_network() {
        // `br-` is Docker's user-created-bridge naming. A traditional
        // `br0` bridging the machine's own NIC is the network this machine
        // is on, and excluding it would leave such a host with no devices
        // to pick at all.
        let found =
            parse_neighbours("10.10.10.1 dev br0 lladdr 50:e6:36:51:42:fd REACHABLE\n").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].interface, "br0");
    }

    #[test]
    fn the_public_entry_point_offers_no_virtual_interface_either() {
        // `neighbours` is the only way anything outside this module turns
        // the kernel's table into `Neighbour` values, so this is what every
        // caller gets -- the two pickers and `devices::resolve` alike.
        let runner = RecordingRunner::with_responses(vec![Output::stdout(IP_NEIGH_WITH_BRIDGE)]);
        let found = neighbours(&runner).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|n| !is_virtual_interface(&n.interface)));
    }

    #[test]
    fn an_incomplete_neighbour_has_no_mac_and_is_skipped_not_misread() {
        let found = parse_neighbours(IP_NEIGH).unwrap();
        assert_eq!(found.len(), 3);
        assert!(found.iter().all(|n| n.mac != "incomplete"));
    }

    /// Synthetic, not captured: this machine's own table held only
    /// `REACHABLE` and `STALE` entries, so a `FAILED` line could not be
    /// observed here. What it stands for is an entry the kernel probed and
    /// got no answer for, which retains the `lladdr` it last knew -- the
    /// shape that matters, since that residual MAC is what a parser keying
    /// only on `lladdr` would accept.
    const IP_NEIGH_FAILED: &str = "\
10.10.10.1 dev wlo1 lladdr 50:e6:36:51:42:fd REACHABLE
10.10.10.88 dev wlo1 lladdr bc:24:11:77:88:99 FAILED
";

    #[test]
    fn a_failed_neighbour_is_rejected_even_though_it_still_carries_a_mac() {
        // FAILED is the kernel's record that it asked this address and got
        // nothing back. Accepting the lladdr it still carries would resolve
        // a saved device through a mapping that has been actively
        // disproved, and open a port towards it.
        let found = parse_neighbours(IP_NEIGH_FAILED).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].mac, "50:e6:36:51:42:fd");
        assert!(
            !found.iter().any(|n| n.mac == "bc:24:11:77:88:99"),
            "a FAILED entry must not resolve"
        );
    }

    #[test]
    fn a_state_word_is_never_mistaken_for_an_interface_or_a_mac() {
        // The loop steps over the value it consumed after `dev` and
        // `lladdr`, so the state scan only ever sees bare tokens. Pins that
        // an interface or MAC could not smuggle a rejection in.
        let found =
            parse_neighbours("10.0.0.5 dev FAILED lladdr aa:bb:cc:dd:ee:ff STALE\n").unwrap();
        assert_eq!(
            found.len(),
            1,
            "`dev FAILED` names an interface, not a state"
        );
        assert_eq!(found[0].interface, "FAILED");
    }

    #[test]
    fn a_stale_neighbour_still_resolves() {
        // Deliberate, and documented on `neighbours`: STALE is the ordinary
        // condition of an idle device, not evidence the mapping is wrong.
        // Two of this machine's own five entries were STALE at rest, so
        // refusing them would refuse much of a quiet network -- while still
        // not bounding exposure, because a rule outlives the check that
        // authorized it.
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
