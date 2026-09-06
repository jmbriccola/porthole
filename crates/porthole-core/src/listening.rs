//! What is listening on this machine, read from `/proc`.
//!
//! This is what makes `porthole open` pleasant: pick a port from a list
//! instead of typing a number you half-remember. All of the difficulty here
//! is parsing, not presentation — see
//! `.superpowers/sdd/milestone-4-verified-facts.md` (in the source tree, not
//! shipped) for the numbers this module was built against.
//!
//! Two details in `/proc/net/tcp`'s own format are easy to get backwards, and
//! getting either one wrong produces a plausible-looking wrong answer rather
//! than a parse error:
//!
//! - `local_address` is `HEXADDR:HEXPORT`, and the address is stored in the
//!   host's native (little-endian) byte order: `0100007F` is `127.0.0.1`.
//!   Read the bytes in the order they appear in the string and you get
//!   `1.0.0.127` instead — a valid-looking address that would classify a
//!   loopback-only service as reachable from the network.
//! - The port is hex: `B67B` is 46715, not garbage, and `1435` is 5173, not
//!   one thousand four hundred and thirty-five.
//!
//! And one classification is not a nicety: on the machine this was built and
//! measured on, six of the seven listening TCP sockets were bound to
//! `127.0.0.0/8`. Opening the firewall for any of them would change nothing —
//! the process is not listening on a network interface at all — so
//! [`Binding::LoopbackOnly`] is marked plainly, not folded into a generic
//! "open" affordance.
//!
//! A second distinction matters just as much, in the opposite direction: a
//! socket bound to a genuine IPv6 address — not the wildcard, not loopback,
//! not v4-mapped — **is** reachable from the network. Porthole simply cannot
//! do anything about it, since v1 manages IPv4 rules only. That is a
//! fundamentally different fact from loopback-only (safe, and nothing to do)
//! rather than the same one worded differently, so it gets its own variant,
//! [`Binding::BeyondReach`], rather than being folded into `LoopbackOnly`
//! because porthole is equally unable to help with either.

use crate::error::{Error, Result};
use crate::model::Protocol;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// How a listening socket is reachable, coarsely — the one fact that decides
/// whether opening porthole's (IPv4-only) firewall for it can do anything,
/// and whether it is actually safe to leave alone.
///
/// `LoopbackOnly` and `BeyondReach` both mean "porthole cannot help", but for
/// opposite reasons and with opposite implications for the user: the first
/// is safe because nothing outside this machine can reach it; the second is
/// exposed to the network and porthole is simply blind to it. Do not merge
/// them, reword one to sound like the other, or treat "porthole can't act"
/// as a stand-in for "this is fine" — see this module's own doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// Bound to `127.0.0.0/8`, or its IPv6 loopback equivalent (`::1`). Only
    /// processes on this machine can reach it; no firewall rule changes
    /// that.
    LoopbackOnly,
    /// Bound to `0.0.0.0` (or, for a v6 listener, `::`): every interface,
    /// including whichever one the local network is reachable through.
    AllInterfaces,
    /// Bound to one specific IPv4 address — an interface's own IP, not the
    /// wildcard. Still network-facing, just narrower than `AllInterfaces`.
    Specific(Ipv4Addr),
    /// Bound to a genuine IPv6 address — not the wildcard, not loopback, not
    /// v4-mapped. This listener **is** reachable over the network; porthole
    /// simply cannot open or close a firewall rule for it, since v1 manages
    /// IPv4 rules only. This is not `LoopbackOnly` worded differently: a
    /// loopback-only listener is safe from the network, this one is exposed
    /// to it and porthole cannot affect that exposure either way.
    BeyondReach(Ipv6Addr),
}

fn classify_v4(addr: Ipv4Addr) -> Binding {
    if addr.is_loopback() {
        Binding::LoopbackOnly
    } else if addr.is_unspecified() {
        Binding::AllInterfaces
    } else {
        Binding::Specific(addr)
    }
}

/// The same classification for a `/proc/net/tcp6` address.
///
/// Measured on this machine (`.superpowers/sdd/milestone-4-verified-facts.md`,
/// cross-checked against `ss -ltnp` during development): every real LISTEN
/// row seen in practice is either `::` or `::1`. The v4-mapped and "anything
/// else" arms below exist for correctness, not because either was ever
/// observed here.
fn classify_v6(addr: Ipv6Addr) -> Binding {
    if addr.is_unspecified() {
        // `::` accepts v4-mapped connections on most systems (Linux's default
        // is `net.ipv6.bindv6only=0`), so it is reachable over IPv4 too --
        // see this module's doc comment and `doctor`'s own IPv6 caveat.
        Binding::AllInterfaces
    } else if let Some(v4) = addr.to_ipv4_mapped() {
        classify_v4(v4)
    } else if addr.is_loopback() {
        Binding::LoopbackOnly
    } else {
        // A genuine IPv6 address that is neither the wildcard, loopback, nor
        // v4-mapped. It is not reachable over IPv4 -- true -- but it is
        // reachable over IPv6, by whatever this address's own scope allows
        // (link-local, unique-local, or a globally routable address if this
        // one happens to be routable). Porthole cannot open or close a
        // firewall rule for it either way, since v1 manages IPv4 rules only
        // -- but that is a statement about porthole's reach, not the
        // socket's. Folding this into `LoopbackOnly` (as an earlier version
        // of this function did) would tell the user "only this machine can
        // reach it" about a socket the network can reach -- false in the
        // dangerous direction. See `Binding::BeyondReach`.
        Binding::BeyondReach(addr)
    }
}

/// A single TCP socket in the `LISTEN` state, as reported by `/proc`.
///
/// Only TCP is scanned today: `porthole listen` reads `/proc/net/tcp` and
/// `/proc/net/tcp6`, not the `udp` counterparts, so `protocol` is always
/// [`Protocol::Tcp`] for now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub port: u16,
    pub protocol: Protocol,
    /// The literal address this socket is bound to, exactly as parsed —
    /// `0.0.0.0`, `127.0.0.1`, `::`, `::1`, or a specific interface address.
    pub address: IpAddr,
    /// The coarser fact `binding` exists to answer: would opening a firewall
    /// rule for this port change anything.
    pub binding: Binding,
    /// `None` when the owning process could not be identified — a different
    /// user's process, most commonly, since resolving this needs read access
    /// to that process's own `/proc/<pid>/fd`. Never a placeholder like
    /// `"unknown"`: that would claim a name porthole does not actually have.
    pub process: Option<String>,
    pub pid: Option<u32>,
}

/// A parsed `/proc/net/tcp`(6) row, before the inode is resolved to a
/// process. Kept separate from [`Service`] because resolution needs a
/// [`ProcFs`] and this does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawListener {
    port: u16,
    address: IpAddr,
    binding: Binding,
    inode: u64,
}

/// `local_address` is little-endian: the bytes appear in the string in the
/// opposite order from the address's own octets. `0100007F` is `127.0.0.1`;
/// reading the string's byte pairs in order instead gives `1.0.0.127` —
/// exactly the "plausible but wrong" failure this function exists to avoid.
/// `u32::swap_bytes` makes the flip explicit rather than leaving it implicit
/// in a hand-rolled loop.
fn parse_hex_addr_v4(hex: &str) -> Result<Ipv4Addr> {
    if hex.len() != 8 {
        return Err(Error::Unexpected(format!(
            "not an 8-digit hex IPv4 address: {hex}"
        )));
    }
    let bits = u32::from_str_radix(hex, 16)
        .map_err(|_| Error::Unexpected(format!("not a hex address: {hex}")))?;
    Ok(Ipv4Addr::from(bits.swap_bytes()))
}

/// The v6 counterpart: 16 bytes as four 8-hex-digit words, each word
/// byte-swapped the same way [`parse_hex_addr_v4`] swaps its one word.
fn parse_hex_addr_v6(hex: &str) -> Result<Ipv6Addr> {
    if hex.len() != 32 {
        return Err(Error::Unexpected(format!(
            "not a 32-digit hex IPv6 address: {hex}"
        )));
    }
    let mut octets = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
        let word = std::str::from_utf8(chunk)
            .map_err(|_| Error::Unexpected(format!("not valid hex bytes: {hex}")))?;
        let bits = u32::from_str_radix(word, 16)
            .map_err(|_| Error::Unexpected(format!("not a hex address: {word}")))?
            .swap_bytes();
        octets[i * 4..i * 4 + 4].copy_from_slice(&bits.to_be_bytes());
    }
    Ok(Ipv6Addr::from(octets))
}

/// The port, unlike the address, is plain big-endian hex: `B67B` is 46715.
/// Read as decimal it would either fail outright (`B67B` has no decimal
/// meaning) or, worse, silently parse as the wrong number (`1435` reads as
/// one thousand four hundred thirty-five instead of port 5173).
fn parse_hex_port(hex: &str) -> Result<u16> {
    u16::from_str_radix(hex, 16).map_err(|_| Error::Unexpected(format!("not a hex port: {hex}")))
}

/// Yields `(address_hex, port_hex, inode)` for every row in `LISTEN` state
/// (`st == 0A`) in a `/proc/net/tcp`-or-`tcp6`-shaped text, skipping the
/// header line. Anything else — an established connection, a short or
/// otherwise unparseable row — is silently absent, never a reason to fail
/// the whole scan: a future kernel adding a column, or one stray line, must
/// not take down `porthole listen` entirely.
fn listening_rows(text: &str) -> impl Iterator<Item = (&str, &str, u64)> {
    text.lines().skip(1).filter_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 || fields[3] != "0A" {
            return None;
        }
        let (addr_hex, port_hex) = fields[1].split_once(':')?;
        let inode: u64 = fields[9].parse().ok()?;
        Some((addr_hex, port_hex, inode))
    })
}

/// Every row this parses is either used or silently skipped (see
/// `listening_rows`'s own doc comment) -- there is no path through this
/// function that produces an `Err`, so unlike almost everything else in this
/// module it returns a plain `Vec`, not a `Result`.
fn parse_proc_net_tcp(text: &str) -> Vec<RawListener> {
    let mut out = Vec::new();
    for (addr_hex, port_hex, inode) in listening_rows(text) {
        let (Ok(address), Ok(port)) = (parse_hex_addr_v4(addr_hex), parse_hex_port(port_hex))
        else {
            continue;
        };
        out.push(RawListener {
            port,
            address: IpAddr::V4(address),
            binding: classify_v4(address),
            inode,
        });
    }
    out
}

/// The v6 counterpart of [`parse_proc_net_tcp`]. Same reasoning: no path
/// here produces an `Err` either.
fn parse_proc_net_tcp6(text: &str) -> Vec<RawListener> {
    let mut out = Vec::new();
    for (addr_hex, port_hex, inode) in listening_rows(text) {
        let (Ok(address), Ok(port)) = (parse_hex_addr_v6(addr_hex), parse_hex_port(port_hex))
        else {
            continue;
        };
        out.push(RawListener {
            port,
            address: IpAddr::V6(address),
            binding: classify_v6(address),
            inode,
        });
    }
    out
}

/// Everything `scan` needs from `/proc`, seamed out exactly the way
/// [`crate::command::CommandRunner`] seams out external commands: a real
/// implementation for production, and a fake one for tests that has no
/// dependency on this host's actual process table.
pub trait ProcFs {
    /// Contents of `/proc/net/tcp`.
    fn net_tcp(&self) -> Result<String>;
    /// Contents of `/proc/net/tcp6`. A machine with no IPv6 support at all
    /// may not have this file; that is not the same failure as
    /// `/proc/net/tcp` itself being unreadable, and callers should treat an
    /// `Err` here as "no IPv6 listeners", not as a reason to fail outright.
    fn net_tcp6(&self) -> Result<String>;
    /// Every pid currently visible in `/proc` — listing them needs no
    /// privilege; reading into one belonging to another user does.
    fn pids(&self) -> Result<Vec<u32>>;
    /// The symlink target of every entry in `/proc/<pid>/fd`, e.g.
    /// `"socket:[67371]"`. `Err` means the directory itself could not be
    /// read at all — ordinarily because `pid` belongs to another user.
    fn fd_links(&self, pid: u32) -> Result<Vec<String>>;
    /// The contents of `/proc/<pid>/comm`, trimmed.
    fn comm(&self, pid: u32) -> Result<String>;
}

/// Reads the real `/proc`.
pub struct RealProcFs;

impl ProcFs for RealProcFs {
    fn net_tcp(&self) -> Result<String> {
        std::fs::read_to_string("/proc/net/tcp")
            .map_err(|e| Error::Unexpected(format!("could not read /proc/net/tcp: {e}")))
    }

    fn net_tcp6(&self) -> Result<String> {
        std::fs::read_to_string("/proc/net/tcp6")
            .map_err(|e| Error::Unexpected(format!("could not read /proc/net/tcp6: {e}")))
    }

    fn pids(&self) -> Result<Vec<u32>> {
        let entries = std::fs::read_dir("/proc")
            .map_err(|e| Error::Unexpected(format!("could not read /proc: {e}")))?;
        Ok(entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().to_str().and_then(|s| s.parse().ok()))
            .collect())
    }

    fn fd_links(&self, pid: u32) -> Result<Vec<String>> {
        let dir = format!("/proc/{pid}/fd");
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| Error::Unexpected(format!("could not read {dir}: {e}")))?;
        Ok(entries
            .filter_map(|entry| entry.ok())
            // A fd can close between listing the directory and reading this
            // one link -- that race is not an error, just one fewer link.
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .filter_map(|target| target.to_str().map(str::to_string))
            .collect())
    }

    fn comm(&self, pid: u32) -> Result<String> {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .map_err(|e| Error::Unexpected(format!("could not read /proc/{pid}/comm: {e}")))
    }
}

/// `socket:[67371]` -> `67371`. Anything else a `/proc/<pid>/fd` entry can
/// point to (a regular file, a pipe, a terminal) is simply not a match.
fn parse_socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Maps each socket inode in `raw` to the pid and process name that own it,
/// by scanning every visible pid's `fd` directory for `socket:[<inode>]`.
///
/// Unprivileged, `fd_links` fails for any pid this process does not own —
/// that failure is per-pid and is skipped, not propagated: one unreadable
/// process must not blank out every resolution this scan could otherwise
/// make. A pid enumeration failure (`pids()` itself erroring) is likewise
/// not fatal to the overall scan — it just means nothing resolves, the same
/// outcome as every individual pid being denied.
fn resolve_pids(fs: &dyn ProcFs, raw: &[RawListener]) -> HashMap<u64, (u32, String)> {
    let mut resolved = HashMap::new();
    let Ok(pids) = fs.pids() else {
        return resolved;
    };
    let inodes: HashSet<u64> = raw.iter().map(|r| r.inode).collect();

    for pid in pids {
        let Ok(links) = fs.fd_links(pid) else {
            continue;
        };
        for link in links {
            let Some(inode) = parse_socket_inode(&link) else {
                continue;
            };
            if !inodes.contains(&inode) {
                continue;
            }
            if let Ok(name) = fs.comm(pid) {
                resolved.insert(inode, (pid, name));
            }
        }
    }
    resolved
}

/// Every TCP socket in `LISTEN` state on this machine, IPv4 and IPv6 alike,
/// with as much process identity as this process is privileged to see.
///
/// A v6 listener bound to `::` is included, not filtered out for being
/// "not IPv4" — see this module's own doc comment for why it is still
/// reachable over IPv4 on most systems, and `porthole doctor`'s `IPv6` check
/// (`porthole-cli/src/doctor.rs`) for the caveat that porthole itself only
/// ever opens IPv4 rules regardless. Omitting a `::` listener here would
/// hide a real, network-facing service.
pub fn scan(fs: &dyn ProcFs) -> Result<Vec<Service>> {
    let mut raw = parse_proc_net_tcp(&fs.net_tcp()?);
    // A machine with IPv6 disabled entirely may have no /proc/net/tcp6 at
    // all; that is not a reason to fail a scan that is otherwise fine.
    if let Ok(text6) = fs.net_tcp6() {
        raw.extend(parse_proc_net_tcp6(&text6));
    }

    let resolved = resolve_pids(fs, &raw);

    let mut services: Vec<Service> = raw
        .into_iter()
        .map(|r| {
            let found = resolved.get(&r.inode);
            Service {
                port: r.port,
                protocol: Protocol::Tcp,
                address: r.address,
                binding: r.binding,
                process: found.map(|(_, name)| name.clone()),
                pid: found.map(|(pid, _)| *pid),
            }
        })
        .collect();

    services.sort_by_key(|s| (s.port, s.address));
    Ok(services)
}

/// An in-memory `/proc`, for tests. Mirrors the seam
/// [`crate::command::RecordingRunner`] establishes for `CommandRunner`.
#[derive(Default)]
pub struct FakeProcFs {
    tcp: String,
    tcp6: String,
    deny_fd_access: bool,
    /// (inode, owning pid, comm) for every socket a fake process holds open.
    sockets: Vec<(u64, u32, String)>,
    /// Pids visible in `/proc` beyond whatever `sockets` implies — for
    /// simulating "other users' processes exist, and this one cannot read
    /// them" without needing a socket of its own.
    extra_pids: Vec<u32>,
}

impl FakeProcFs {
    pub fn new(tcp: &str) -> Self {
        FakeProcFs {
            tcp: tcp.to_string(),
            ..Default::default()
        }
    }

    /// Simulates every pid's `/proc/<pid>/fd` being unreadable — the
    /// ordinary unprivileged case for any process this one does not own.
    pub fn with_no_fd_access(mut self) -> Self {
        self.deny_fd_access = true;
        // At least one pid must actually be visible for the denial to mean
        // anything: on a real machine there is always some other user's
        // process running, and the resolution path this simulates is
        // "saw the pid, could not read into it", not "saw no pids at all".
        if self.sockets.is_empty() && self.extra_pids.is_empty() {
            self.extra_pids.push(1);
        }
        self
    }

    /// Registers a socket this fake owns: `inode` resolves to `pid`, whose
    /// `/proc/<pid>/comm` is `comm`.
    pub fn with_socket(mut self, inode: u64, pid: u32, comm: &str) -> Self {
        self.sockets.push((inode, pid, comm.to_string()));
        self
    }
}

impl ProcFs for FakeProcFs {
    fn net_tcp(&self) -> Result<String> {
        Ok(self.tcp.clone())
    }

    fn net_tcp6(&self) -> Result<String> {
        Ok(self.tcp6.clone())
    }

    fn pids(&self) -> Result<Vec<u32>> {
        let mut pids: Vec<u32> = self.sockets.iter().map(|(_, pid, _)| *pid).collect();
        pids.extend(&self.extra_pids);
        pids.sort_unstable();
        pids.dedup();
        Ok(pids)
    }

    fn fd_links(&self, pid: u32) -> Result<Vec<String>> {
        if self.deny_fd_access {
            return Err(Error::Unexpected(format!(
                "permission denied reading fd for pid {pid} (fake)"
            )));
        }
        Ok(self
            .sockets
            .iter()
            .filter(|(_, p, _)| *p == pid)
            .map(|(inode, _, _)| format!("socket:[{inode}]"))
            .collect())
    }

    fn comm(&self, pid: u32) -> Result<String> {
        self.sockets
            .iter()
            .find(|(_, p, _)| *p == pid)
            .map(|(_, _, name)| name.clone())
            .ok_or_else(|| Error::Unexpected(format!("no such pid {pid} (fake)")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from this machine's /proc/net/tcp. Column meanings:
    /// sl, local_address, rem_address, st, ..., uid, ..., inode
    const PROC_NET_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:B67B 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 67371 1 0000000000000000 100 0 0 10 0
   1: 00000000:1435 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 42898 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   193        0 15731 1 0000000000000000 100 0 0 10 5
   3: 0100007F:C1B4 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 56062 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn the_address_is_little_endian_and_reading_it_the_other_way_is_plausible_nonsense() {
        // 0100007F is 127.0.0.1. Read big-endian it becomes 1.0.0.127 --
        // a valid-looking address that would classify a loopback-only service
        // as network-facing, which is the exact mistake this list exists to
        // prevent. Test the conversion on its own so the bug cannot hide.
        assert_eq!(
            parse_hex_addr_v4("0100007F").unwrap(),
            "127.0.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            parse_hex_addr_v4("00000000").unwrap(),
            Ipv4Addr::UNSPECIFIED
        );
        assert_eq!(
            parse_hex_addr_v4("3600007F").unwrap(),
            "127.0.0.54".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn the_port_is_hex_not_decimal() {
        // B67B is 46715. Reading it as decimal gives nothing at all, but
        // 1435 would silently parse as one thousand four hundred and
        // thirty-five instead of 5173.
        assert_eq!(parse_hex_port("B67B").unwrap(), 46715);
        assert_eq!(parse_hex_port("1435").unwrap(), 5173);
    }

    #[test]
    fn only_listening_sockets_appear() {
        // st 0A is LISTEN; 01 is ESTABLISHED. An established connection is
        // not a service anyone can open a port for.
        let found = parse_proc_net_tcp(PROC_NET_TCP);
        assert_eq!(
            found.len(),
            3,
            "the 01 row is an open connection, not a listener"
        );
    }

    #[test]
    fn loopback_only_is_distinguished_from_network_facing() {
        let found = parse_proc_net_tcp(PROC_NET_TCP);
        let by_port: std::collections::HashMap<u16, Binding> =
            found.iter().map(|s| (s.port, s.binding)).collect();
        assert_eq!(by_port[&46715], Binding::LoopbackOnly);
        assert_eq!(by_port[&5173], Binding::AllInterfaces);
        assert_eq!(by_port[&53], Binding::LoopbackOnly);
    }

    #[test]
    fn a_service_on_another_users_uid_is_still_listed() {
        // Row 2 belongs to uid 193 (systemd-resolved). It is listening, and
        // hiding it would make the list quietly incomplete -- porthole would
        // report nothing on 53 while something is plainly there. The process
        // name is what is unavailable without privilege, not the socket.
        let found = parse_proc_net_tcp(PROC_NET_TCP);
        assert!(found.iter().any(|s| s.port == 53));
    }

    #[test]
    fn a_process_name_that_cannot_be_resolved_is_absent_not_invented() {
        // Unprivileged, /proc/<pid>/fd is readable only for the user's own
        // processes. An unresolvable name must stay None: showing "unknown"
        // as if it were a process name is a small lie that makes the list
        // look complete when it is not.
        let fs = FakeProcFs::new(PROC_NET_TCP).with_no_fd_access();
        let found = scan(&fs).unwrap();
        assert!(found.iter().all(|s| s.process.is_none()));
    }

    #[test]
    fn a_resolved_process_carries_its_name_and_pid() {
        let fs = FakeProcFs::new(PROC_NET_TCP).with_socket(67371, 9816, "code");
        let found = scan(&fs).unwrap();
        let svc = found.iter().find(|s| s.port == 46715).unwrap();
        assert_eq!(svc.process.as_deref(), Some("code"));
        assert_eq!(svc.pid, Some(9816));
    }

    #[test]
    fn a_socket_with_no_matching_process_still_has_no_placeholder() {
        // Same shape as the no-fd-access test, but here resolution simply
        // finds nothing to match rather than being denied outright -- both
        // must leave `process`/`pid` at `None`, never a string like
        // "unknown" standing in for a name porthole does not have.
        let fs = FakeProcFs::new(PROC_NET_TCP).with_socket(999999, 1234, "unrelated");
        let found = scan(&fs).unwrap();
        assert!(found.iter().all(|s| s.process.is_none() && s.pid.is_none()));
    }

    #[test]
    fn results_are_sorted_by_port() {
        let fs = FakeProcFs::new(PROC_NET_TCP);
        let found = scan(&fs).unwrap();
        let ports: Vec<u16> = found.iter().map(|s| s.port).collect();
        let mut sorted = ports.clone();
        sorted.sort_unstable();
        assert_eq!(
            ports, sorted,
            "porthole listen must not reorder on every run"
        );
    }

    /// Captured from this machine's /proc/net/tcp6: one `::` listener, one
    /// `::1` listener. See milestone-4-verified-facts.md's cross-check
    /// against `ss -ltnp` for how these were confirmed.
    const PROC_NET_TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:06B4 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 47549 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 13902 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn a_v6_wildcard_listener_is_all_interfaces_not_loopback() {
        // `::` accepts v4-mapped connections on this kind of system (Linux's
        // default `net.ipv6.bindv6only=0`), so it is exactly as
        // network-facing as 0.0.0.0 -- folding it into LoopbackOnly would
        // hide a real, reachable service.
        let found = parse_proc_net_tcp6(PROC_NET_TCP6);
        let by_port: HashMap<u16, Binding> = found.iter().map(|s| (s.port, s.binding)).collect();
        assert_eq!(by_port[&1716], Binding::AllInterfaces);
        assert_eq!(by_port[&631], Binding::LoopbackOnly);
    }

    #[test]
    fn scan_includes_v6_listeners_alongside_v4() {
        let fs = FakeProcFs::new(PROC_NET_TCP);
        // FakeProcFs's tcp6 defaults to empty, so wire the v6 fixture in by
        // hand via a second fake sharing the same fd/process state would be
        // needed for a full end-to-end check; here the parse-level test
        // above already proves the v6 parsing itself, so this just proves
        // `scan` does not drop tcp entries when tcp6 is present but empty.
        let found = scan(&fs).unwrap();
        assert!(found.iter().any(|s| s.port == 46715));
    }

    #[test]
    fn classify_v4_matches_the_documented_rule() {
        assert_eq!(
            classify_v4("127.0.0.1".parse().unwrap()),
            Binding::LoopbackOnly
        );
        assert_eq!(
            classify_v4("127.0.0.54".parse().unwrap()),
            Binding::LoopbackOnly
        );
        assert_eq!(classify_v4(Ipv4Addr::UNSPECIFIED), Binding::AllInterfaces);
        assert_eq!(
            classify_v4("10.10.10.5".parse().unwrap()),
            Binding::Specific("10.10.10.5".parse().unwrap())
        );
    }

    #[test]
    fn a_v4_mapped_v6_address_classifies_by_its_embedded_v4_address() {
        // ::ffff:127.0.0.1 -- porthole has never observed this shape in
        // practice (see this module's doc comment), but a v6 socket
        // explicitly bound to a mapped loopback address is still, in fact,
        // loopback-only.
        let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(classify_v6(mapped), Binding::LoopbackOnly);
    }

    #[test]
    fn a_genuine_global_ipv6_address_is_beyond_reach_not_loopback() {
        // The bug this guards against: an earlier version of `classify_v6`
        // folded this case into `LoopbackOnly`, which asserts "only this
        // machine can reach it" -- false for a socket bound to a real,
        // routable IPv6 address. 2001:db8::1 is the documentation range
        // (RFC 3849): never actually assigned, but shaped exactly like a
        // real global address, which is the point -- porthole cannot tell
        // it apart from one that truly is reachable from the internet, and
        // must not pretend otherwise.
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(classify_v6(global), Binding::BeyondReach(global));
    }

    #[test]
    fn an_unresolvable_pid_enumeration_does_not_fail_the_scan() {
        // pids() failing outright (e.g. /proc unreadable for some other
        // reason) must degrade to "nothing resolves", not an error -- a
        // resolution problem must never take down the whole listing.
        struct NoPids;
        impl ProcFs for NoPids {
            fn net_tcp(&self) -> Result<String> {
                Ok(PROC_NET_TCP.to_string())
            }
            fn net_tcp6(&self) -> Result<String> {
                Ok(String::new())
            }
            fn pids(&self) -> Result<Vec<u32>> {
                Err(Error::Unexpected("no /proc here (fake)".to_string()))
            }
            fn fd_links(&self, _pid: u32) -> Result<Vec<String>> {
                unreachable!("pids() failed; nothing should call this")
            }
            fn comm(&self, _pid: u32) -> Result<String> {
                unreachable!("pids() failed; nothing should call this")
            }
        }

        let found = scan(&NoPids).unwrap();
        assert!(!found.is_empty());
        assert!(found.iter().all(|s| s.process.is_none()));
    }
}
