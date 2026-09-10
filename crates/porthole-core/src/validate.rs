//! Validation of untrusted input.
//!
//! Everything here takes a `&str` from a command line or a D-Bus message and
//! returns a domain type, or an error. The privileged side runs these on its
//! own rather than trusting a client to have done it: a compromised client must
//! not be able to inject an arbitrary rule.

use crate::error::{Error, Result};
use crate::model::{Protocol, ScopeSpec, MAX_DURATION};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// Parse a port number. Valid range is 1-65535; port 0 is not a real port.
pub fn parse_port(raw: &str) -> Result<u16> {
    let port: u32 = raw
        .parse()
        .map_err(|_| Error::InvalidArgument(format!("`{raw}` is not a port number")))?;
    if !(1..=65535).contains(&port) {
        return Err(Error::InvalidArgument(format!(
            "port {port} is out of range; valid ports are 1-65535"
        )));
    }
    Ok(port as u16)
}

/// Parse a protocol from the closed list `tcp` / `udp`.
pub fn parse_protocol(raw: &str) -> Result<Protocol> {
    match raw.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        other => Err(Error::InvalidArgument(format!(
            "`{other}` is not a supported protocol; use tcp or udp"
        ))),
    }
}

/// Parse a duration written as an integer plus a `s`, `m` or `h` suffix.
///
/// One value and one unit: `90m`, never `1h30m`. The grammar is deliberately
/// this small because this runs on the privileged side, where every accepted
/// input shape is attack surface.
///
/// Rejects zero, and rejects anything above [`MAX_DURATION`]. The ceiling is a
/// product decision, not a limitation: see `MAX_DURATION`.
pub fn parse_duration(raw: &str) -> Result<Duration> {
    let invalid = || {
        Error::InvalidArgument(format!(
            "`{raw}` is not a duration; use a number followed by s, m or h (for example 30m, 1h)"
        ))
    };

    let (value, unit_secs) = match raw.as_bytes().last() {
        Some(b's') => (&raw[..raw.len() - 1], 1u64),
        Some(b'm') => (&raw[..raw.len() - 1], 60),
        Some(b'h') => (&raw[..raw.len() - 1], 3600),
        _ => return Err(invalid()),
    };

    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }

    let amount: u64 = value.parse().map_err(|_| invalid())?;
    let secs = amount.checked_mul(unit_secs).ok_or_else(invalid)?;

    if secs == 0 {
        return Err(Error::InvalidArgument(
            "a duration of zero would open nothing; use at least 1s".to_string(),
        ));
    }

    let duration = Duration::from_secs(secs);
    if duration > MAX_DURATION {
        // The ceiling is read off `MAX_DURATION` rather than written down a
        // second time, the same way `open_dialog`'s ceiling chip is: lowering
        // the constant lowers this sentence with it, instead of leaving it
        // claiming eight hours while refusing at four.
        let hours = MAX_DURATION.as_secs() / 3600;
        // And it names the lifetime rather than any one surface's spelling of
        // it. `--until-reboot` is the CLI's spelling; the GUI's is a chip
        // labelled "Until reboot", and this exact string is what
        // `porthole-gui`'s custom-duration field puts on screen -- it renders
        // whatever `parse_duration` returns. A flag in a window is an
        // instruction its reader cannot carry out.
        //
        // "the only longer choice" is what `Lifetime` has: `For`, capped
        // here, and `UntilReboot`. There is no third.
        return Err(Error::InvalidArgument(format!(
            "{raw} is longer than the {hours} hours porthole allows; \
             the only longer choice is until reboot, which lasts \
             for the rest of the session"
        )));
    }

    Ok(duration)
}

/// Parse `--to`: `subnet`, `any`, a CIDR, or a bare IPv4 address.
///
/// A CIDR with host bits set is normalised to its network address, so
/// `10.10.10.42/24` means `10.10.10.0/24`.
pub fn parse_scope(raw: &str) -> Result<ScopeSpec> {
    match raw {
        "subnet" => return Ok(ScopeSpec::CurrentSubnet),
        "any" => return Ok(ScopeSpec::Anywhere),
        "" => {
            return Err(Error::InvalidArgument(
                "empty scope; use subnet, any, a CIDR or an IP address".to_string(),
            ))
        }
        _ => {}
    }

    if raw.contains('/') {
        if let Ok(net) = raw.parse::<Ipv4Net>() {
            return Ok(ScopeSpec::Network(net.trunc()));
        }
        if raw.parse::<ipnet::Ipv6Net>().is_ok() {
            return Err(ipv6_unsupported(raw));
        }
        return Err(Error::InvalidArgument(format!(
            "`{raw}` is not a valid IPv4 network"
        )));
    }

    match raw.parse::<IpAddr>() {
        Ok(IpAddr::V4(addr)) => Ok(ScopeSpec::Host(addr)),
        Ok(IpAddr::V6(_)) => Err(ipv6_unsupported(raw)),
        Err(_) => Err(Error::InvalidArgument(format!(
            "`{raw}` is not a network, an IP address, `subnet` or `any`"
        ))),
    }
}

fn ipv6_unsupported(raw: &str) -> Error {
    Error::InvalidArgument(format!(
        "`{raw}` is IPv6, and porthole v1 only manages IPv4 rules. \
         On a network with IPv6 enabled, opening or closing an IPv4 port says \
         nothing about IPv6 reachability."
    ))
}

/// Widen a single host into the `/32` network a backend can use.
pub fn host_to_network(addr: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(addr, 32).expect("32 is a valid IPv4 prefix length")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn accepts_ports_in_range() {
        assert_eq!(parse_port("1").unwrap(), 1);
        assert_eq!(parse_port("5173").unwrap(), 5173);
        assert_eq!(parse_port("65535").unwrap(), 65535);
    }

    #[test]
    fn rejects_ports_out_of_range() {
        for bad in ["0", "65536", "-1", "", "http", "5173 ", " 5173"] {
            assert!(parse_port(bad).is_err(), "expected {bad:?} to be rejected");
        }
    }

    #[test]
    fn accepts_the_closed_protocol_list_case_insensitively() {
        assert_eq!(parse_protocol("tcp").unwrap(), Protocol::Tcp);
        assert_eq!(parse_protocol("TCP").unwrap(), Protocol::Tcp);
        assert_eq!(parse_protocol("udp").unwrap(), Protocol::Udp);
    }

    #[test]
    fn rejects_protocols_outside_the_list() {
        for bad in ["sctp", "icmp", "", "tcp,udp", "all"] {
            assert!(
                parse_protocol(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn parses_duration_suffixes() {
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("8h").unwrap(), Duration::from_secs(28800));
    }

    #[test]
    fn rejects_zero_unsuffixed_and_compound_durations() {
        // "8h1s" and "1h30m" are compound durations. porthole takes one value
        // and one unit: write 90m, not 1h30m. Keeping the grammar this small
        // matters because this code runs on the privileged side.
        for bad in [
            "0m", "0", "", "h", "1", "1d", "-5m", "1.5h", "1 h", "8h1s", "1h30m",
        ] {
            assert!(
                parse_duration(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn enforces_the_eight_hour_ceiling() {
        assert!(parse_duration("8h").is_ok());
        // Exactly one second over the ceiling, written with a single unit.
        // porthole takes one value and one unit — never a compound like "8h1s".
        let err = parse_duration("28801s").unwrap_err();
        // "until reboot", not "--until-reboot": the message is read in a GUI
        // dialog as well as on a terminal, and the flag is only one surface's
        // name for the lifetime. A test pinning the flag spelling is what
        // would have to be re-blessed to put it back.
        assert!(err.to_string().contains("until reboot"), "got: {err}");
        assert!(
            !err.to_string().contains("--until-reboot"),
            "the message must name no surface's flag: {err}"
        );
        assert!(parse_duration("481m").is_err());
        assert!(parse_duration("24h").is_err());
    }

    #[test]
    fn duration_ceiling_message_names_the_limit() {
        // The literal stays here while `parse_duration` derives it from
        // `MAX_DURATION`, which is the pairing that makes the derivation
        // worth having: lowering the constant changes the message and fails
        // this, rather than leaving a sentence that promises eight hours
        // above a refusal at four. Same arrangement as `open_dialog`'s
        // `the_ceiling_option_is_built_from_the_shared_max_duration_constant`.
        let err = parse_duration("24h").unwrap_err().to_string();
        assert!(err.contains("8 hours"), "got: {err}");
        assert_eq!(MAX_DURATION.as_secs(), 8 * 3600, "the literal above");
    }

    #[test]
    fn parses_scope_keywords() {
        assert_eq!(parse_scope("subnet").unwrap(), ScopeSpec::CurrentSubnet);
        assert_eq!(parse_scope("any").unwrap(), ScopeSpec::Anywhere);
    }

    #[test]
    fn parses_networks_and_hosts() {
        assert_eq!(
            parse_scope("10.10.10.0/24").unwrap(),
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap())
        );
        assert_eq!(
            parse_scope("10.10.10.42").unwrap(),
            ScopeSpec::Host("10.10.10.42".parse().unwrap())
        );
    }

    #[test]
    fn normalises_a_cidr_with_host_bits_set() {
        // 10.10.10.42/24 means the 10.10.10.0/24 network. Do not open towards a
        // string the user did not mean.
        assert_eq!(
            parse_scope("10.10.10.42/24").unwrap(),
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap())
        );
    }

    #[test]
    fn rejects_ipv6_with_a_message_that_says_so() {
        let err = parse_scope("fe80::1").unwrap_err().to_string();
        assert!(err.contains("IPv6"), "got: {err}");
        let err = parse_scope("2001:db8::/32").unwrap_err().to_string();
        assert!(err.contains("IPv6"), "got: {err}");
    }

    #[test]
    fn rejects_nonsense_scopes() {
        for bad in ["", "10.10.10.0/33", "not-an-address", "10.10.10.0/"] {
            assert!(parse_scope(bad).is_err(), "expected {bad:?} to be rejected");
        }
    }
}
