//! Saved devices: an address book so a person can open a port "towards my
//! phone" instead of typing its address by hand.
//!
//! Devices are named by MAC address, not IP: under DHCP the phone gets a
//! different address, and a rule aimed at yesterday's address is useless --
//! or worse, aimed at whatever device holds that address today. So a saved
//! device records its MAC (or, for something worth naming by hostname
//! instead, an mDNS/DNS name) and [`resolve`] turns that into an address at
//! the moment a port is actually opened, never earlier.
//!
//! The book lives client-side, at [`default_path`] -- the privileged helper
//! never reads it. Resolution happens here, in the unprivileged CLI, before
//! anything crosses the D-Bus boundary, which is what keeps the helper's own
//! validation surface small: it only ever sees an already-resolved IP.

use crate::command::{Command, CommandRunner};
use crate::error::{Error, Result};
use crate::net;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Test-only override of the address book's location. Honoured in debug
/// builds only, the same way [`crate::state::STATE_FILE_ENV`] overrides the
/// runtime state path -- a release binary must not take a config path from
/// the environment.
pub const DEVICES_FILE_ENV: &str = "PORTHOLE_DEVICES_FILE";

/// How a saved device's current address is found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceAddress {
    /// Looked up in the kernel's neighbour table -- see [`resolve`].
    Mac(String),
    /// Looked up through the system resolver, e.g. an mDNS `.local` name.
    Host(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub address: DeviceAddress,
}

/// A saved device plus whether it resolves on this network right now -- the
/// address alone does not say whether it is reachable today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStatus {
    pub device: Device,
    pub resolved: Option<Ipv4Addr>,
}

/// The address book. A flat list: nothing here is large enough to need an
/// index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Book {
    devices: Vec<Device>,
}

impl Book {
    pub fn from_devices(devices: Vec<Device>) -> Book {
        Book { devices }
    }

    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    pub fn find(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }

    /// Save a device, replacing any existing one with the same name.
    pub fn add(&mut self, device: Device) {
        self.devices.retain(|d| d.name != device.name);
        self.devices.push(device);
    }

    /// Forget a device. `true` if one was actually there to forget.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.name != name);
        self.devices.len() != before
    }

    /// Load the book, or start empty if the file does not exist yet.
    ///
    /// Validates every entry at load time: a name `--to` can actually reach
    /// ([`device_name_problem`]), exactly one of `mac`/`host` per device,
    /// and a `mac` that actually looks like one. `devices.toml` is
    /// hand-editable, and failing here -- naming the device -- beats failing
    /// later at resolution time with an error that reads as "the device is
    /// merely absent" when the real problem is the file.
    pub fn load(path: &Path) -> Result<Book> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Book::default()),
            Err(e) => {
                return Err(Error::Unexpected(format!(
                    "could not read {}: {e}",
                    path.display()
                )))
            }
        };
        let raw: RawBook = toml::from_str(&text)
            .map_err(|e| Error::InvalidArgument(format!("{}: {e}", path.display())))?;

        let mut devices = Vec::with_capacity(raw.device.len());
        for entry in raw.device {
            if let Some(problem) = device_name_problem(&entry.name) {
                return Err(Error::InvalidArgument(format!(
                    "{}: {problem}",
                    path.display()
                )));
            }
            let address = match (entry.mac, entry.host) {
                (Some(mac), None) => DeviceAddress::Mac(normalize_mac(&entry.name, &mac)?),
                (None, Some(host)) => DeviceAddress::Host(host),
                (Some(_), Some(_)) => {
                    return Err(Error::InvalidArgument(format!(
                        "device `{}` in {} has both `mac` and `host`; exactly one is allowed",
                        entry.name,
                        path.display()
                    )))
                }
                (None, None) => {
                    return Err(Error::InvalidArgument(format!(
                        "device `{}` in {} has neither `mac` nor `host`; exactly one is \
                         required",
                        entry.name,
                        path.display()
                    )))
                }
            };
            devices.push(Device {
                name: entry.name,
                address,
            });
        }
        Ok(Book { devices })
    }

    /// Write the book atomically: a temporary file in the same directory,
    /// then a rename -- a crash mid-write must not leave a half-written file
    /// that reads as parse-corrupt the next time anything loads it.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Error::Unexpected(format!("could not create {}: {e}", parent.display()))
            })?;
        }

        let raw = RawBook {
            device: self
                .devices
                .iter()
                .map(|d| {
                    let (mac, host) = match &d.address {
                        DeviceAddress::Mac(mac) => (Some(mac.clone()), None),
                        DeviceAddress::Host(host) => (None, Some(host.clone())),
                    };
                    RawDevice {
                        name: d.name.clone(),
                        mac,
                        host,
                    }
                })
                .collect(),
        };
        let text = toml::to_string_pretty(&raw)
            .map_err(|e| Error::Unexpected(format!("could not serialise devices.toml: {e}")))?;

        let temp = path.with_extension("toml.tmp");
        fs::write(&temp, &text)
            .map_err(|e| Error::Unexpected(format!("could not write {}: {e}", temp.display())))?;
        fs::rename(&temp, path)
            .map_err(|e| Error::Unexpected(format!("could not save {}: {e}", path.display())))?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct RawBook {
    #[serde(default, rename = "device")]
    device: Vec<RawDevice>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawDevice {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
}

/// Validate and lower-case a MAC address: six colon-separated hex bytes.
///
/// Public because a MAC reaches the address book two ways -- picked out of
/// the neighbour table, where it can only ever be one this machine has
/// already seen, and typed by hand, where it can be anything. Both are held
/// to this one rule, in one place, so a MAC one of them accepts is never
/// one [`Book::load`] then refuses.
///
/// The error names the offending text and the shape expected, and nothing
/// about where it came from: [`normalize_mac`] adds the device it belongs
/// to, and a caller reading a field a person is still typing has no device
/// to name yet.
pub fn parse_mac(raw: &str) -> Result<String> {
    let bytes: Vec<&str> = raw.split(':').collect();
    let valid = bytes.len() == 6
        && bytes
            .iter()
            .all(|b| b.len() == 2 && b.chars().all(|c| c.is_ascii_hexdigit()));
    if !valid {
        return Err(Error::InvalidArgument(format!(
            "`{raw}` is not a MAC address; expected six colon-separated hex bytes, \
             e.g. bc:24:11:5e:1c:6e"
        )));
    }
    Ok(raw.to_ascii_lowercase())
}

/// [`parse_mac`], with the device the MAC was written against named -- what
/// a book being loaded can say and a field being typed into cannot.
fn normalize_mac(device_name: &str, raw: &str) -> Result<String> {
    parse_mac(raw)
        .map_err(|e| Error::InvalidArgument(format!("device `{device_name}` has a bad mac: {e}")))
}

/// Why this name cannot be used, or `None` when it can.
///
/// `--to` reads the scope grammar first and consults the address book only
/// when that grammar rejects the string. So a name the grammar *accepts* --
/// `subnet`, `any`, an IP address, a CIDR -- is taken as a scope, and the
/// saved device behind it is never looked for. A name containing `/` or `:`
/// is read as a failed attempt at that same grammar and reported as one,
/// in words about networks and IPv6 that never mention devices.
///
/// Either way the device is saveable and then permanently unusable, which
/// is why both are refused where a name is chosen ([`validate_device_name`])
/// and where one is read back ([`Book::load`]).
fn device_name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("a device needs a name".to_string());
    }
    if crate::validate::parse_scope(name).is_ok() {
        return Some(format!(
            "`{name}` is already a scope, so `--to {name}` opens towards that scope and \
             never looks for a saved device; pick a different name"
        ));
    }
    if name.contains('/') || name.contains(':') {
        return Some(format!(
            "device name `{name}` contains `/` or `:`, which `--to` reads as a network \
             or an IP address rather than a name, so the device could never be reached; \
             pick a different name"
        ));
    }
    None
}

/// Reject a device name that `--to` could never reach -- see
/// [`device_name_problem`] for which names those are and why.
pub fn validate_device_name(name: &str) -> Result<()> {
    match device_name_problem(name) {
        Some(problem) => Err(Error::InvalidArgument(problem)),
        None => Ok(()),
    }
}

/// Where the book lives by default: `~/.config/porthole/devices.toml`
/// (honouring `$XDG_CONFIG_HOME` when it is set), overridable in debug builds
/// only via [`DEVICES_FILE_ENV`].
pub fn default_path() -> PathBuf {
    default_path_from(
        std::env::var(DEVICES_FILE_ENV).ok().as_deref(),
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// [`default_path`]'s decision, split out so it can be tested without
/// mutating process-global environment state -- see
/// `crate::state::state_path_from`'s own doc comment for why that matters
/// under a parallel test runner.
fn default_path_from(
    override_value: Option<&str>,
    xdg_config_home: Option<&str>,
    home: Option<&str>,
) -> PathBuf {
    if cfg!(debug_assertions) {
        if let Some(path) = override_value {
            if !path.is_empty() {
                return PathBuf::from(path);
            }
        }
    }
    let base = match xdg_config_home {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => match home {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir).join(".config"),
            _ => PathBuf::from(".config"),
        },
    };
    base.join("porthole").join("devices.toml")
}

/// Resolve a saved device to the address it holds on this network right now.
///
/// MAC devices are looked up in the kernel's neighbour table
/// ([`net::neighbours`]); an mDNS/hostname device goes through the system
/// resolver via `getent`. Both can fail legitimately -- the device may be
/// asleep, or simply not here -- and that failure is
/// [`Error::DeviceUnreachable`], not a generic error: the device is known,
/// just not on this network, and opening a port towards it would achieve
/// nothing.
pub fn resolve(book: &Book, name: &str, runner: &dyn CommandRunner) -> Result<Ipv4Addr> {
    let device = book.find(name).ok_or_else(|| unknown_device(book, name))?;
    match &device.address {
        DeviceAddress::Mac(mac) => resolve_mac(runner, name, mac),
        DeviceAddress::Host(host) => resolve_host(runner, name, host),
    }
}

/// Every saved device, each with its current resolution attempted -- what
/// `porthole devices list` actually shows.
///
/// Only [`Error::DeviceUnreachable`] becomes `resolved: None`. A lookup that
/// could not be made at all -- `ip` or `getent` that would not spawn or that
/// exited non-zero, or no default route to settle a duplicate MAC with --
/// returns the error instead. Discarding those with `.ok()` folded "there is
/// no such device here right now" together with "porthole could not find
/// out", and `docs/json-schema.md` reads `resolvable: false` narrowly as the
/// first of the two. `listen --json` spends a whole field (`docker_checked`)
/// keeping exactly this pair apart; the cheaper way to keep the promise here
/// is not to make the claim when it was not checked.
///
/// Each of those conditions belongs to the machine rather than to the device,
/// and `resolve` reports the same ones to `porthole open --to <name>`, which
/// has always failed on them. The cost is that one of them ends the listing
/// rather than annotating a row.
pub fn list_status(book: &Book, runner: &dyn CommandRunner) -> Result<Vec<DeviceStatus>> {
    book.devices()
        .iter()
        .map(|d| {
            let resolved = match resolve(book, &d.name, runner) {
                Ok(address) => Some(address),
                Err(Error::DeviceUnreachable(_)) => None,
                Err(e) => return Err(e),
            };
            Ok(DeviceStatus {
                device: d.clone(),
                resolved,
            })
        })
        .collect()
}

fn unknown_device(book: &Book, name: &str) -> Error {
    let known: Vec<&str> = book.devices().iter().map(|d| d.name.as_str()).collect();
    if known.is_empty() {
        Error::InvalidArgument(format!(
            "no saved device named `{name}`; there are no saved devices yet -- see \
             `porthole devices add`"
        ))
    } else {
        Error::InvalidArgument(format!(
            "no saved device named `{name}`; known devices: {}",
            known.join(", ")
        ))
    }
}

fn resolve_mac(runner: &dyn CommandRunner, name: &str, mac: &str) -> Result<Ipv4Addr> {
    let mac = mac.to_ascii_lowercase();
    let neighbours = net::neighbours(runner)?;
    let matches: Vec<&net::Neighbour> = neighbours.iter().filter(|n| n.mac == mac).collect();

    let chosen = match matches.len() {
        0 => None,
        1 => Some(matches[0]),
        _ => {
            // The same MAC on two interfaces -- a laptop docked and on wifi
            // can see the same neighbour twice. Picking arbitrarily would
            // open towards an address that is right only half the time, so
            // the interface actually carrying traffic breaks the tie.
            let default_interface = net::default_route_interface(runner)?;
            matches
                .into_iter()
                .find(|n| n.interface == default_interface)
        }
    };

    chosen.map(|n| n.address).ok_or_else(|| {
        Error::DeviceUnreachable(format!("`{name}` ({mac}) is not on this network right now"))
    })
}

fn resolve_host(runner: &dyn CommandRunner, name: &str, host: &str) -> Result<Ipv4Addr> {
    let cmd = Command::read("getent", ["ahostsv4", host]);
    let out = runner.run(&cmd)?;
    if !out.success() {
        // `getent` says nothing at all for a name it simply cannot find --
        // exit 2, no stdout, no stderr -- so appending its stderr
        // unconditionally ended the message with a colon and nothing after
        // it. Only a `getent` that actually said something gets a colon.
        let detail = out.stderr.trim();
        return Err(Error::DeviceUnreachable(if detail.is_empty() {
            format!("`{name}` ({host}) did not resolve")
        } else {
            format!("`{name}` ({host}) did not resolve: {detail}")
        }));
    }
    out.stdout
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        .ok_or_else(|| {
            Error::DeviceUnreachable(format!(
                "`{name}` ({host}) did not resolve to an IPv4 address"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{Output, RecordingRunner};
    // The one captured `ip -4 neigh show` this crate keeps, rather than a
    // second copy here that could drift from it.
    use crate::net::tests::IP_NEIGH;
    use tempfile::TempDir;

    fn book_with(name: &str, mac: &str) -> Book {
        Book::from_devices(vec![Device {
            name: name.to_string(),
            address: DeviceAddress::Mac(mac.to_string()),
        }])
    }

    fn book_with_host(name: &str, host: &str) -> Book {
        Book::from_devices(vec![Device {
            name: name.to_string(),
            address: DeviceAddress::Host(host.to_string()),
        }])
    }

    #[test]
    fn a_mac_is_matched_case_insensitively() {
        // devices.toml is hand-editable and `ip neigh` prints lower case.
        let book = book_with("phone", "BC:24:11:5E:1C:6E");
        let runner = RecordingRunner::with_responses(vec![Output::stdout(IP_NEIGH)]);
        assert_eq!(
            resolve(&book, "phone", &runner).unwrap(),
            "10.10.10.245".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn a_device_that_is_not_on_this_network_is_unreachable_with_its_own_exit_code() {
        // Not a generic failure: the user needs to know the device is
        // absent, not that porthole broke. Opening towards it would achieve
        // nothing.
        let book = book_with("phone", "aa:bb:cc:dd:ee:ff");
        let runner = RecordingRunner::with_responses(vec![Output::stdout(IP_NEIGH)]);
        let err = resolve(&book, "phone", &runner).unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::DeviceUnreachable);
        assert!(err.to_string().contains("phone"), "got: {err}");
    }

    #[test]
    fn the_same_mac_on_two_interfaces_resolves_to_the_default_route_one() {
        // A laptop docked and on wifi can see the same neighbour twice.
        // Picking arbitrarily would open towards an address that is right
        // half the time.
        let book = book_with("phone", "bc:24:11:5e:1c:6e");
        let neigh = "\
10.10.10.245 dev wlo1 lladdr bc:24:11:5e:1c:6e STALE
192.168.1.50 dev enp0s31f6 lladdr bc:24:11:5e:1c:6e REACHABLE
";
        let route_json = r#"[{"dst":"default","dev":"enp0s31f6","metric":100}]"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(neigh),
            Output::stdout(route_json),
        ]);
        assert_eq!(
            resolve(&book, "phone", &runner).unwrap(),
            "192.168.1.50".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn an_unknown_device_name_lists_the_known_ones() {
        let book = book_with("phone", "bc:24:11:5e:1c:6e");
        let runner = RecordingRunner::with_responses(vec![Output::stdout(IP_NEIGH)]);
        let err = resolve(&book, "tablet", &runner).unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::InvalidArguments);
        assert!(err.to_string().contains("phone"), "say what does exist");
        // Nothing was read: the name was rejected before ever touching the
        // neighbour table.
        assert!(runner.recorded().is_empty());
    }

    #[test]
    fn an_unknown_device_with_an_empty_book_says_there_are_no_devices_yet() {
        let book = Book::default();
        let runner = RecordingRunner::new();
        let err = resolve(&book, "anything", &runner).unwrap_err();
        assert!(err.to_string().contains("devices add"), "got: {err}");
    }

    #[test]
    fn a_device_may_be_saved_as_an_mdns_name_instead_of_a_mac() {
        // Resolution goes through the resolver, not the neighbour table.
        let book = book_with_host("printer", "printer.local");
        let runner = RecordingRunner::with_responses(vec![Output::stdout(
            "10.10.10.55     STREAM printer.local\n10.10.10.55     DGRAM\n10.10.10.55     RAW\n",
        )]);
        let resolved = resolve(&book, "printer", &runner).unwrap();
        assert_eq!(resolved, "10.10.10.55".parse::<Ipv4Addr>().unwrap());

        let commands = runner.recorded();
        assert_eq!(commands.len(), 1, "must not touch the neighbour table");
        assert_eq!(commands[0].program, "getent");
    }

    #[test]
    fn an_mdns_name_that_does_not_resolve_is_device_unreachable() {
        let book = book_with_host("printer", "printer.local");
        let runner = RecordingRunner::with_responses(vec![Output::failure("not found")]);
        let err = resolve(&book, "printer", &runner).unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::DeviceUnreachable);
        assert!(err.to_string().contains("printer"), "got: {err}");
    }

    #[test]
    fn a_silent_getent_failure_does_not_end_the_message_with_a_bare_colon() {
        // What `getent ahostsv4` really does for a name it cannot find,
        // checked on this machine: exit 2, nothing on stdout, nothing on
        // stderr. Appending that empty stderr after a colon left the user
        // reading "... did not resolve: " with nothing after it.
        let book = book_with_host("printer", "printer.local");
        let runner = RecordingRunner::with_responses(vec![Output {
            status: 2,
            stdout: String::new(),
            stderr: String::new(),
        }]);
        let err = resolve(&book, "printer", &runner).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("did not resolve"), "got: {text}");
        assert!(
            !text.trim_end().ends_with(':'),
            "nothing follows the colon: {text}"
        );
    }

    #[test]
    fn a_getent_that_did_say_something_still_passes_it_on() {
        // The other half: when there is a reason, it must not be dropped in
        // the course of suppressing the empty one.
        let book = book_with_host("printer", "printer.local");
        let runner = RecordingRunner::with_responses(vec![Output::failure(
            "getent: unknown database `ahostsv4'",
        )]);
        let err = resolve(&book, "printer", &runner).unwrap_err();
        assert!(err.to_string().contains("unknown database"), "got: {err}");
    }

    #[test]
    fn devices_toml_round_trips_and_rejects_a_malformed_mac_at_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("devices.toml");

        let mut book = Book::default();
        book.add(Device {
            name: "phone".to_string(),
            address: DeviceAddress::Mac("bc:24:11:5e:1c:6e".to_string()),
        });
        book.add(Device {
            name: "printer".to_string(),
            address: DeviceAddress::Host("printer.local".to_string()),
        });
        book.save(&path).unwrap();

        let reloaded = Book::load(&path).unwrap();
        assert_eq!(reloaded.devices().len(), 2);
        assert_eq!(
            reloaded.find("phone").unwrap().address,
            DeviceAddress::Mac("bc:24:11:5e:1c:6e".to_string())
        );
        assert_eq!(
            reloaded.find("printer").unwrap().address,
            DeviceAddress::Host("printer.local".to_string())
        );

        // Failing at load, with the device named, beats a resolution error
        // that looks like the device is merely absent.
        std::fs::write(
            &path,
            "[[device]]\nname = \"broken\"\nmac = \"not-a-mac\"\n",
        )
        .unwrap();
        let err = Book::load(&path).unwrap_err();
        assert!(err.to_string().contains("broken"), "got: {err}");
    }

    #[test]
    fn both_mac_and_host_is_a_load_error_naming_the_device() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("devices.toml");
        std::fs::write(
            &path,
            "[[device]]\nname = \"confused\"\nmac = \"bc:24:11:5e:1c:6e\"\nhost = \"x.local\"\n",
        )
        .unwrap();
        let err = Book::load(&path).unwrap_err();
        assert!(err.to_string().contains("confused"), "got: {err}");
        assert!(err.to_string().contains("both"), "got: {err}");
    }

    #[test]
    fn neither_mac_nor_host_is_a_load_error_naming_the_device() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("devices.toml");
        std::fs::write(&path, "[[device]]\nname = \"empty\"\n").unwrap();
        let err = Book::load(&path).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn a_missing_file_loads_as_an_empty_book() {
        let dir = TempDir::new().unwrap();
        let book = Book::load(&dir.path().join("nope.toml")).unwrap();
        assert!(book.devices().is_empty());
    }

    #[test]
    fn add_replaces_a_device_with_the_same_name() {
        let mut book = book_with("phone", "aa:aa:aa:aa:aa:aa");
        book.add(Device {
            name: "phone".to_string(),
            address: DeviceAddress::Mac("bb:bb:bb:bb:bb:bb".to_string()),
        });
        assert_eq!(book.devices().len(), 1);
        assert_eq!(
            book.find("phone").unwrap().address,
            DeviceAddress::Mac("bb:bb:bb:bb:bb:bb".to_string())
        );
    }

    #[test]
    fn remove_reports_whether_it_actually_removed_something() {
        let mut book = book_with("phone", "aa:aa:aa:aa:aa:aa");
        assert!(book.remove("phone"));
        assert!(!book.remove("phone"));
        assert!(book.devices().is_empty());
    }

    #[test]
    fn list_status_reports_each_devices_current_reachability() {
        let book = Book::from_devices(vec![
            Device {
                name: "phone".to_string(),
                address: DeviceAddress::Mac("bc:24:11:5e:1c:6e".to_string()),
            },
            Device {
                name: "tablet".to_string(),
                address: DeviceAddress::Mac("aa:bb:cc:dd:ee:ff".to_string()),
            },
        ]);
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(IP_NEIGH),
            Output::stdout(IP_NEIGH),
        ]);
        let rows = list_status(&book, &runner).expect("both lookups ran");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].resolved,
            Some("10.10.10.245".parse::<Ipv4Addr>().unwrap())
        );
        assert_eq!(rows[1].resolved, None);
    }

    #[test]
    fn list_status_reports_a_lookup_it_could_not_make_rather_than_calling_it_absent() {
        // `resolvable: false` is documented as "the lookup found nothing here
        // and now". An `ip` that would not run found nothing of the sort, and
        // saying `false` for it would put two different facts behind one
        // value -- the hazard `listen --json`'s `docker_checked` exists for.
        let book = book_with("phone", "bc:24:11:5e:1c:6e");
        let runner = RecordingRunner::with_responses(vec![Output::failure("ip: not found")]);

        let err = list_status(&book, &runner).expect_err("the lookup could not be made");
        assert!(
            matches!(err, Error::CommandFailed { .. }),
            "the command's own failure, not a device verdict: {err:?}"
        );
    }

    #[test]
    fn default_path_prefers_xdg_config_home() {
        assert_eq!(
            default_path_from(None, Some("/x/cfg"), Some("/home/j")),
            PathBuf::from("/x/cfg/porthole/devices.toml")
        );
    }

    #[test]
    fn default_path_falls_back_to_home_dot_config() {
        assert_eq!(
            default_path_from(None, None, Some("/home/j")),
            PathBuf::from("/home/j/.config/porthole/devices.toml")
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn the_devices_file_override_is_honoured_in_debug_builds() {
        assert_eq!(
            default_path_from(
                Some("/tmp/porthole-test/devices.toml"),
                Some("/x"),
                Some("/home/j")
            ),
            PathBuf::from("/tmp/porthole-test/devices.toml")
        );
    }

    #[test]
    fn parse_mac_accepts_what_the_neighbour_table_and_a_typed_field_both_produce() {
        assert_eq!(parse_mac("BC:24:11:5E:1C:6E").unwrap(), "bc:24:11:5e:1c:6e");
        assert_eq!(parse_mac("bc:24:11:5e:1c:6e").unwrap(), "bc:24:11:5e:1c:6e");
    }

    #[test]
    fn parse_mac_refuses_anything_that_is_not_six_hex_bytes() {
        for raw in [
            "",
            "not-a-mac",
            "bc:24:11:5e:1c",
            "bc:24:11:5e:1c:6e:7f",
            "bc:24:11:5e:1c:6g",
            "bc-24-11-5e-1c-6e",
            "bc:24:11:5e:1c:6",
        ] {
            let err = parse_mac(raw).unwrap_err();
            assert!(
                err.to_string().contains(raw),
                "the offending text must be named, got: {err}"
            );
        }
    }

    #[test]
    fn a_bad_mac_in_the_file_still_names_the_device_it_belongs_to() {
        // `parse_mac` names the text and nothing else, since a field being
        // typed into has no device to name yet. Loading a file does, and
        // that is where the device's name is added back.
        let err = normalize_mac("broken", "not-a-mac").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("broken"), "got: {text}");
        assert!(text.contains("not-a-mac"), "got: {text}");
    }

    #[test]
    fn a_name_the_scope_grammar_would_swallow_is_refused() {
        // Each of these reaches `--to` before the address book does, so a
        // device saved under one could never be opened towards.
        for name in ["subnet", "any", "10.0.0.5", "10.0.0.0/24"] {
            let err = validate_device_name(name).unwrap_err();
            assert!(
                err.to_string().contains("scope"),
                "{name} should be refused as a scope, got: {err}"
            );
        }
    }

    #[test]
    fn a_name_containing_a_slash_or_a_colon_is_refused() {
        // The reproduction from the review: `office:pc` saved cleanly, then
        // `open --to office:pc` died with "not a network, an IP address,
        // `subnet` or `any`" -- an error that never mentions devices.
        for name in ["office:pc", "home/laptop", "fe80::1"] {
            let err = validate_device_name(name).unwrap_err();
            assert!(
                err.to_string().contains(name),
                "the offending name must be named, got: {err}"
            );
        }
    }

    #[test]
    fn an_ordinary_name_is_accepted() {
        for name in ["phone", "office pc", "Jacopo's laptop", "printer-2"] {
            validate_device_name(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn a_hand_edited_book_with_an_unreachable_name_fails_at_load_naming_it() {
        // `devices.toml` is hand-editable, so the save-time check is not the
        // only way such a name can arrive. Failing here, naming the device
        // and the file, beats resolving it and reporting "device not found".
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("devices.toml");
        fs::write(
            &path,
            "[[device]]\nname = \"office:pc\"\nmac = \"bc:24:11:5e:1c:6e\"\n",
        )
        .unwrap();

        let err = Book::load(&path).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("office:pc"), "got: {text}");
        assert!(text.contains("devices.toml"), "got: {text}");
    }

    #[test]
    fn an_ordinary_book_still_loads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("devices.toml");
        fs::write(
            &path,
            "[[device]]\nname = \"phone\"\nmac = \"bc:24:11:5e:1c:6e\"\n",
        )
        .unwrap();
        assert_eq!(Book::load(&path).unwrap().devices().len(), 1);
    }
}
