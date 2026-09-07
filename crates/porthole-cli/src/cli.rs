//! The command line.
//!
//! Arguments arrive as strings and are validated by `porthole_core::validate`
//! rather than by clap's own parsers, so the CLI and the future D-Bus helper
//! reject the same things with the same words.

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "porthole",
    version,
    about = "Open a port to your local network, temporarily and on purpose.",
    long_about = "porthole opens a single port towards the network you are on right now, \
                  for a bounded amount of time, and closes it again by itself.\n\n\
                  It never writes permanent firewall rules, so a reboot closes everything. \
                  It is not a firewall manager: for zones, services and permanent rules, \
                  use your distribution's firewall tool."
)]
pub struct Cli {
    /// Print machine-readable JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Show what would happen without changing anything. Needs no privileges.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Talk to a helper on the session bus instead of the system bus.
    /// For tests: the real helper serves the system bus.
    #[arg(long, global = true, hide = true)]
    pub session: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Open a port towards the local network.
    Open(OpenArgs),
    /// Close a port porthole opened.
    Close(CloseArgs),
    /// List the ports porthole currently has open.
    List,
    /// Show the firewall backend, the current network, and what is open.
    Status,
    /// Diagnose why porthole is not working: firewall, helper, polkit,
    /// network, Docker, and IPv6.
    Doctor,
    /// List TCP services listening on this machine, so you can pick a port
    /// instead of typing one. Marks loopback-only services separately
    /// (opening the firewall for those changes nothing) from ones reachable
    /// only over IPv6 (porthole manages IPv4 rules only, and can neither
    /// open nor close those).
    Listen,
    /// Manage saved devices, so `--to <name>` can open towards one instead of
    /// typing its address by hand.
    Devices {
        #[command(subcommand)]
        command: DevicesCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum DevicesCommand {
    /// List saved devices and whether each resolves on this network right
    /// now.
    List,
    /// Save a device, picked from the machines currently seen on this
    /// network.
    Add,
    /// Forget a saved device.
    Rm {
        /// The device's name, as shown by `devices list`.
        name: String,
    },
}

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

#[derive(Debug, Args)]
pub struct OpenArgs {
    /// Port to open, 1-65535.
    pub port: String,

    /// Protocol: tcp or udp.
    #[arg(long, default_value = "tcp")]
    pub proto: String,

    /// How long to keep it open: 15m, 1h, 4h. Maximum 8h. Defaults to 1h.
    #[arg(long = "for", id = "duration", conflicts_with = "until_reboot")]
    pub duration: Option<String>,

    /// Keep it open until the machine reboots.
    #[arg(long)]
    pub until_reboot: bool,

    /// Who to open towards: subnet, any, a CIDR, an IP address, or the name
    /// of a device saved with `porthole devices add`.
    #[arg(long, default_value = "subnet")]
    pub to: String,
}

#[derive(Debug, Args)]
pub struct CloseArgs {
    /// Port to close.
    #[arg(conflicts_with_all = ["id", "all"])]
    pub port: Option<String>,

    /// Protocol of the port to close.
    #[arg(long, default_value = "tcp")]
    pub proto: String,

    /// Close the rule with this id, as shown by `porthole list --json`.
    #[arg(long, conflicts_with_all = ["port", "all"])]
    pub id: Option<String>,

    /// Close every port porthole has open.
    #[arg(long, conflicts_with_all = ["port", "id"])]
    pub all: bool,

    /// Set when the expiry timer invokes the close. Not for humans.
    #[arg(long, hide = true)]
    pub from_timer: bool,

    /// Drop the record of a rule without touching any firewall.
    ///
    /// Only for a rule recorded under a backend this machine no longer has
    /// (`porthole list`/`--json` names it): reconciliation never removes
    /// such an entry on its own, since it may still be sitting in whatever
    /// firewall created it, and an ordinary `close` cannot reach it through
    /// the backend now detected. Refused for anything else -- forgetting a
    /// rule the current backend could actually close would leave it
    /// enforced with no record left able to close it later.
    ///
    /// Not the same outcome on every backend: a forgotten ufw or nftables
    /// rule is still closed automatically by the next `open` or `close` run
    /// while that backend is current (reconciliation proves it is theirs and
    /// sweeps it as an orphan) -- `status` and `list` will not, since they
    /// never touch the firewall. A forgotten firewalld rule is never closed
    /// at all: firewalld cannot prove a rich rule is its own, so no sweep
    /// ever runs there.
    #[arg(long, requires = "id")]
    pub forget: bool,
}
