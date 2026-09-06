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

    /// Who to open towards: subnet, any, a CIDR, or an IP address.
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
    /// rule is still closed automatically once that backend is current
    /// again (reconciliation proves it is theirs and sweeps it as an
    /// orphan); a forgotten firewalld rule is not -- firewalld can never
    /// prove a rule is its own, so nothing ever closes it, permanently.
    #[arg(long, requires = "id")]
    pub forget: bool,
}
