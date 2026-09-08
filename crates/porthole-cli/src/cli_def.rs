// The clap command definition, and nothing else.
//
// Read twice: as a `#[path]` module of `src/cli.rs`, which is what `main`
// parses with, and `include!`d by `build.rs`, which renders the man page and
// the shell completions from it. That is why this file is separate from
// `cli.rs` and why it names no `porthole_core` type -- `build.rs` would
// otherwise need the whole core crate as a build dependency. The parts of the
// command line that do need core (`ToSpec`, `parse_to`) stay in `cli.rs`.
//
// A file of its own rather than a shared crate because a build script cannot
// depend on a library target of the package it belongs to, and `include!` on
// the build.rs side for the same reason. A module rather than a second
// `include!` on the crate side because rustfmt walks `mod` declarations and
// does not expand macros: as an `include!` this file was in no
// `cargo fmt --all`.

use clap::{Args, Parser, Subcommand};

/// Prose the argument parser cannot derive from the flags: what the exit
/// codes mean, what porthole does not do, and the two ways a closed port can
/// still be reachable.
///
/// Hung off the clap command as `after_long_help` so `porthole --help` and
/// `porthole.1` render the same bytes.
pub const AFTER_LONG_HELP: &str = "\
Exit codes:
  0  Success
  1  Unexpected failure
  2  Invalid arguments
  3  An operation needed a usable firewall and there was none.
     `porthole status` does not use this code: it reports the
     situation in its own output and exits 0.
  4  Polkit refused the request. Never `sudo`: the CLI holds no
     privilege of its own to grant.
  5  That port is already open
  6  The named device is not reachable on this network
  7  No porthole-managed rule matches
  8  No usable network
  9  There was nothing to choose from. `porthole devices add` found
     no device on this network to offer.
  10 `porthole forward` was given a port no container publishes, or
     Docker could not be read at all. The message says which.
  11 The port `porthole forward` would give the local network is
     already carrying something a redirect would take traffic from:
     a porthole rule, or a service listening on an address the
     network reaches. A loopback-only listener is not one of them,
     and does not refuse. The message names `--as <PORT>`, which is
     what gives the local network a different port.
  12 This machine's firewall has no way to redirect a port.
  13 A check porthole makes before creating a redirect has no answer
     for what was asked. The message says which check.
  14 Docker publishes that container on an address other than
     loopback, so the local network may already reach it. That is
     Docker's own rule, and porthole can neither have made it nor
     close it. What porthole read to decide this is the `-d` flag on
     Docker's own DNAT rule for the port, and nothing else: no `-d`
     is every interface, and a `-d` naming any other address is that
     address, whether or not this machine holds it.

No permanent rules:
  Every rule porthole writes is a runtime rule, so a reboot closes
  everything it opened, and a timed opening is capped at eight
  hours. porthole does not do zones, services or permanent rules;
  for those, use firewall-config, ufw or nft directly. The one
  redirect it writes is `porthole forward`'s, and that is a runtime
  rule with a timer like every other.

Docker:
  Docker publishes container ports through iptables rules of its
  own, ahead of anything porthole writes. A port published on every
  interface is reachable whether or not porthole has opened it, and
  porthole can neither open nor close it. A port published on this
  machine's loopback address is reachable from this machine only,
  and `porthole forward` is what redirects an external port to the
  container behind it, for a bounded time. `porthole doctor` lists
  the published ports it can see, and `porthole listen` marks the
  listeners behind them.

IPv6:
  porthole manages IPv4 rules only. On a machine with a global IPv6
  address, a service listening on IPv6 stays reachable over IPv6
  whatever porthole has open or closed. `porthole listen` marks
  IPv6-only listeners and `porthole doctor` warns when this machine
  has a global IPv6 address. A port porthole reports as closed is
  not on its own evidence that nothing can reach it.
";

#[derive(Debug, Parser)]
#[command(
    name = "porthole",
    version,
    about = "Open a port to your local network, temporarily and on purpose.",
    long_about = "porthole opens a single port towards the network you are on right now, \
                  for a bounded amount of time, and closes it again by itself.\n\n\
                  It never writes permanent firewall rules, so a reboot closes everything. \
                  It is not a firewall manager: for zones, services and permanent rules, \
                  use your distribution's firewall tool.",
    after_long_help = AFTER_LONG_HELP
)]
pub struct Cli {
    /// Print machine-readable JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Show what would happen without changing anything. Needs no privileges,
    /// except for `forward`: that one reads Docker's own rules itself, which
    /// needs root, and exits 10 without it.
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
    /// Redirect a port to a Docker container published only on this machine,
    /// so the local network can reach it for a bounded time.
    ///
    /// A separate command from `open`, and not a flag on it, because the
    /// consequence is different: `open` permits traffic to something already
    /// listening on the network, and this redirects traffic to something
    /// that was not. It asks for permission every time.
    ///
    /// There is no --proto: every forward is TCP. Before creating a redirect
    /// porthole checks whether something on this machine already answers on
    /// the port the local network would connect to, and that check reads TCP
    /// sockets only -- so a UDP request is refused rather than made with the
    /// check having compared against nothing.
    Forward(ForwardArgs),
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

/// `porthole forward`'s own arguments.
///
/// Two port numbers, and which is which is the whole of this command's
/// surface: `port` is the one already on this machine, `--as` is the one the
/// local network will see.
///
/// There is no `--proto`. Every request this command sends is a TCP one, and
/// there is no UDP forward to ask for: the check porthole makes before
/// creating one -- whether something on this machine already answers on the
/// external port -- reads TCP only, so a UDP request is refused.
///
/// No `--until-reboot` either, unlike `open`: a forward always runs out, and
/// `--for` is what sets when, under `open`'s own eight-hour ceiling.
#[derive(Debug, Args)]
pub struct ForwardArgs {
    /// The port to forward, as `porthole listen` shows it: the one Docker
    /// published on this machine.
    pub port: String,

    /// The port the local network connects to. Defaults to the port being
    /// forwarded.
    #[arg(long = "as", value_name = "PORT")]
    pub as_port: Option<String>,

    /// How long to keep it open: 15m, 1h, 4h. Maximum 8h. Defaults to 1h.
    #[arg(long = "for", value_name = "DURATION")]
    pub duration: Option<String>,

    /// Who to forward towards: subnet, any, a CIDR, an IP address, or the
    /// name of a device saved with `porthole devices add`.
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
