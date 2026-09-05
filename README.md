# porthole

Open a port to your local network, temporarily and on purpose — and let it close
itself.

porthole is not a firewall GUI. It does one thing: it opens a single port
towards the network you are on right now, for a bounded amount of time, and
closes it again. It never writes permanent rules, so a reboot closes everything.

Status: in development. See `docs/` for design notes.

Licensed under the GNU General Public License v3.0 or later.
