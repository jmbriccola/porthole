//! The "Listening" section: the lower half of the main window, showing
//! services running on this machine that are not (yet) open to the network.
//!
//! This is what makes the app pleasant: you never type a port number. You
//! see `node · 5173` and press Open on the one you want. Like
//! [`crate::open_now::OpenNowSection`], this section is `set`-driven, not
//! self-fetching: `set_services` is the whole way a service list reaches it
//! (the caller gets that list from `porthole_core::listening::scan`), and
//! `set_open_ports` is the whole way it learns which ports are already open
//! (the caller gets that from the helper's `list`, the same data
//! `OpenNowSection::set_rules` is fed). Task 6 owns wiring both of those up
//! at startup and on refresh -- this section only renders what it is given.
//!
//! ## The distinction this section must not blur
//!
//! Measured on this machine, six of seven listening TCP sockets are
//! [`Binding::LoopbackOnly`] -- so the row a user is most likely to click is
//! the one where opening the firewall does nothing at all. That row is shown
//! (hiding it would make the list look incomplete) but carries no Open
//! button, and its subtitle is one dry, reassuring sentence: opening the
//! firewall genuinely changes nothing for it.
//!
//! [`Binding::BeyondReach`] also gets no Open button -- porthole manages
//! IPv4 rules only, so it can neither open nor close a rule for a genuine
//! IPv6 address -- but the reason is the opposite of reassuring: this
//! service **is** reachable from the network, and porthole is simply blind
//! to that exposure. `porthole-core`'s own module doc (and the review that
//! produced `Binding::BeyondReach` as its own variant rather than a
//! reworded `LoopbackOnly`) is explicit that folding these two together
//! tells a user on an IPv6 network they are private when they may be
//! exposed. This section keeps them as two different subtitles, on purpose,
//! and the `BeyondReach` one points at `porthole doctor`'s own IPv6 check
//! rather than repeating porthole's own IPv4-only caveat as if it were a
//! safety fact.
//!
//! ## Ports already open
//!
//! A network-facing service whose port is already open (per
//! `set_open_ports`) is still listed here -- removing it would make the
//! list quietly incomplete -- but it gets no Open button either: it is
//! already in the "Open now" section above, with a countdown, and a second
//! `open` attempt would be refused by the helper for a reason nothing on
//! this screen had suggested.
//!
//! ## The Open button's handler
//!
//! A row's Open button is connected as it is built, in `apply`, which is
//! the only place in this crate that constructs one. What it is connected
//! to is the callback [`ListeningSection::connect_open_requested`] stores
//! on the section itself, which outlives every button. So the handler is
//! not something a caller has to reattach after a rebuild: a rendered
//! button is a connected button, and a setter that rebuilds rows cannot
//! produce a row whose button does nothing.
//!
//! It was that, before: the connection was made from outside, after
//! whichever setters the code that made it knew about. Two setters added
//! later rebuilt rows the same way, and one of them runs on every launch,
//! so the button never worked for anyone -- found by a person, not by the
//! GUI checks here, which asked whether the button existed and never
//! pressed it. `tests/window.rs` presses it now.
//!
//! The callback lives here and the dialog does not: this section renders
//! what it is given, and knows nothing about `OpenDialog` or the window.
//!
//! ## Dual-stack rows
//!
//! `porthole listen`'s human output (`porthole-cli`) prints a dual-stack
//! service (one socket on `0.0.0.0`, another on `::`) as two visually
//! identical rows, because it has no address column; that is tracked for
//! this milestone's final wave as a defect in *that* surface. This list is a
//! different surface and the fix is cheap here: every network-facing row's
//! subtitle is the literal address it is bound to (`0.0.0.0`, `::`,
//! `10.0.0.5`, ...), so two rows that share a title because they share a
//! port still read as two distinct sockets rather than one service listed
//! twice by mistake.
//!
//! ## Docker-published ports
//!
//! A row whose port and protocol match one of the ports Docker has
//! published carries a marker icon and, in its subtitle, the address Docker
//! published it on -- the same two facts `porthole listen`'s own trailing
//! `docker:` column prints, worded the same way. Nothing enforces that: the
//! two are separate strings in separate crates. porthole never touches
//! Docker's rules -- the marker says what is there, and
//! `porthole_core::docker`'s own module doc is where the consequences are
//! spelled out.
//!
//! ## The one loopback row that is offered something
//!
//! A loopback-only row published by a container on loopback carries a
//! **Forward** button. That is a different act from Open and the row says
//! so: `open` permits traffic to a service the network was already reaching,
//! and a forward redirects a port on the network into one it was not. The
//! reassurance stays as it was -- nothing outside this machine reaches that
//! socket, and the firewall is not what is stopping it -- and
//! [`FORWARDABLE_SUFFIX`] is the sentence that says what the button does.
//!
//! [`can_forward`] is the whole condition, and each of its four parts
//! mirrors a refusal the helper makes on its own side -- so no button is
//! offered on a row that could only ever be refused for something about
//! *that row*. It is not a promise that pressing it succeeds, and this
//! section must not be read as making one: the helper also refuses a
//! backend that cannot redirect at all, a firewall that is not running, and
//! an external port already answered on -- and that last one is a number
//! the user types into the dialog afterwards, which this section never
//! sees. Those refusals arrive as messages, from the helper, in its own
//! words. An ordinary local process gets no button at all rather than a
//! disabled one: a forward needs a container, and a disabled button
//! explains nothing about why.
//!
//! An unmarked row means one of three things: Docker was asked and does not
//! publish this port, Docker was asked and could not answer, or Docker has
//! not been asked yet. A row carries no way to tell them apart. The group's
//! own description line is where the difference is said, once for the whole
//! list rather than per row -- which mirrors what `porthole-cli`'s own
//! `render_listening` does with the same fact -- and it has all three
//! states, [`DockerPorts`], not two.
//!
//! The third one is why: the list this section reads comes from the helper,
//! and the `/proc` scan that fills these rows lands first (measured; see
//! below). A section that reported a failure from its own initial state
//! would report one at every launch, in the window before the helper had
//! answered anything at all.
//!
//! ## A scan failure is not "nothing is listening"
//!
//! `set_services` is fed from `porthole_core::listening::scan`, a `/proc`
//! read that can fail (however rarely on a normal Linux machine). The
//! calm "Nothing else is listening" state is a confirmed fact this section
//! earns by being *told* the list is empty, through `set_services(&[])` --
//! it must not also be what a scan *failure* falls back to, or a caller
//! choosing not to call `set_services` at all when the scan errors would
//! silently present "porthole could not check" as "porthole checked and
//! found nothing", the identical collapse `open_now.rs`'s own module doc
//! describes. [`ListeningSection::set_scan_failed`] is the distinct state
//! for it: a fourth widget, [`Inner::error_note`], never the calm one.
//! [`Inner::loading_note`] is the fifth and last, for the identical reason
//! before the first scan result has ever arrived at all.
//!
//! **Both of those must survive `set_open_ports` on its own**, and an
//! earlier version of this section did not: `set_open_ports` calls the
//! same `apply` that renders the calm page, and `apply` used to decide
//! between the calm page and the row list by checking whether `services`
//! was empty -- which it also is before the first scan, and after
//! `set_scan_failed` clears it, since neither of those has a stale row
//! list to fall back to either. So a `set_open_ports` arriving after a
//! failed scan (traced in a container: a `/proc` read on the thread pool
//! reliably beats a system-bus connect plus two polkit-checked calls, so
//! this is the *likely* arrival order for a real failure, not an edge
//! case) rebuilt the calm page right out from under `error_note`, and the
//! same held for `loading_note` before any scan had run. [`Inner::scanned`]
//! is the fix: `apply` now checks *that* first, not `services.is_empty()`,
//! and `set_open_ports` alone can no longer produce either page --
//! `tests/listening.rs`'s own opposite-order tests pin both halves of
//! this.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

use adw::prelude::*;

use porthole_core::docker::{already_reachable, Published};
use porthole_core::listening::{Binding, Service};
use porthole_core::model::Protocol;

use crate::quiet::{quiet_note, TroubleNote};

/// What this section says once a scan has come back and found nothing.
/// One dim line rather than a whole-view empty state -- see `quiet.rs`.
const EMPTY_NOTE: &str =
    "Nothing else is listening. Other services running on this machine will appear here.";

/// What this section says before any scan result has arrived. Same shape
/// and same scale as [`EMPTY_NOTE`], different words -- see this module's
/// own doc comment on why "no scan yet" is not the same fact as "the scan
/// found nothing".
const LOADING_NOTE: &str = "Checking what's listening…";

/// What a caller registers through
/// [`ListeningSection::connect_open_requested`] to hear that a row's Open
/// button was pressed, carrying that row's port. One slot, not a list:
/// registering again replaces it.
type OpenRequestedCallback = Rc<dyn Fn(u16)>;

/// What a caller registers through
/// [`ListeningSection::connect_forward_requested`] to hear that a row's
/// Forward button was pressed, carrying the port Docker publishes that
/// service on -- which is the number `porthole forward` itself takes, not
/// the port the local network would end up connecting to. One slot, not a
/// list, exactly like [`OpenRequestedCallback`].
type ForwardRequestedCallback = Rc<dyn Fn(u16)>;

/// One rendered service: the widgets `Inner::rows` needs to update or
/// remove later, plus the port a caller needs back from [`activate_open`]
/// once the button (if any) is clicked.
///
/// [`activate_open`]: ListeningSection::activate_open
struct Row {
    port: u16,
    row: adw::ActionRow,
    /// `None` for a service porthole cannot open (`LoopbackOnly`,
    /// `BeyondReach`) or one that is already open -- see this module's own
    /// doc comment for why each of those has no button.
    open_button: Option<gtk::Button>,
    /// `None` on every row [`can_forward`] answers `false` for, which is
    /// every row but one shape: a loopback-only service a checked Docker
    /// list publishes on loopback only.
    forward_button: Option<gtk::Button>,
    /// The marker on a row whose port Docker publishes. `None` on every
    /// other row, and on every row at all while Docker could not be checked.
    docker_icon: Option<gtk::Image>,
}

struct Inner {
    /// What `PortholeWindow` appends into its `content()` box. Holds
    /// exactly one child at a time: `loading_note` while `scanned` is
    /// `false` and no row list has ever been confirmed, `empty_note` once
    /// a scan confirmed there is nothing listening, `error_note` when the
    /// last scan failed, `group` otherwise -- the same shape
    /// `open_now::Inner::container` uses, for the same reason. `apply`
    /// (called by both `set_services` and `set_open_ports`) is the only
    /// place that decides between these, and it decides from `scanned`,
    /// not from whether `services` happens to be empty -- see this
    /// module's own doc comment for why that distinction is the whole fix.
    container: gtk::Box,
    group: adw::PreferencesGroup,
    /// The confirmed-nothing-listening state: one dim line, section-
    /// scaled, carrying [`EMPTY_NOTE`] and no icon at all. See `quiet.rs`.
    empty_note: gtk::Label,
    /// A **different** widget from `empty_note`, of a different type --
    /// see this module's own doc comment on why a scan failure must never
    /// render as "nothing is listening", and stays that way through a
    /// `set_open_ports` that arrives afterward.
    error_note: TroubleNote,
    /// A **different** widget again, shown only while `scanned` is `false`
    /// -- necessary, not sufficient: `scanned` is also `false` right after
    /// `set_scan_failed`, when `error_note` is what actually shows. See
    /// this module's own doc comment. Not "before `set_services` has ever
    /// been called" alone either: `set_open_ports` alone cannot displace
    /// it, which is exactly the property an earlier version of this
    /// section did not have.
    loading_note: gtk::Label,
    rows: RefCell<Vec<Row>>,
    /// The last list `set_services` was given. Kept so `set_open_ports`
    /// alone can re-render without a caller having to resupply the service
    /// list, and vice versa -- the two setters can arrive in either order.
    services: RefCell<Vec<Service>>,
    /// Ports `set_open_ports` was last given, as a set for cheap lookup.
    open_ports: RefCell<HashSet<u16>>,
    /// What this section knows about Docker -- three states, see
    /// [`DockerPorts`].
    docker: RefCell<DockerPorts>,
    /// Whether `services` is a confirmed scan result right now -- `true`
    /// only between a `set_services` call and the next `set_scan_failed`
    /// (which clears it again). `apply` reads this, not
    /// `services.is_empty()`, to decide whether the calm page may show at
    /// all: an *empty* `services` can mean either "the scan ran and found
    /// nothing" or "no confirmed scan exists" (before the first one, or
    /// after `set_scan_failed` cleared it), and only the first of those
    /// earns the calm page. Without this flag, `apply` had no way to tell
    /// the two apart -- see this module's own doc comment on the bug that
    /// produced.
    scanned: Cell<bool>,
    /// Where every Open button's click goes. Held on the section rather
    /// than on the buttons, so it outlives them: `apply` discards every
    /// button it finds and builds new ones, and this is what the new ones
    /// are connected to as they are built.
    on_open_requested: RefCell<Option<OpenRequestedCallback>>,
    /// Where every Forward button's click goes, held on the section for the
    /// same reason `on_open_requested` is: `apply` discards every button it
    /// finds and builds new ones.
    on_forward_requested: RefCell<Option<ForwardRequestedCallback>>,
}

/// `"node · 5173"` when the owning process is known, `"4000"` alone when it
/// is not -- never a placeholder name standing in for one porthole does not
/// actually have.
fn title_for(service: &Service) -> String {
    match &service.process {
        Some(name) => format!("{name} · {}", service.port),
        None => service.port.to_string(),
    }
}

/// The one dry sentence for a service the firewall cannot affect because
/// nothing outside this machine can reach it. No warning, no "cannot open"
/// framing: it is a fact about the service, not a problem with it.
const LOOPBACK_SUBTITLE: &str = "listening only on this machine — the firewall does not affect it";

/// What a row that can be forwarded says after [`LOOPBACK_SUBTITLE`]'s own
/// sentence. The reassurance is unchanged and still true -- nothing outside
/// this machine reaches that socket, and opening the firewall would not
/// change it -- and the second half names the act the row's own button
/// performs, which is not opening. A row offering a button whose subtitle
/// only says the firewall cannot help says nothing about what the button
/// does.
const FORWARDABLE_SUFFIX: &str = ", but a forward can redirect a network port into it";

/// The opposite-direction case: porthole cannot open or close this either,
/// but because it is blind to it, not because it is safe. Deliberately
/// worded so it shares no sentence with [`LOOPBACK_SUBTITLE`] -- see this
/// module's own doc comment, and `porthole_core::listening::Binding`'s, for
/// why merging these two is the exact mistake a past review caught here.
const BEYOND_REACH_SUBTITLE: &str = "reachable over IPv6 — porthole manages IPv4 rules only and \
     cannot open or close it. Run `porthole doctor` to check your IPv6 exposure.";

/// What this section says once a `docker_ports` call has actually come back
/// without an answer. Under the group's title, once, rather than on every
/// row -- see this module's own doc comment. Makes the same claim
/// `porthole-cli`'s own `render_listening` prints for the identical fact.
pub const DOCKER_UNAVAILABLE_NOTE: &str = "Docker information unavailable — the porthole helper \
     could not be reached, or answered with an error, so porthole cannot say whether any of \
     these ports are already published by a container.";

/// What this section says before any `docker_ports` call has come back at
/// all. Claims nothing about the helper, because there is nothing to
/// claim: in this state no call has failed, and whether one is in flight is
/// not something this section is told.
pub const DOCKER_NOT_CHECKED_NOTE: &str = "Docker information not checked yet — porthole cannot \
     yet say whether any of these ports are already published by a container.";

/// What this section knows about Docker's published ports.
///
/// Three states, not two. [`DockerPorts::NotChecked`] is the state a
/// freshly constructed section is in, and it is **not**
/// [`DockerPorts::Unavailable`]: nothing has failed yet. Collapsing the two
/// puts a failure on screen at every launch, during the window in which the
/// `/proc` scan has landed and the helper round trip has not -- which is
/// the ordinary order, not an edge case; see `apply`'s own doc comment for
/// where that ordering was measured.
#[derive(Debug, Clone)]
enum DockerPorts {
    /// No `docker_ports` call has come back yet.
    NotChecked,
    /// A `docker_ports` call came back with no answer -- no bus, a typed
    /// error, or a timeout. Only this one earns [`DOCKER_UNAVAILABLE_NOTE`].
    Unavailable,
    /// The checked list. Empty means Docker publishes nothing, which is an
    /// answer.
    Known(Vec<Published>),
}

impl DockerPorts {
    /// The list to look a row's port up in, or `None` when there is no
    /// checked list -- in either of the two ways there can fail to be one.
    fn checked(&self) -> Option<&[Published]> {
        match self {
            DockerPorts::Known(list) => Some(list),
            DockerPorts::NotChecked | DockerPorts::Unavailable => None,
        }
    }

    /// The group's description line for this state: the two that carry no
    /// list each say which one they are, and a checked list needs no line
    /// at all.
    fn note(&self) -> Option<&'static str> {
        match self {
            DockerPorts::Known(_) => None,
            DockerPorts::NotChecked => Some(DOCKER_NOT_CHECKED_NOTE),
            DockerPorts::Unavailable => Some(DOCKER_UNAVAILABLE_NOTE),
        }
    }
}

/// **Every** rule Docker has for `port`/`protocol`, most exposing first.
///
/// A host port can carry more than one DNAT rule -- `-p 127.0.0.1:5432:80
/// -p 0.0.0.0:5432:80` is two -- and this used to return the first match
/// only, so the second address was invisible and the row read as the whole
/// picture. `porthole-cli`'s own lookup had the identical bug and was fixed
/// to pick the most exposing single match; it has to pick one, because
/// `docs/json-schema.md` documents that field as a single object. This row
/// has no such limit: its subtitle is a sentence, so it names them all, and
/// nothing has to be dropped or ranked to fit.
///
/// The order still matters, and it is `porthole_core::docker::advise`'s
/// own: most exposing first, so the address that most affects what a user
/// should do is the one they read first.
fn docker_matches(
    port: u16,
    protocol: porthole_core::model::Protocol,
    published: &[Published],
) -> Vec<Published> {
    let mut matches: Vec<Published> = published
        .iter()
        .filter(|p| p.host_port == port && p.protocol == protocol)
        .copied()
        .collect();
    matches.sort_by_key(|p| match p.host_addr {
        None => 0,                              // every interface
        Some(addr) if !addr.is_loopback() => 1, // one address on the network
        Some(_) => 2,                           // loopback only
    });
    matches
}

/// Where one rule publishes its port, as the `docker:` fragment names it.
fn published_where(published: &Published) -> String {
    match published.host_addr {
        Some(addr) => addr.to_string(),
        None => "every interface".to_string(),
    }
}

/// The `docker:` fragment a published row's subtitle ends with, worded the
/// same way `porthole listen`'s own trailing column words it -- and, for a
/// port carrying more than one rule, naming every one of them rather than
/// whichever the lookup happened to reach first.
///
/// `matches` must be non-empty; a row with no matches carries no fragment
/// at all. See [`docker_matches`] for the order they arrive in.
fn docker_fragment(matches: &[Published]) -> String {
    let places: Vec<String> = matches.iter().map(published_where).collect();
    format!("docker: published on {}", places.join(", "))
}

/// Every row's subtitle. Always `Some` in this section's own design: even a
/// service with no Docker/loopback/reach caveat and no already-open
/// suppression still gets a subtitle -- the literal bind address, which is
/// what lets two dual-stack rows sharing a title (see this module's doc
/// comment) read as two sockets rather than one listed twice.
///
/// `docker` is the whole checked list, or `None` for "porthole could not
/// check". An unchecked row's subtitle is identical to an unpublished
/// row's -- neither mentions Docker -- which is why the difference between
/// them is said once under the group's title instead, in
/// [`DOCKER_UNKNOWN_NOTE`]. A subtitle cannot carry it.
fn subtitle_for(
    service: &Service,
    open_ports: &HashSet<u16>,
    docker: Option<&[Published]>,
) -> String {
    let mut base = subtitle_without_docker(service, open_ports);
    if can_forward(service, docker) {
        base.push_str(FORWARDABLE_SUFFIX);
    }
    let matches = docker.map(|list| docker_matches(service.port, service.protocol, list));
    match matches.as_deref() {
        Some(matches) if !matches.is_empty() => {
            format!("{base} · {}", docker_fragment(matches))
        }
        _ => base,
    }
}

/// [`subtitle_for`] without its Docker fragment: everything this section
/// says about a socket from the scan alone.
fn subtitle_without_docker(service: &Service, open_ports: &HashSet<u16>) -> String {
    match service.binding {
        Binding::LoopbackOnly => LOOPBACK_SUBTITLE.to_string(),
        Binding::BeyondReach(_) => BEYOND_REACH_SUBTITLE.to_string(),
        Binding::AllInterfaces | Binding::Specific(_) => {
            if open_ports.contains(&service.port) {
                // The address stays on this branch too -- see this module's
                // own doc comment on dual-stack rows. Two sockets that share
                // a port *and* are already open bypassed that
                // disambiguation before this fix: both produced the bare
                // string "already open", identical text for two genuinely
                // different sockets, the same collapse the plain address
                // branch below exists to prevent.
                format!("already open · {}", service.address)
            } else {
                service.address.to_string()
            }
        }
    }
}

/// Whether opening the firewall for `service` could change anything at all.
/// `false` for `LoopbackOnly` (nothing to open) and `BeyondReach` (porthole
/// cannot act on IPv6), and `false` again for a network-facing service whose
/// port is already open -- a second `open` would just be refused by the
/// helper for a reason this list gave no hint of.
fn is_actionable(service: &Service, open_ports: &HashSet<u16>) -> bool {
    matches!(
        service.binding,
        Binding::AllInterfaces | Binding::Specific(_)
    ) && !open_ports.contains(&service.port)
}

/// Whether a forward of this service could be created at all.
///
/// Four conditions, each one a refusal `porthole_core::engine::Engine::
/// forward` makes on its own side. All four are properties of the row
/// itself, which is what makes them answerable here; the helper's other
/// refusals are not, and this is deliberately **not** the set of everything
/// that can go wrong -- see this module's own doc comment on what still
/// arrives as a message:
///
/// - the service is [`Binding::LoopbackOnly`]. A forward redirects traffic
///   to something the network was not reaching; a network-facing service
///   is what `open` is for.
/// - the protocol is TCP. The helper declines a UDP forward, because the
///   check it makes for a local listener on the external port reads TCP.
/// - a **checked** Docker list names this port. `None` is both ways there
///   can fail to be one, and neither is an answer -- the same rule the
///   Docker marker follows.
/// - Docker publishes it on loopback only, per
///   `porthole_core::docker::already_reachable`. A container the local
///   network already reaches is refused a forward: it would add a second
///   way in, and closing it later would remove only that one.
///
/// The last one reads Docker's own rule rather than the `/proc` scan's
/// binding, because Docker's rule is what a forward would sit beside.
fn can_forward(service: &Service, docker: Option<&[Published]>) -> bool {
    if !matches!(service.binding, Binding::LoopbackOnly) || service.protocol != Protocol::Tcp {
        return false;
    }
    let Some(published) = docker else {
        return false;
    };
    !docker_matches(service.port, service.protocol, published).is_empty()
        && already_reachable(service.port, service.protocol, published).is_none()
}

/// Sort key that puts the rows a user can act on first: network-facing
/// (whether actionable right now or already open) ahead of `BeyondReach`
/// ahead of `LoopbackOnly`. Mirrors `porthole-cli`'s own
/// `render_listening` grouping order for the same reason it chose that
/// order -- the rows a user can act on must not be buried under the ones
/// they cannot, and among the ones they cannot, the concerning one
/// (`BeyondReach`) should not be buried under the reassuring, and usually
/// far more numerous, `LoopbackOnly` rows.
fn group_rank(binding: &Binding) -> u8 {
    match binding {
        Binding::AllInterfaces | Binding::Specific(_) => 0,
        Binding::BeyondReach(_) => 1,
        Binding::LoopbackOnly => 2,
    }
}

/// Replaces every row in `inner.group`, built from whatever `set_services`
/// and `set_open_ports` last stored -- called by both setters, since either
/// one can change what should be on screen.
///
/// Guarded by `inner.scanned`: `set_open_ports` calls this too, and before
/// this guard existed, an out-of-order `set_open_ports` (arriving after a
/// `set_scan_failed`, or before the first `set_services` at all) fell
/// through to the `services.is_empty()` branch below -- `apply_scan_failed`
/// and the constructor both leave `services` empty -- and rebuilt the calm
/// "Nothing else is listening" page right out from under `error_note` or
/// `loading_note`. Traced in a container: a `/proc` read on the thread
/// pool reliably finishes before a system-bus connect plus two
/// polkit-checked calls, so `set_scan_failed` → `set_open_ports` is the
/// likely arrival order for a real scan failure, not an edge case. See
/// `tests/listening.rs`'s own opposite-order tests for both halves of this
/// (a scan failure, and the initial loading state) surviving a
/// `set_open_ports` that arrives after them.
fn apply(inner: &Rc<Inner>) {
    if !inner.scanned.get() {
        return;
    }

    let services = inner.services.borrow().clone();
    let open_ports = inner.open_ports.borrow().clone();
    let docker = inner.docker.borrow().clone();

    for row in inner.rows.replace(Vec::new()) {
        inner.group.remove(&row.row);
    }

    // A successful `apply` -- even from an empty list -- means the scan
    // *did* answer (the guard above already confirmed `scanned`), so any
    // previous "scan failed"/"not scanned yet" state is stale and must go,
    // the same way `error_note` displaces `group`, `empty_note` and
    // `loading_note` in `apply_scan_failed` below.
    if inner.error_note.is_showing() {
        inner.container.remove(inner.error_note.widget());
    }
    if inner.loading_note.parent().is_some() {
        inner.container.remove(&inner.loading_note);
    }

    if services.is_empty() {
        if inner.group.parent().is_some() {
            inner.container.remove(&inner.group);
        }
        if inner.empty_note.parent().is_none() {
            inner.container.append(&inner.empty_note);
        }
        return;
    }

    if inner.empty_note.parent().is_some() {
        inner.container.remove(&inner.empty_note);
    }
    if inner.group.parent().is_none() {
        inner.container.append(&inner.group);
    }

    // Which of the three things an unmarked row means, said once for the
    // whole list -- see this module's own doc comment, and `DockerPorts`.
    inner.group.set_description(docker.note());

    let mut ordered: Vec<&Service> = services.iter().collect();
    ordered.sort_by_key(|s| group_rank(&s.binding));

    let mut rows = Vec::with_capacity(ordered.len());
    for service in ordered {
        // `use_markup(false)`: the title carries a process name read out of
        // `/proc`, which is whatever the running binary happens to be
        // called, and an `AdwPreferencesRow` parses its title and subtitle
        // as Pango markup by default.
        let action_row = adw::ActionRow::builder()
            .title(title_for(service))
            .subtitle(subtitle_for(service, &open_ports, docker.checked()))
            .use_markup(false)
            .build();

        // The marker the module doc describes: an icon, not colour, and
        // only ever on a row a checked list actually names.
        let docker_icon = docker
            .checked()
            .map(|list| docker_matches(service.port, service.protocol, list))
            .filter(|matches| !matches.is_empty())
            .map(|matches| {
                let icon = gtk::Image::from_icon_name("package-x-generic-symbolic");
                icon.set_valign(gtk::Align::Center);
                icon.set_tooltip_text(Some(&docker_fragment(&matches)));
                action_row.add_prefix(&icon);
                icon
            });

        let open_button = if is_actionable(service, &open_ports) {
            let button = gtk::Button::builder()
                .label("Open")
                .valign(gtk::Align::Center)
                .css_classes(["suggested-action"])
                .tooltip_text(format!("Open port {}", service.port))
                .build();
            // Connected here, in the same statement that builds it: a
            // button this section renders is a button this section has
            // already wired. See this module's own doc comment.
            let inner_for_click = Rc::clone(inner);
            let port = service.port;
            button.connect_clicked(move |_| {
                // Cloned out of the cell before the call, so the callback
                // is free to come back into this section -- opening a port
                // ends in a refresh, and a refresh rebuilds these rows.
                let callback = inner_for_click.on_open_requested.borrow().clone();
                if let Some(callback) = callback {
                    callback(port);
                }
            });
            action_row.add_suffix(&button);
            Some(button)
        } else {
            // `BeyondReach` gets a warning icon on top of its subtitle --
            // the one visual cue this section uses, and only for the case
            // that is actually concerning. `LoopbackOnly` and an
            // already-open network-facing row get neither icon nor colour:
            // see this module's own doc comment for why treating those as
            // alarming would be its own kind of dishonesty.
            if matches!(service.binding, Binding::BeyondReach(_)) {
                let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
                icon.add_css_class("warning");
                icon.set_valign(gtk::Align::Center);
                icon.set_tooltip_text(Some(
                    "Reachable over IPv6 — see porthole doctor's IPv6 check",
                ));
                action_row.add_prefix(&icon);
            }
            None
        };

        // The other act this section can offer, on the rows `open` cannot
        // help at all: redirecting a port on the network into the container
        // that publishes this one. Built and connected in the same
        // statement, exactly as the Open button above is and for the same
        // reason -- see this module's own doc comment on the wiring pass
        // that left that one dead.
        let forward_button = if can_forward(service, docker.checked()) {
            let button = gtk::Button::builder()
                .label("Forward")
                .valign(gtk::Align::Center)
                .tooltip_text(format!(
                    "Redirect a port on the network to the container publishing {}",
                    service.port
                ))
                .build();
            let inner_for_click = Rc::clone(inner);
            let published_port = service.port;
            button.connect_clicked(move |_| {
                // Cloned out of the cell before the call, for the reason
                // the Open button's own handler clones its own: what the
                // callback does can come back into this section.
                let callback = inner_for_click.on_forward_requested.borrow().clone();
                if let Some(callback) = callback {
                    callback(published_port);
                }
            });
            action_row.add_suffix(&button);
            Some(button)
        } else {
            None
        };

        inner.group.add(&action_row);
        rows.push(Row {
            port: service.port,
            row: action_row,
            open_button,
            forward_button,
            docker_icon,
        });
    }
    inner.rows.replace(rows);
}

/// Replaces whatever `inner.container` was showing with `error_note`,
/// described by `message` -- [`ListeningSection::set_scan_failed`]'s
/// state. Clears `services` (`open_ports` is untouched: it comes from an
/// entirely different, independent round trip and a scan failure says
/// nothing about whether it is stale) and, critically, `scanned` -- it is
/// `scanned` being `false` afterward, not the empty `services`, that keeps
/// a later lone `set_open_ports` from rebuilding the calm page over this
/// failure: `apply` reads `scanned` first and returns before it ever looks
/// at whether `services` is empty. An earlier version of this function
/// cleared `services` only and reasoned from that alone, which was the
/// actual defect -- `apply`'s own `services.is_empty()` branch cannot
/// distinguish "the scan ran and found nothing" from "there is no
/// confirmed scan at all", so a `set_open_ports` arriving after this
/// call did read as the former. Pinned by `tests/listening.rs`'s
/// `a_scan_failure_survives_a_later_set_open_ports` (`set_scan_failed`,
/// then `set_open_ports`, then still `error_note`, not `empty_note`).
fn apply_scan_failed(inner: &Rc<Inner>, message: &str) {
    inner.services.replace(Vec::new());
    inner.scanned.set(false);
    for row in inner.rows.replace(Vec::new()) {
        inner.group.remove(&row.row);
    }

    if inner.group.parent().is_some() {
        inner.container.remove(&inner.group);
    }
    if inner.empty_note.parent().is_some() {
        inner.container.remove(&inner.empty_note);
    }
    if inner.loading_note.parent().is_some() {
        inner.container.remove(&inner.loading_note);
    }

    inner.error_note.set_description(message);
    if !inner.error_note.is_showing() {
        inner.container.append(inner.error_note.widget());
    }
}

/// The lower section of the main window: services running on this machine
/// that are not open to the network, each offering an Open button only when
/// pressing it could actually change something.
#[derive(Clone)]
pub struct ListeningSection {
    inner: Rc<Inner>,
}

impl Default for ListeningSection {
    fn default() -> Self {
        Self::new()
    }
}

impl ListeningSection {
    pub fn new() -> Self {
        let group = adw::PreferencesGroup::builder().title("Listening").build();

        // Nothing else listening is an ordinary, calm state on most
        // machines -- not an error -- so this mirrors `OpenNowSection`'s own
        // quiet note: one dim line, no icon, no error styling, and no
        // whole-window widget standing in for one section (see `quiet.rs`).
        let empty_note = quiet_note(EMPTY_NOTE);

        // A scan failure is a different fact from a confirmed-empty scan --
        // see this module's own doc comment. Same shape as
        // `open_now::Inner::error_note`: an icon and a CSS class, on a
        // widget of a different type from the calm note above, which has
        // neither.
        let error_note = TroubleNote::new();
        error_note.set_title("Could not check what's listening");

        // Shown while `scanned` is still `false` -- see this module's own
        // doc comment on why the calm note must not be the default, and on
        // why "before `set_services`" alone used to be the wrong
        // condition. Neutral: no error/warning styling, and the same scale
        // as `empty_note`, so the section does not change height when one
        // replaces the other.
        let loading_note = quiet_note(LOADING_NOTE);

        let container = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();
        container.append(&loading_note);

        let inner = Rc::new(Inner {
            container,
            group,
            empty_note,
            error_note,
            loading_note,
            rows: RefCell::new(Vec::new()),
            services: RefCell::new(Vec::new()),
            open_ports: RefCell::new(HashSet::new()),
            docker: RefCell::new(DockerPorts::NotChecked),
            scanned: Cell::new(false),
            on_open_requested: RefCell::new(None),
            on_forward_requested: RefCell::new(None),
        });

        Self { inner }
    }

    /// The widget `PortholeWindow::content()` appends this section's
    /// contribution as.
    pub fn widget(&self) -> &gtk::Box {
        &self.inner.container
    }

    /// Registers what a row's Open button does, once, for the whole life
    /// of this section: `f` is called with that row's port every time one
    /// is pressed, however many times the rows have been rebuilt in
    /// between. Registering again replaces it.
    ///
    /// This section renders what it is given and knows nothing about the
    /// dialog `f` goes on to present -- see this module's own doc comment.
    pub fn connect_open_requested(&self, f: impl Fn(u16) + 'static) {
        self.inner.on_open_requested.replace(Some(Rc::new(f)));
    }

    /// Registers what a row's Forward button does, once, for the whole life
    /// of this section, exactly as
    /// [`ListeningSection::connect_open_requested`] does for the other
    /// button. `f` is called with the port Docker publishes that service
    /// on -- the number `porthole forward` takes.
    pub fn connect_forward_requested(&self, f: impl Fn(u16) + 'static) {
        self.inner.on_forward_requested.replace(Some(Rc::new(f)));
    }

    /// The whole way a service list reaches this section -- see this
    /// module's own doc comment. Re-renders immediately against whatever
    /// `set_open_ports` last stored, in either call order.
    pub fn set_services(&self, services: &[Service]) {
        self.inner.services.replace(services.to_vec());
        self.inner.scanned.set(true);
        apply(&self.inner);
    }

    /// The whole way this section learns which ports are already open, so
    /// it can withhold the Open button for them. Re-renders immediately
    /// against whatever `set_services` last stored, in either call order.
    pub fn set_open_ports(&self, ports: &[u16]) {
        self.inner
            .open_ports
            .replace(ports.iter().copied().collect());
        apply(&self.inner);
    }

    /// The failure counterpart to [`ListeningSection::set_open_ports`]: a
    /// helper round trip that could not confirm which ports are open at all
    /// is not the same fact as one that confirmed there are none, and
    /// `open_ports` must not keep holding whatever it last knew once that
    /// round trip has failed -- a still-listed port would otherwise keep
    /// reading "already open" and keep withholding its Open button on a
    /// claim porthole can no longer stand behind. Same reasoning as
    /// [`crate::open_now::OpenNowSection`]'s own rule list on a failed
    /// refresh, applied to this section's own set instead of a list of
    /// rows.
    pub fn set_open_ports_unknown(&self) {
        self.inner.open_ports.replace(HashSet::new());
        apply(&self.inner);
    }

    /// The whole way this section learns which ports Docker publishes.
    /// Re-renders immediately against whatever the other setters last
    /// stored, in any call order.
    pub fn set_docker_ports(&self, published: &[Published]) {
        self.inner
            .docker
            .replace(DockerPorts::Known(published.to_vec()));
        apply(&self.inner);
    }

    /// The failure counterpart to [`ListeningSection::set_docker_ports`]:
    /// a `docker_ports` call came back without an answer, which is not the
    /// same fact as it answering "none". Drops whatever list was last known
    /// -- a marker left standing would keep claiming something porthole can
    /// no longer stand behind -- and puts [`DOCKER_UNAVAILABLE_NOTE`] under
    /// the group's title.
    ///
    /// **Not** the state a freshly constructed section is in. That one is
    /// [`DockerPorts::NotChecked`], and this method is the only way to
    /// reach this one: a caller that has not called `docker_ports` yet must
    /// not call this, or the section reports a failure nobody has had. See
    /// this module's own doc comment.
    pub fn set_docker_unavailable(&self) {
        self.inner.docker.replace(DockerPorts::Unavailable);
        apply(&self.inner);
    }

    /// The state for a `/proc` scan that failed outright -- see this
    /// module's own doc comment for why this must not fall back to the
    /// calm "Nothing else is listening" page. `message` is the scan's own
    /// error, verbatim.
    pub fn set_scan_failed(&self, message: &str) {
        apply_scan_failed(&self.inner, message);
    }

    /// `Some` only while there is nothing to list -- once there is a row,
    /// the last scan failed ([`ListeningSection::error_note`]), or no scan
    /// has run yet ([`ListeningSection::loading_note`]), this section
    /// shows something else instead.
    ///
    /// A `gtk::Label`, not an `adw::StatusPage`: this is one section of a
    /// window, not a view of its own. See `quiet.rs`.
    pub fn empty_note(&self) -> Option<gtk::Label> {
        if self.inner.empty_note.parent().is_some() {
            Some(self.inner.empty_note.clone())
        } else {
            None
        }
    }

    /// `Some` only while [`ListeningSection::set_scan_failed`]'s state is
    /// showing -- a real, distinct widget from
    /// [`ListeningSection::empty_note`], of a different type, never both at
    /// once.
    pub fn error_note(&self) -> Option<TroubleNote> {
        if self.inner.error_note.is_showing() {
            Some(self.inner.error_note.clone())
        } else {
            None
        }
    }

    /// `Some` only while `scanned` is still `false` -- the very first
    /// widget a freshly constructed section shows, and gone for good the
    /// moment `set_services` or `set_scan_failed` is called even once.
    /// `set_open_ports` alone, called any number of times before either of
    /// those, leaves this exactly as it was: `apply` (which
    /// `set_open_ports` calls) checks `scanned` before it touches the
    /// container at all.
    pub fn loading_note(&self) -> Option<gtk::Label> {
        if self.inner.loading_note.parent().is_some() {
            Some(self.inner.loading_note.clone())
        } else {
            None
        }
    }

    pub fn rows(&self) -> Vec<adw::ActionRow> {
        self.inner
            .rows
            .borrow()
            .iter()
            .map(|r| r.row.clone())
            .collect()
    }

    /// The group's own description line: [`DOCKER_NOT_CHECKED_NOTE`] before
    /// any `docker_ports` call has come back, [`DOCKER_UNAVAILABLE_NOTE`]
    /// once one came back without an answer, `None` once one brought a
    /// list.
    pub fn group_description(&self) -> Option<String> {
        self.inner
            .group
            .description()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    }

    /// Whether row `index` carries the Docker marker, checked against the
    /// live widget tree -- the icon's own `parent()` -- rather than only
    /// whether the field is `Some`, the same way
    /// `OpenDialog::is_marked_significant` checks its own. `Some` alone
    /// would prove an icon was constructed, not that it was ever attached.
    pub fn is_marked_docker(&self, index: usize) -> bool {
        self.inner.rows.borrow().get(index).is_some_and(|r| {
            r.docker_icon
                .as_ref()
                .is_some_and(|icon| icon.parent().is_some())
        })
    }

    /// `None` for a row the firewall cannot affect (`LoopbackOnly`,
    /// `BeyondReach`) or one whose port is already open.
    pub fn open_button_for(&self, index: usize) -> Option<gtk::Button> {
        self.inner
            .rows
            .borrow()
            .get(index)
            .and_then(|r| r.open_button.clone())
    }

    /// What pressing row `index`'s Open button carries: the port
    /// [`ListeningSection::connect_open_requested`]'s callback is handed.
    /// `None` when that row has no Open button at all -- there is nothing
    /// to activate.
    ///
    /// A pure lookup, not a simulated click. It reads back which port a
    /// row would send; it does not prove the button sends anything. Only
    /// emitting `clicked` on the button itself proves that, and
    /// `tests/window.rs` is where that is done.
    pub fn activate_open(&self, index: usize) -> Option<u16> {
        self.inner.rows.borrow().get(index).and_then(|r| {
            if r.open_button.is_some() {
                Some(r.port)
            } else {
                None
            }
        })
    }

    /// `None` for every row [`can_forward`] answers `false` for -- see that
    /// function for the four things that have to hold at once.
    pub fn forward_button_for(&self, index: usize) -> Option<gtk::Button> {
        self.inner
            .rows
            .borrow()
            .get(index)
            .and_then(|r| r.forward_button.clone())
    }

    /// What pressing row `index`'s Forward button carries: the published
    /// port [`ListeningSection::connect_forward_requested`]'s callback is
    /// handed. `None` when that row has no Forward button at all.
    ///
    /// A pure lookup, not a simulated click -- the same limit
    /// [`ListeningSection::activate_open`] carries, and `tests/window.rs`
    /// is where the button itself is pressed.
    pub fn activate_forward(&self, index: usize) -> Option<u16> {
        self.inner.rows.borrow().get(index).and_then(|r| {
            if r.forward_button.is_some() {
                Some(r.port)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::model::Protocol;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // Pure-function coverage of title/subtitle/ordering text and logic,
    // independent of GTK -- these run in the crate's ordinary unit-test
    // binary, unlike everything in `tests/listening.rs`.

    fn svc(port: u16, process: Option<&str>, binding: Binding) -> Service {
        let address = match binding {
            Binding::LoopbackOnly => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Binding::AllInterfaces => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Binding::Specific(a) => IpAddr::V4(a),
            Binding::BeyondReach(a) => IpAddr::V6(a),
        };
        Service {
            port,
            protocol: Protocol::Tcp,
            address,
            binding,
            process: process.map(str::to_string),
            pid: None,
        }
    }

    #[test]
    fn title_names_the_process_and_port_with_a_middle_dot() {
        assert_eq!(
            title_for(&svc(5173, Some("node"), Binding::AllInterfaces)),
            "node · 5173"
        );
    }

    #[test]
    fn title_is_the_bare_port_when_no_process_is_known() {
        assert_eq!(title_for(&svc(4000, None, Binding::AllInterfaces)), "4000");
    }

    #[test]
    fn loopback_subtitle_is_the_exact_reassuring_sentence() {
        let open = HashSet::new();
        assert_eq!(
            subtitle_for(&svc(53, None, Binding::LoopbackOnly), &open, None),
            LOOPBACK_SUBTITLE,
        );
    }

    #[test]
    fn beyond_reach_subtitle_does_not_borrow_the_loopback_sentence() {
        // The regression this pins: task 1's first draft folded BeyondReach
        // into LoopbackOnly's wording. If a future edit does the same thing
        // to this section's subtitles, this fails.
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let open = HashSet::new();
        let subtitle = subtitle_for(&svc(22, None, Binding::BeyondReach(addr)), &open, None);
        assert!(
            !subtitle.contains("only on this machine"),
            "a BeyondReach subtitle must not claim the reassurance LoopbackOnly earns: {subtitle}"
        );
        assert!(
            subtitle.contains("IPv6"),
            "a BeyondReach subtitle must name the reason: {subtitle}"
        );
        assert!(
            subtitle.contains("porthole doctor"),
            "a BeyondReach subtitle must point at doctor's IPv6 check: {subtitle}"
        );
    }

    #[test]
    fn an_already_open_network_facing_service_is_marked_without_a_new_claim() {
        let mut open = HashSet::new();
        open.insert(5173);
        assert_eq!(
            subtitle_for(
                &svc(5173, Some("node"), Binding::AllInterfaces),
                &open,
                None
            ),
            "already open · 0.0.0.0"
        );
    }

    #[test]
    fn two_already_open_rows_sharing_a_port_still_read_as_two_sockets() {
        // The already-open branch used to bypass the address-based
        // disambiguation entirely, so two rows that share a port that is
        // *also* already open both rendered the bare string "already open"
        // -- identical text for two different sockets, the exact collapse
        // this module's own doc comment on dual-stack rows says the
        // subtitle must never produce. Both fixtures here are IPv4
        // (`AllInterfaces`/`Specific`, not a genuine v4+v6 pair) -- the
        // disambiguation this pins is address-based, not stack-based, so
        // two same-port IPv4 sockets at different addresses already prove
        // it without needing a real dual-stack pair.
        let mut open = HashSet::new();
        open.insert(53);
        let wildcard = svc(53, None, Binding::AllInterfaces);
        let specific = svc(53, None, Binding::Specific("10.0.0.5".parse().unwrap()));
        let wildcard_subtitle = subtitle_for(&wildcard, &open, None);
        let specific_subtitle = subtitle_for(&specific, &open, None);
        assert_ne!(
            wildcard_subtitle, specific_subtitle,
            "two already-open sockets sharing a port must not render identically"
        );
        assert!(
            wildcard_subtitle.contains("0.0.0.0"),
            "got: {wildcard_subtitle}"
        );
        assert!(
            specific_subtitle.contains("10.0.0.5"),
            "got: {specific_subtitle}"
        );
    }

    #[test]
    fn a_network_facing_service_shows_its_own_bind_address() {
        // Cheap disambiguation for the dual-stack case: two rows sharing a
        // title because they share a port still carry different addresses.
        let open = HashSet::new();
        assert_eq!(
            subtitle_for(
                &svc(5173, Some("node"), Binding::AllInterfaces),
                &open,
                None
            ),
            "0.0.0.0"
        );
        let specific: Ipv4Addr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            subtitle_for(
                &svc(5173, Some("node"), Binding::Specific(specific)),
                &open,
                None
            ),
            "10.0.0.5"
        );
    }

    #[test]
    fn only_loopback_and_beyond_reach_are_non_actionable() {
        let open = HashSet::new();
        assert!(is_actionable(
            &svc(5173, None, Binding::AllInterfaces),
            &open
        ));
        assert!(is_actionable(
            &svc(5173, None, Binding::Specific("10.0.0.5".parse().unwrap())),
            &open
        ));
        assert!(!is_actionable(
            &svc(5173, None, Binding::LoopbackOnly),
            &open
        ));
        assert!(!is_actionable(
            &svc(
                5173,
                None,
                Binding::BeyondReach("2001:db8::1".parse().unwrap())
            ),
            &open
        ));
    }

    #[test]
    fn an_already_open_port_is_not_actionable_even_though_network_facing() {
        let mut open = HashSet::new();
        open.insert(5173);
        assert!(!is_actionable(
            &svc(5173, None, Binding::AllInterfaces),
            &open
        ));
    }

    #[test]
    fn group_rank_orders_actionable_before_beyond_reach_before_loopback() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(group_rank(&Binding::AllInterfaces) < group_rank(&Binding::BeyondReach(global)));
        assert!(group_rank(&Binding::BeyondReach(global)) < group_rank(&Binding::LoopbackOnly));
    }

    fn published(port: u16, host_addr: Option<&str>) -> Published {
        Published {
            host_addr: host_addr.map(|a| a.parse().unwrap()),
            host_port: port,
            protocol: Protocol::Tcp,
            container_addr: "172.17.0.2".parse().unwrap(),
            container_port: 80,
        }
    }

    #[test]
    fn a_published_row_names_the_address_docker_published_it_on() {
        let open = HashSet::new();
        let list = [published(8080, None)];
        assert_eq!(
            subtitle_for(
                &svc(8080, Some("node"), Binding::AllInterfaces),
                &open,
                Some(&list)
            ),
            "0.0.0.0 · docker: published on every interface"
        );

        // The same row also gains `FORWARDABLE_SUFFIX`: a container
        // publishing a port on loopback is exactly the shape that gets a
        // Forward button, and the row has to say what that button does.
        let list = [published(5432, Some("127.0.0.1"))];
        assert_eq!(
            subtitle_for(&svc(5432, None, Binding::LoopbackOnly), &open, Some(&list)),
            format!("{LOOPBACK_SUBTITLE}{FORWARDABLE_SUFFIX} · docker: published on 127.0.0.1")
        );
    }

    #[test]
    fn a_loopback_row_a_container_publishes_on_loopback_can_be_forwarded() {
        let list = [published(3000, Some("127.0.0.1"))];
        assert!(can_forward(
            &svc(3000, Some("docker-proxy"), Binding::LoopbackOnly),
            Some(&list)
        ));
    }

    #[test]
    fn nothing_else_can_be_forwarded() {
        let loopback_list = [published(3000, Some("127.0.0.1"))];
        let exposed_list = [published(3000, None)];

        // No container publishes it.
        assert!(!can_forward(
            &svc(3000, Some("code"), Binding::LoopbackOnly),
            Some(&[])
        ));
        // A container publishes a different port.
        assert!(!can_forward(
            &svc(9843, Some("code"), Binding::LoopbackOnly),
            Some(&loopback_list)
        ));
        // No checked list at all -- neither of the two ways there can fail
        // to be one is an answer.
        assert!(!can_forward(
            &svc(3000, Some("docker-proxy"), Binding::LoopbackOnly),
            None
        ));
        // The network already reaches the container, which the helper
        // refuses: a forward would add a second way in.
        assert!(!can_forward(
            &svc(3000, Some("docker-proxy"), Binding::LoopbackOnly),
            Some(&exposed_list)
        ));
        // Network-facing, and so `open`'s business rather than this one's.
        assert!(!can_forward(
            &svc(3000, Some("docker-proxy"), Binding::AllInterfaces),
            Some(&loopback_list)
        ));
        // UDP, which the helper declines to forward.
        let mut udp_service = svc(3000, Some("docker-proxy"), Binding::LoopbackOnly);
        udp_service.protocol = Protocol::Udp;
        let mut udp_published = published(3000, Some("127.0.0.1"));
        udp_published.protocol = Protocol::Udp;
        assert!(!can_forward(&udp_service, Some(&[udp_published])));
    }

    #[test]
    fn a_row_that_cannot_be_forwarded_keeps_the_reassurance_alone() {
        // The suffix is the whole difference between the two loopback
        // rows, and an ordinary local process must not carry it: it names
        // an act that row cannot perform.
        let open = HashSet::new();
        let list = [published(3000, Some("127.0.0.1"))];
        let plain = subtitle_for(
            &svc(9843, Some("code"), Binding::LoopbackOnly),
            &open,
            Some(&list),
        );
        assert_eq!(plain, LOOPBACK_SUBTITLE);
    }

    #[test]
    fn a_row_docker_does_not_publish_says_nothing_about_docker() {
        let open = HashSet::new();
        let list = [published(8080, None)];
        assert_eq!(
            subtitle_for(&svc(4000, None, Binding::AllInterfaces), &open, Some(&list)),
            "0.0.0.0"
        );
    }

    #[test]
    fn a_row_carries_no_docker_text_when_there_is_no_checked_list() {
        // Both no-list states leave a row's own text exactly as the scan
        // alone would render it, which is the whole reason the difference
        // between them is said at group level instead.
        let open = HashSet::new();
        let service = svc(8080, Some("node"), Binding::AllInterfaces);
        for state in [DockerPorts::NotChecked, DockerPorts::Unavailable] {
            assert_eq!(
                subtitle_for(&service, &open, state.checked()),
                subtitle_without_docker(&service, &open),
                "{state:?}"
            );
        }
    }

    #[test]
    fn a_section_nobody_has_asked_about_docker_yet_reports_no_failure() {
        // The defect this state exists for: the `/proc` scan lands before
        // the helper round trip, so a section whose initial state was
        // `Unavailable` would put "the helper could not be reached" on
        // screen at every launch, before anything had failed.
        assert_eq!(
            DockerPorts::NotChecked.note(),
            Some(DOCKER_NOT_CHECKED_NOTE)
        );
        assert_eq!(
            DockerPorts::Unavailable.note(),
            Some(DOCKER_UNAVAILABLE_NOTE)
        );
        assert_eq!(DockerPorts::Known(Vec::new()).note(), None);

        let not_checked = DOCKER_NOT_CHECKED_NOTE.to_lowercase();
        for failure_word in ["could not be reached", "unavailable", "error"] {
            assert!(
                !not_checked.contains(failure_word),
                "the not-checked note must not report a failure: {DOCKER_NOT_CHECKED_NOTE}"
            );
        }
    }

    #[test]
    fn a_published_port_on_the_other_protocol_is_not_this_rows_docker_port() {
        let mut udp = published(8080, None);
        udp.protocol = Protocol::Udp;
        assert!(docker_matches(8080, Protocol::Tcp, &[udp]).is_empty());
        assert_eq!(docker_matches(8080, Protocol::Udp, &[udp]).len(), 1);
    }

    #[test]
    fn a_port_with_two_docker_rules_shows_both_addresses() {
        // `-p 127.0.0.1:5432:80 -p 10.0.0.5:5432:80` is two DNAT rules on
        // one host port. Taking the first match hid the second entirely,
        // and the row read as the whole picture -- the same defect
        // `porthole-cli`'s own lookup carried.
        let open = HashSet::new();
        let list = [
            published(5432, Some("127.0.0.1")),
            published(5432, Some("10.0.0.5")),
        ];
        let subtitle = subtitle_for(
            &svc(5432, Some("docker-proxy"), Binding::AllInterfaces),
            &open,
            Some(&list),
        );
        assert!(
            subtitle.contains("127.0.0.1"),
            "the loopback rule must still be named: {subtitle}"
        );
        assert!(
            subtitle.contains("10.0.0.5"),
            "the second rule must not be hidden by the first: {subtitle}"
        );
    }

    #[test]
    fn the_most_exposing_rule_is_named_first() {
        // Same ordering `porthole_core::docker::advise` uses, and for the
        // same reason: the address that most affects what a user should do
        // is the one they read first. The input here is in the opposite
        // order, so a lookup that merely preserved chain order would fail.
        let list = [
            published(5432, Some("127.0.0.1")),
            published(5432, Some("10.0.0.5")),
            published(5432, None),
        ];
        let matches = docker_matches(5432, Protocol::Tcp, &list);
        assert_eq!(
            matches.iter().map(published_where).collect::<Vec<_>>(),
            vec!["every interface", "10.0.0.5", "127.0.0.1"]
        );
        assert_eq!(
            docker_fragment(&matches),
            "docker: published on every interface, 10.0.0.5, 127.0.0.1"
        );
    }

    #[test]
    fn a_port_with_one_docker_rule_reads_exactly_as_it_did() {
        // The single-rule wording is what `porthole listen`'s own trailing
        // column prints, and listing them all must not have changed it.
        assert_eq!(
            docker_fragment(&[published(8080, None)]),
            "docker: published on every interface"
        );
        assert_eq!(
            docker_fragment(&[published(5432, Some("127.0.0.1"))]),
            "docker: published on 127.0.0.1"
        );
    }

    #[test]
    fn the_unavailable_note_says_porthole_could_not_check_not_that_there_is_nothing() {
        let note = DOCKER_UNAVAILABLE_NOTE.to_lowercase();
        assert!(note.contains("unavailable"), "{DOCKER_UNAVAILABLE_NOTE}");
        assert!(note.contains("cannot say"), "{DOCKER_UNAVAILABLE_NOTE}");
    }
}
