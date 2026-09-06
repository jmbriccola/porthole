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
//! ## What this section does not do yet
//!
//! Docker-published ports belong in this list too (a container publishing a
//! port on `0.0.0.0` is a service running on this machine, in every sense a
//! user cares about), but detection arrives in milestone 5.
//! `porthole_core::listening::Binding` is left exactly as task 1 shaped it,
//! ready for a future variant or flag -- this section does not stub a fake
//! "not a container" marking now. A marking that is always absent would look
//! like it works when it does not, which is worse than no marking at all.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use adw::prelude::*;

use porthole_core::listening::{Binding, Service};

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
}

struct Inner {
    /// What `PortholeWindow` appends into its `content()` box. Holds
    /// exactly one child at a time: `status_page` when nothing is
    /// listening, `group` otherwise -- the same shape
    /// `open_now::Inner::container` uses, for the same reason.
    container: gtk::Box,
    group: adw::PreferencesGroup,
    status_page: adw::StatusPage,
    rows: RefCell<Vec<Row>>,
    /// The last list `set_services` was given. Kept so `set_open_ports`
    /// alone can re-render without a caller having to resupply the service
    /// list, and vice versa -- the two setters can arrive in either order.
    services: RefCell<Vec<Service>>,
    /// Ports `set_open_ports` was last given, as a set for cheap lookup.
    open_ports: RefCell<HashSet<u16>>,
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

/// The opposite-direction case: porthole cannot open or close this either,
/// but because it is blind to it, not because it is safe. Deliberately
/// worded so it shares no sentence with [`LOOPBACK_SUBTITLE`] -- see this
/// module's own doc comment, and `porthole_core::listening::Binding`'s, for
/// why merging these two is the exact mistake a past review caught here.
fn beyond_reach_subtitle() -> String {
    "reachable over IPv6 — porthole manages IPv4 rules only and cannot open \
     or close it. Run `porthole doctor` to check your IPv6 exposure."
        .to_string()
}

/// Every row's subtitle. Always `Some` in this section's own design: even a
/// service with no Docker/loopback/reach caveat and no already-open
/// suppression still gets a subtitle -- the literal bind address, which is
/// what lets two dual-stack rows sharing a title (see this module's doc
/// comment) read as two sockets rather than one listed twice.
fn subtitle_for(service: &Service, open_ports: &HashSet<u16>) -> String {
    match service.binding {
        Binding::LoopbackOnly => LOOPBACK_SUBTITLE.to_string(),
        Binding::BeyondReach(_) => beyond_reach_subtitle(),
        Binding::AllInterfaces | Binding::Specific(_) => {
            if open_ports.contains(&service.port) {
                "already open".to_string()
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
fn apply(inner: &Rc<Inner>) {
    let services = inner.services.borrow().clone();
    let open_ports = inner.open_ports.borrow().clone();

    for row in inner.rows.replace(Vec::new()) {
        inner.group.remove(&row.row);
    }

    if services.is_empty() {
        if inner.group.parent().is_some() {
            inner.container.remove(&inner.group);
        }
        if inner.status_page.parent().is_none() {
            inner.container.append(&inner.status_page);
        }
        return;
    }

    if inner.status_page.parent().is_some() {
        inner.container.remove(&inner.status_page);
    }
    if inner.group.parent().is_none() {
        inner.container.append(&inner.group);
    }

    let mut ordered: Vec<&Service> = services.iter().collect();
    ordered.sort_by_key(|s| group_rank(&s.binding));

    let mut rows = Vec::with_capacity(ordered.len());
    for service in ordered {
        let action_row = adw::ActionRow::builder()
            .title(title_for(service))
            .subtitle(subtitle_for(service, &open_ports))
            .build();

        let open_button = if is_actionable(service, &open_ports) {
            let button = gtk::Button::builder()
                .label("Open")
                .valign(gtk::Align::Center)
                .css_classes(["suggested-action"])
                .tooltip_text(format!("Open port {}", service.port))
                .build();
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

        inner.group.add(&action_row);
        rows.push(Row {
            port: service.port,
            row: action_row,
            open_button,
        });
    }
    inner.rows.replace(rows);
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
        // status page: no warning icon, no error styling.
        let status_page = adw::StatusPage::builder()
            .title("Nothing else is listening")
            .description("Other services running on this machine will appear here.")
            .icon_name("network-server-symbolic")
            .build();

        let container = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();
        container.append(&status_page);

        let inner = Rc::new(Inner {
            container,
            group,
            status_page,
            rows: RefCell::new(Vec::new()),
            services: RefCell::new(Vec::new()),
            open_ports: RefCell::new(HashSet::new()),
        });

        Self { inner }
    }

    /// The widget `PortholeWindow::content()` appends this section's
    /// contribution as.
    pub fn widget(&self) -> &gtk::Box {
        &self.inner.container
    }

    /// The whole way a service list reaches this section -- see this
    /// module's own doc comment. Re-renders immediately against whatever
    /// `set_open_ports` last stored, in either call order.
    pub fn set_services(&self, services: &[Service]) {
        self.inner.services.replace(services.to_vec());
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

    /// `Some` only while there is nothing to list -- once there is a row,
    /// this section shows rows, not the status page.
    pub fn status_page(&self) -> Option<adw::StatusPage> {
        if self.inner.status_page.parent().is_some() {
            Some(self.inner.status_page.clone())
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

    /// `None` for a row the firewall cannot affect (`LoopbackOnly`,
    /// `BeyondReach`) or one whose port is already open.
    pub fn open_button_for(&self, index: usize) -> Option<gtk::Button> {
        self.inner
            .rows
            .borrow()
            .get(index)
            .and_then(|r| r.open_button.clone())
    }

    /// What pressing row `index`'s Open button carries: the port a future
    /// "open a port" form should pre-fill. `None` when that row has no Open
    /// button at all -- there is nothing to activate. A pure lookup, not a
    /// simulated click: safe to call both from a test standing in for a
    /// user's press, and from inside a real `connect_clicked` handler a
    /// later task attaches to the button `open_button_for` returns.
    pub fn activate_open(&self, index: usize) -> Option<u16> {
        self.inner.rows.borrow().get(index).and_then(|r| {
            if r.open_button.is_some() {
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
            subtitle_for(&svc(53, None, Binding::LoopbackOnly), &open),
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
        let subtitle = subtitle_for(&svc(22, None, Binding::BeyondReach(addr)), &open);
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
            subtitle_for(&svc(5173, Some("node"), Binding::AllInterfaces), &open),
            "already open"
        );
    }

    #[test]
    fn a_network_facing_service_shows_its_own_bind_address() {
        // Cheap disambiguation for the dual-stack case: two rows sharing a
        // title because they share a port still carry different addresses.
        let open = HashSet::new();
        assert_eq!(
            subtitle_for(&svc(5173, Some("node"), Binding::AllInterfaces), &open),
            "0.0.0.0"
        );
        let specific: Ipv4Addr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            subtitle_for(&svc(5173, Some("node"), Binding::Specific(specific)), &open),
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
}
