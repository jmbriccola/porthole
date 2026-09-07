//! The open dialog: where a user chooses what to open, for how long, and
//! towards whom.
//!
//! Two of its choices are the project's central safety decisions, not
//! preferences.
//!
//! **The duration ceiling.** The chips in [`duration_options`] are exactly
//! the five the spec names -- 15 minutes, 1 hour (the default), 4 hours, 8
//! hours, until reboot -- and nothing between 8 hours and until-reboot
//! exists. [`porthole_core::model::MAX_DURATION`] is what makes porthole's
//! "temporary" promise true; a sixth chip offering more than it would be
//! refused by the helper, and refusing something the app itself put on
//! screen is an avoidable dead end.
//!
//! **"Anyone".** [`build_targets`] always puts it last and marks it (an
//! icon, not colour alone -- colour alone fails a colour-blind user and a
//! high-contrast theme). It is never preselected: the selection starts at
//! "This network" and only ever moves on a real click.
//!
//! That sentence deliberately names no function. Two earlier attempts to
//! attribute the behaviour were both wrong -- first to `build_targets`, which
//! carries no selection state, then to `rebuild_targets`, which does not set
//! the default and in fact *preserves* the existing selection on every call
//! after the first. Attributing a behaviour is where this file kept going
//! wrong; stating it is enough. [`anyone_note`] is the one dry sentence the spec asks for:
//! "niente toni allarmistici o didattici, solo una frase asciutta su cosa
//! comporta." A warning that lectures gets dismissed unread, which makes the
//! genuinely significant choice less safe, not more.
//!
//! ## What this dialog does not do
//!
//! It never composes a firewall rule. Pressing "Open" builds a [`Request`] --
//! port, protocol, lifetime, scope -- and [`open_over_dbus`] sends exactly
//! what `porthole-cli`'s own `client::open` sends: `scope` as the
//! un-resolved string a person would have typed (`subnet`, `any`, a CIDR, an
//! IP; see [`scope_wire_string`]), re-validated by the helper independently.
//! A compromised client sending a `Request` it invented gets no more trust
//! than the CLI's own flags would.
//!
//! [`build_targets`] takes the current subnet and the saved devices as
//! plain arguments and returns a `Vec`, rather than the target list being a
//! fixed set of widgets. The saved devices are an insertion between "This
//! network" and "Anyone" in that one function -- a data change, not a
//! redesign.
//!
//! ## Saved devices, and the ones that are not here right now
//!
//! A saved device whose address cannot be resolved at this moment still gets
//! a row, carrying the resolution error's own text and no scope, rendered
//! insensitive. Dropping it from the list instead would be indistinguishable,
//! on screen, from the device having been deleted.
//!
//! The dialog resolves nothing itself. [`DeviceEntry`] is already the answer
//! -- a name and either an address or a reason -- computed by whoever fed it
//! in, on a thread that is not this one.
//!
//! ## Docker
//!
//! porthole never touches Docker's rules; it explains them. When Docker
//! already publishes the port about to be opened, pressing Open presents
//! [`porthole_core::docker::advise`]'s own sentence first, with "Open
//! Anyway" as a real way through -- the spec asks for an explanation, not a
//! prohibition. `docker_alert_for` is where that decision is made, and
//! [`OpenDialog::docker_alert`] builds the identical alert without
//! presenting it, which is the only part of this a test in this repository
//! actually exercises: the presented alert's own two responses are answered
//! by a person, not by CI.
//!
//! ## `on_opened`
//!
//! [`OpenDialog::on_opened`] is a hook a caller registers to learn a request
//! actually succeeded (the new [`WireRule`] the helper returned).
//! `window.rs` registers it on every dialog it presents -- from the header
//! bar's button and from each "Listening" row's own pre-filled one -- so a
//! successful open re-populates both sections and the status line from the
//! helper and `/proc` again, the same refresh construction itself already
//! runs.
//!
//! And, like [`crate::open_now::OpenNowSection`]'s close button before it,
//! the "Open" button's real D-Bus round trip has no automated test: the
//! container this milestone tests in runs no live helper, so a click's
//! success or failure path is exercised by inspection, not by CI. What *is*
//! tested is everything the round trip depends on being right before it ever
//! reaches the bus -- the request built from the widgets, and the exact
//! strings and seconds that request turns into.

use std::cell::{Cell, RefCell};
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;
use ipnet::Ipv4Net;

use porthole_core::docker::{advise, Published};
use porthole_core::ipc::{PortholeProxy, WireRule};
use porthole_core::model::{Lifetime, Protocol, ScopeSpec, DEFAULT_DURATION, MAX_DURATION};

/// What this dialog hands the client once the user presses Open: the same
/// four things the CLI's `open` subcommand sends -- port, protocol,
/// lifetime, scope -- never a composed firewall rule. The helper validates
/// every one of these independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub port: u16,
    pub protocol: Protocol,
    pub lifetime: Lifetime,
    pub scope: ScopeSpec,
}

/// The five duration chips, in this exact order and exactly these five --
/// see this module's own doc comment for why the ceiling matters.
///
/// The chip that *is* the ceiling is built from [`MAX_DURATION`] itself,
/// not a second hardcoded `8 * 60 * 60`: that is what makes "no chip exceeds
/// the ceiling" true by construction for this entry rather than true only
/// because nobody has changed `MAX_DURATION` since the literal was copied
/// down here. Lowering `MAX_DURATION` lowers this chip with it. The "1 hour"
/// entry is built from [`DEFAULT_DURATION`] for the identical reason. The
/// 15-minute and 4-hour entries are independent literals with no such tie --
/// comfortably under the ceiling today, but not linked to it at compile
/// time -- which is why the property test below (`no_duration_option_exceeds_the_ceiling`)
/// stays, checking every entry against `MAX_DURATION` at run time rather
/// than trusting that only the two tied ones could ever need it.
fn duration_options() -> Vec<(&'static str, Lifetime)> {
    vec![
        ("15 minutes", Lifetime::For(Duration::from_secs(15 * 60))),
        ("1 hour", Lifetime::For(DEFAULT_DURATION)),
        ("4 hours", Lifetime::For(Duration::from_secs(4 * 60 * 60))),
        ("8 hours", Lifetime::For(MAX_DURATION)),
        ("Until reboot", Lifetime::UntilReboot),
    ]
}

/// One dry sentence about what "Anyone" means, reused verbatim everywhere
/// this dialog mentions it (the target row's subtitle, its icon's tooltip,
/// and [`OpenDialog::note_for_anyone`]) so those three cannot drift into
/// different claims about the same choice. `pub(crate)`, not private: a
/// fourth site outside this module makes the identical claim about the
/// identical choice -- `open_now.rs`'s "open to anyone" marking on an
/// already-open rule -- and calls this directly rather than keeping its
/// own, separate copy of the sentence (an earlier version did exactly
/// that, worded slightly differently, outside every guard that keeps
/// these three in sync).
pub(crate) fn anyone_note() -> String {
    "Opens the port to anyone your machine can reach, not just devices on this network.".to_string()
}

/// One saved device as this dialog needs it: its name, and either the
/// address it resolves to right now or the reason it does not.
///
/// Deliberately not [`porthole_core::devices::DeviceStatus`], which records
/// resolution as `Option<Ipv4Addr>`: an absent address there is one value
/// standing for two different facts -- the device is not on this network,
/// and the lookup itself failed. This dialog puts that text on screen, so it
/// carries whatever `porthole_core::devices::resolve` said, verbatim, rather
/// than composing a reason of its own from an `Option`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    pub name: String,
    /// `Ok` is the address the device holds right now; `Err` is the
    /// resolution error's own rendered text.
    pub resolved: Result<Ipv4Addr, String>,
}

/// What a target row is, independently of where it currently sits in the
/// list. [`rebuild_targets`] restores the user's choice by this rather than
/// by index: a device list arriving after the dialog is already on screen
/// shifts "Anyone" from index 1 to index 1 + n, so an index kept across that
/// rebuild would silently point at a different row than the one that was
/// chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetKey {
    CurrentSubnet,
    Device(String),
    Anywhere,
}

/// One row of the target list: what the user can open towards, and whether
/// it is significant enough to need marking.
struct TargetOption {
    key: TargetKey,
    label: String,
    subtitle: Option<String>,
    /// `None` for a row that names no scope porthole can open towards right
    /// now -- a saved device that does not resolve. Such a row is rendered,
    /// and rendered insensitive: nothing can select it, and nothing sends
    /// it.
    scope: Option<ScopeSpec>,
    /// Only "Anyone" is `true`. Marked in the rendered row by an icon, not
    /// colour alone.
    significant: bool,
}

/// The subtitle a saved device's row carries: the address it resolves to, or
/// the resolution error's own text.
fn device_subtitle(entry: &DeviceEntry) -> String {
    match &entry.resolved {
        Ok(addr) => format!("resolves to {addr}"),
        Err(reason) => reason.clone(),
    }
}

/// "This network" first, named by its actual subnet once a caller has
/// supplied one (plain "This network" before that -- still a real, selected
/// option, not a placeholder); every saved device next, in the order the
/// caller supplied them; "Anyone" always last and the only entry marked
/// significant. That order is the spec's.
///
/// A device that does not resolve right now still gets a row, carrying its
/// own reason and no scope: hiding it would read as the device having been
/// deleted.
fn build_targets(current_network: Option<Ipv4Net>, devices: &[DeviceEntry]) -> Vec<TargetOption> {
    let mut options = vec![TargetOption {
        key: TargetKey::CurrentSubnet,
        label: match current_network {
            Some(net) => format!("This network ({net})"),
            None => "This network".to_string(),
        },
        subtitle: None,
        scope: Some(ScopeSpec::CurrentSubnet),
        significant: false,
    }];

    for entry in devices {
        options.push(TargetOption {
            key: TargetKey::Device(entry.name.clone()),
            label: entry.name.clone(),
            subtitle: Some(device_subtitle(entry)),
            scope: entry.resolved.as_ref().ok().map(|a| ScopeSpec::Host(*a)),
            significant: false,
        });
    }

    options.push(TargetOption {
        key: TargetKey::Anywhere,
        label: "Anyone".to_string(),
        subtitle: Some(anyone_note()),
        scope: Some(ScopeSpec::Anywhere),
        significant: true,
    });

    options
}

/// A port a user typed, or `None` for anything that is not a real, non-zero
/// port -- the exact rule the helper enforces
/// (`porthole_core::validate::parse_port`), checked here first so a bad port
/// never reaches the bus at all.
fn parse_port_for_submit(text: &str) -> Option<u16> {
    porthole_core::validate::parse_port(text.trim()).ok()
}

/// The scope string the helper's `open` expects: the exact vocabulary
/// `porthole_core::validate::parse_scope` re-parses on the privileged side.
/// This is what the CLI's own `--to` flag would have sent for the same
/// choice, never a rule this dialog composed itself.
fn scope_wire_string(scope: &ScopeSpec) -> String {
    match scope {
        ScopeSpec::CurrentSubnet => "subnet".to_string(),
        ScopeSpec::Anywhere => "any".to_string(),
        ScopeSpec::Network(net) => net.to_string(),
        ScopeSpec::Host(addr) => addr.to_string(),
    }
}

/// `seconds` as the wire's `open` expects it: 0 is the until-reboot
/// sentinel, exactly as `porthole-cli`'s own client sends it.
fn lifetime_wire_seconds(lifetime: Lifetime) -> u32 {
    match lifetime {
        Lifetime::For(d) => d.as_secs() as u32,
        Lifetime::UntilReboot => 0,
    }
}

/// One duration chip: the lifetime it represents, and the real
/// `gtk::ToggleButton` a test or a click reads back.
struct DurationChip {
    lifetime: Lifetime,
    button: gtk::ToggleButton,
}

/// One target row: the scope it represents, the real `adw::ActionRow` and
/// `gtk::CheckButton` a test or a click reads back, and the `gtk::Image`
/// built only for the significant entry.
/// [`OpenDialog::is_marked_significant`] does not trust this field's mere
/// `Some`-ness -- that would only prove an icon was *constructed*, not that
/// it was ever actually attached to `row` -- so it also checks the icon's
/// own `parent()` against the live widget tree.
struct TargetRow {
    /// `None` for a row that names no scope right now -- see
    /// [`TargetOption::scope`]. Such a row's `check` is insensitive, so
    /// nothing can make it the active one.
    scope: Option<ScopeSpec>,
    row: adw::ActionRow,
    check: gtk::CheckButton,
    significant_icon: Option<gtk::Image>,
}

/// The closure a caller registers via [`OpenDialog::on_opened`]. A type
/// alias rather than spelling `Box<dyn Fn(&WireRule)>` out inline at its one
/// field -- clippy's `type_complexity` flags the inline form (the actual
/// finding from this crate's own container gate, not a guess), the same
/// class of finding `tests/window.rs`'s own `Case` alias already fixed.
type OpenedCallback = Box<dyn Fn(&WireRule)>;

struct Inner {
    dialog: adw::Dialog,
    toast_overlay: adw::ToastOverlay,
    port_row: adw::EntryRow,
    /// TCP is index 0/default; this is the other half of that linked pair.
    udp_toggle: gtk::ToggleButton,
    /// Fixed for the dialog's whole lifetime -- unlike `target_rows`, no
    /// caller ever rebuilds the duration list, so this needs no `RefCell`.
    duration_chips: Vec<DurationChip>,
    target_group: adw::PreferencesGroup,
    /// Rebuilt by [`rebuild_targets`] whenever `set_current_network` learns
    /// a subnet or `set_devices` learns the saved devices.
    target_rows: RefCell<Vec<TargetRow>>,
    current_network: Cell<Option<Ipv4Net>>,
    /// The saved devices this dialog currently knows about, in the order
    /// they will appear between "This network" and "Anyone".
    devices: RefCell<Vec<DeviceEntry>>,
    /// Which target row is selected, tracked independently of the widgets
    /// so a rebuild (a new subnet, or a device list, becoming known) can
    /// restore the user's choice instead of silently resetting it to "This
    /// network". A [`TargetKey`], not an index -- see that type's own doc
    /// comment for what an index got wrong once devices could be inserted
    /// ahead of "Anyone".
    selected_target: RefCell<TargetKey>,
    /// Every port Docker currently publishes, or `None` for "porthole could
    /// not check". `None` is not an empty list: an empty list is a checked
    /// answer, and only a checked answer can say a port is *not* Docker's.
    docker: RefCell<Option<Vec<Published>>>,
    open_button: gtk::Button,
    on_opened: RefCell<Option<OpenedCallback>>,
}

impl Inner {
    fn show_toast(&self, message: &str) {
        self.toast_overlay.add_toast(adw::Toast::new(message));
    }
}

fn selected_protocol_of(inner: &Inner) -> Protocol {
    if inner.udp_toggle.is_active() {
        Protocol::Udp
    } else {
        Protocol::Tcp
    }
}

fn selected_lifetime_of(inner: &Inner) -> Lifetime {
    inner
        .duration_chips
        .iter()
        .find(|c| c.button.is_active())
        .map(|c| c.lifetime)
        .unwrap_or(Lifetime::For(DEFAULT_DURATION))
}

/// The scope of whichever target row is active, or `None` when no active
/// row names one.
///
/// `None`, not a default. Every default available here is *wider* than what
/// a row that failed to produce one might have meant -- `CurrentSubnet` is
/// a whole subnet where the row may have been a single host -- and a
/// fallback in this application has to narrow. `None` narrows all the way:
/// [`build_request`] returns `None` too, and the Open button sends nothing.
///
/// Unreachable as this dialog is built: row 0 is "This network", always
/// present, always selectable, and always what a rebuild falls back to. It
/// is a `None` rather than a default so that stops being load-bearing.
fn selected_scope_of(inner: &Inner) -> Option<ScopeSpec> {
    inner
        .target_rows
        .borrow()
        .iter()
        .find(|r| r.check.is_active())
        .and_then(|r| r.scope.clone())
}

fn build_request(inner: &Inner) -> Option<Request> {
    Some(Request {
        port: parse_port_for_submit(&inner.port_row.text())?,
        protocol: selected_protocol_of(inner),
        lifetime: selected_lifetime_of(inner),
        scope: selected_scope_of(inner)?,
    })
}

/// Rebuilds every row in `inner.target_group` from [`build_targets`],
/// keeping whichever target was selected before rather than resetting the
/// user's choice back to "This network" every time a subnet or a device
/// list becomes known. "Whichever target", by [`TargetKey`], not whichever
/// position: inserting devices moves "Anyone" down the list, and an index
/// carried across that rebuild would land on a device instead.
///
/// A row whose option carries no scope -- a saved device that does not
/// resolve right now -- is built insensitive, which is what makes it
/// visible and unselectable at once. It is also never what the restored
/// selection lands on: if the previously selected target is now such a row
/// (or is gone entirely), the selection falls back to "This network", the
/// one entry that is always present and always selectable.
fn rebuild_targets(inner: &Rc<Inner>) {
    for row in inner.target_rows.replace(Vec::new()) {
        inner.target_group.remove(&row.row);
    }

    let options = {
        let devices = inner.devices.borrow();
        build_targets(inner.current_network.get(), &devices)
    };
    let keep = inner.selected_target.borrow().clone();
    let keep_index = options
        .iter()
        .position(|o| o.key == keep && o.scope.is_some())
        .unwrap_or(0);
    if let Some(option) = options.get(keep_index) {
        inner.selected_target.replace(option.key.clone());
    }

    let mut rows = Vec::with_capacity(options.len());
    let mut first_check: Option<gtk::CheckButton> = None;
    for (index, option) in options.into_iter().enumerate() {
        let significant = option.significant;
        let selectable = option.scope.is_some();

        let check = gtk::CheckButton::new();
        match &first_check {
            Some(first) => check.set_group(Some(first)),
            None => first_check = Some(check.clone()),
        }
        check.set_active(index == keep_index);

        let key = option.key.clone();
        let inner_for_toggle = inner.clone();
        check.connect_toggled(move |c| {
            if c.is_active() {
                inner_for_toggle.selected_target.replace(key.clone());
            }
        });

        // `use_markup(false)`: a saved device's name is whatever the user
        // typed into `devices.toml`, and the title and subtitle of an
        // `AdwPreferencesRow` are parsed as Pango markup by default. A name
        // containing `&` or `<` is not markup a person meant to write.
        let action_row = adw::ActionRow::builder()
            .title(option.label)
            .use_markup(false)
            .build();
        if let Some(subtitle) = &option.subtitle {
            action_row.set_subtitle(subtitle);
        }
        action_row.add_prefix(&check);
        if selectable {
            action_row.set_activatable_widget(Some(&check));
        }
        action_row.set_sensitive(selectable);

        let significant_icon = if significant {
            let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
            icon.add_css_class("warning");
            icon.set_valign(gtk::Align::Center);
            icon.set_tooltip_text(Some(&anyone_note()));
            action_row.add_suffix(&icon);
            Some(icon)
        } else {
            None
        };

        inner.target_group.add(&action_row);
        rows.push(TargetRow {
            scope: option.scope,
            row: action_row,
            check,
            significant_icon,
        });
    }
    inner.target_rows.replace(rows);
}

/// The response id the Docker alert's "Open anyway" carries. The spec asks
/// for an explanation, not a prohibition, so this response exists and is a
/// real way through.
const DOCKER_RESPONSE_OPEN: &str = "open-anyway";

/// The response id for backing out, and the alert's own close response --
/// so dismissing the alert any other way (Escape, clicking away) is the
/// same outcome as pressing Cancel, never an accidental open.
const DOCKER_RESPONSE_CANCEL: &str = "cancel";

/// The alert that has to be answered before `request` is sent, or `None`
/// when there is nothing to explain.
///
/// Nothing to explain covers two different situations and deliberately
/// treats them the same way, exactly as `porthole-cli`'s own `open` does:
/// Docker was checked and has no rule for this port/protocol, and Docker
/// could not be checked at all (`inner.docker` is `None`). `porthole_core::
/// docker`'s own module doc is explicit that a warning on every open trains
/// a user to skip the one that matters; a warning that porthole could not
/// check, on every open, would do the same. The "Listening" section is
/// where that "could not check" fact is said instead, once, rather than at
/// every press of this button.
fn docker_alert_for(inner: &Inner, request: &Request) -> Option<adw::AlertDialog> {
    let published = inner.docker.borrow();
    let message = advise(request.port, request.protocol, published.as_deref()?)?;

    let alert = adw::AlertDialog::builder()
        .heading("Docker already publishes this port")
        .body(message)
        .body_use_markup(false)
        .close_response(DOCKER_RESPONSE_CANCEL)
        .default_response(DOCKER_RESPONSE_CANCEL)
        .build();
    alert.add_response(DOCKER_RESPONSE_CANCEL, "Cancel");
    alert.add_response(DOCKER_RESPONSE_OPEN, "Open Anyway");
    Some(alert)
}

/// The helper's own rendered text from a D-Bus method error, verbatim --
/// same shape and reason as `open_now::helper_message` and
/// `porthole-cli`'s own `client.rs::from_dbus`: the helper already phrased
/// this for a person, so this must not reword it.
fn helper_message(e: &zbus::Error) -> String {
    if let zbus::Error::MethodError(name, detail, _) = e {
        detail.clone().unwrap_or_else(|| name.to_string())
    } else {
        e.to_string()
    }
}

/// Sends exactly what `porthole-cli`'s own `client::open` sends. Same bus as
/// `open_now::close_by_id_over_dbus`: the **system** bus, the one the CLI
/// reaches the helper on by default, never the session bus `adw::Application`'s
/// own id lives on (see `app.rs`'s module doc for why those are not the same
/// bus despite sharing a name).
async fn open_over_dbus(
    port: u16,
    protocol: &str,
    scope: &str,
    seconds: u32,
) -> Result<WireRule, String> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|e| format!("could not reach the porthole helper: {e}"))?;
    let proxy = PortholeProxy::new(&connection)
        .await
        .map_err(|e| format!("could not reach the porthole helper: {e}"))?;
    proxy
        .open(port, protocol, scope, seconds)
        .await
        .map_err(|e| helper_message(&e))
}

/// Where a user chooses what to open, for how long, and towards whom.
pub struct OpenDialog {
    inner: Rc<Inner>,
}

impl Default for OpenDialog {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenDialog {
    pub fn new() -> Self {
        let port_row = adw::EntryRow::builder().title("Port").build();
        let port_group = adw::PreferencesGroup::builder().title("Port").build();
        port_group.add(&port_row);

        let tcp_toggle = gtk::ToggleButton::builder().label("TCP").build();
        tcp_toggle.set_active(true);
        let udp_toggle = gtk::ToggleButton::builder().label("UDP").build();
        udp_toggle.set_group(Some(&tcp_toggle));
        let protocol_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .homogeneous(true)
            .build();
        protocol_box.add_css_class("linked");
        protocol_box.append(&tcp_toggle);
        protocol_box.append(&udp_toggle);
        let protocol_group = adw::PreferencesGroup::builder().title("Protocol").build();
        protocol_group.add(&protocol_box);

        let duration_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .homogeneous(true)
            .build();
        duration_box.add_css_class("linked");
        let mut duration_chips = Vec::new();
        let mut first_duration_button: Option<gtk::ToggleButton> = None;
        for (label, lifetime) in duration_options() {
            let button = gtk::ToggleButton::builder().label(label).build();
            match &first_duration_button {
                Some(first) => button.set_group(Some(first)),
                None => first_duration_button = Some(button.clone()),
            }
            if lifetime == Lifetime::For(DEFAULT_DURATION) {
                button.set_active(true);
            }
            duration_box.append(&button);
            duration_chips.push(DurationChip { lifetime, button });
        }
        let duration_group = adw::PreferencesGroup::builder()
            .title("For how long")
            .build();
        duration_group.add(&duration_box);

        let target_group = adw::PreferencesGroup::builder()
            .title("Open towards")
            .build();

        let open_button = gtk::Button::builder()
            .label("Open")
            .css_classes(["suggested-action"])
            .halign(gtk::Align::End)
            .sensitive(false)
            .build();

        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(18)
            .margin_top(18)
            .margin_bottom(18)
            .margin_start(18)
            .margin_end(18)
            .build();
        content.append(&port_group);
        content.append(&protocol_group);
        content.append(&duration_group);
        content.append(&target_group);
        content.append(&open_button);

        let toast_overlay = adw::ToastOverlay::new();
        toast_overlay.set_child(Some(&content));

        let dialog = adw::Dialog::builder()
            .title("Open a port")
            .content_width(420)
            .child(&toast_overlay)
            .build();

        let inner = Rc::new(Inner {
            dialog,
            toast_overlay,
            port_row: port_row.clone(),
            udp_toggle,
            duration_chips,
            target_group,
            target_rows: RefCell::new(Vec::new()),
            current_network: Cell::new(None),
            devices: RefCell::new(Vec::new()),
            selected_target: RefCell::new(TargetKey::CurrentSubnet),
            docker: RefCell::new(None),
            open_button: open_button.clone(),
            on_opened: RefCell::new(None),
        });

        rebuild_targets(&inner);

        let inner_for_change = inner.clone();
        port_row.connect_changed(move |row| {
            inner_for_change
                .open_button
                .set_sensitive(parse_port_for_submit(&row.text()).is_some());
        });

        let inner_for_click = inner.clone();
        open_button.connect_clicked(move |_| {
            let Some(request) = build_request(&inner_for_click) else {
                return;
            };
            let inner = inner_for_click.clone();
            glib::spawn_future_local(async move {
                // The explanation comes *before* the request, and only
                // "Open Anyway" gets past it -- every other way out of the
                // alert, `DOCKER_RESPONSE_CANCEL` included, sends nothing.
                // An explanation, not a prohibition: see `docker_alert_for`.
                if let Some(alert) = docker_alert_for(&inner, &request) {
                    let response = alert.choose_future(&inner.dialog).await;
                    if response != DOCKER_RESPONSE_OPEN {
                        return;
                    }
                }
                let protocol = request.protocol.to_string();
                let scope = scope_wire_string(&request.scope);
                let seconds = lifetime_wire_seconds(request.lifetime);
                match open_over_dbus(request.port, &protocol, &scope, seconds).await {
                    Ok(rule) => {
                        if let Some(f) = inner.on_opened.borrow().as_ref() {
                            f(&rule);
                        }
                        inner.dialog.close();
                    }
                    Err(message) => inner.show_toast(&message),
                }
            });
        });

        Self { inner }
    }

    /// A dialog pre-filled with `port`, for a caller that already knows
    /// which port it means before presenting the dialog -- e.g. a specific
    /// listening service's own Open button, wherever one exists and is
    /// wired to this constructor.
    pub fn for_port(port: u16) -> Self {
        let dialog = Self::new();
        dialog.set_port_text(&port.to_string());
        dialog
    }

    /// The real duration chips' own displayed labels, read back from the
    /// actual `gtk::ToggleButton`s rather than recomputed independently of
    /// them.
    pub fn duration_labels(&self) -> Vec<String> {
        self.inner
            .duration_chips
            .iter()
            .map(|c| c.button.label().map(|s| s.to_string()).unwrap_or_default())
            .collect()
    }

    pub fn selected_lifetime(&self) -> Lifetime {
        selected_lifetime_of(&self.inner)
    }

    /// Every duration chip's lifetime, in the same order as
    /// [`OpenDialog::duration_labels`].
    pub fn all_lifetimes(&self) -> Vec<Lifetime> {
        self.inner
            .duration_chips
            .iter()
            .map(|c| c.lifetime)
            .collect()
    }

    /// Learns the actual subnet porthole would open towards by default, so
    /// "This network" can name it. Rebuilds the target list; the previously
    /// selected row stays selected.
    pub fn set_current_network(&self, net: Ipv4Net) {
        self.inner.current_network.set(Some(net));
        rebuild_targets(&self.inner);
    }

    /// The saved devices this dialog offers as targets, between "This
    /// network" and "Anyone". Rebuilds the target list; the previously
    /// selected target stays selected unless it is no longer selectable.
    pub fn set_devices(&self, devices: &[DeviceEntry]) {
        self.inner.target_group.set_description(None);
        self.inner.devices.replace(devices.to_vec());
        rebuild_targets(&self.inner);
    }

    /// The state for a caller that could not read the saved devices at all
    /// -- a different fact from "there are none saved", and one this dialog
    /// must not render as an empty device list. `reason` is the caller's own
    /// error text, shown under the group's title; no device rows are built.
    pub fn set_devices_unreadable(&self, reason: &str) {
        self.inner.devices.replace(Vec::new());
        rebuild_targets(&self.inner);
        self.inner.target_group.set_description(Some(reason));
    }

    /// Every port Docker currently publishes, as the helper's own
    /// `docker_ports` reported them. Only a list that actually arrived can
    /// say a port is *not* Docker's -- see
    /// [`OpenDialog::set_docker_unknown`] for the other case.
    pub fn set_docker_ports(&self, published: &[Published]) {
        self.inner.docker.replace(Some(published.to_vec()));
    }

    /// The state for a `docker_ports` call that never answered, or answered
    /// with an error: this dialog then explains nothing about Docker at all,
    /// rather than treating "could not check" as "checked, and Docker
    /// touches nothing here".
    pub fn set_docker_unknown(&self) {
        self.inner.docker.replace(None);
    }

    /// The alert pressing Open right now would present before sending
    /// anything, or `None` when there is nothing to explain. Built, not
    /// presented: the click handler goes through the same
    /// `docker_alert_for`, so a caller reading this reads the alert that
    /// handler would present rather than a lookalike built here.
    pub fn docker_alert(&self) -> Option<adw::AlertDialog> {
        let request = build_request(&self.inner)?;
        docker_alert_for(&self.inner, &request)
    }

    /// The real target rows' own displayed titles.
    pub fn target_labels(&self) -> Vec<String> {
        self.inner
            .target_rows
            .borrow()
            .iter()
            .map(|r| r.row.title().to_string())
            .collect()
    }

    /// The real target rows' own displayed subtitles, in the same order as
    /// [`OpenDialog::target_labels`]. An empty string for a row that has
    /// none ("This network").
    pub fn target_subtitles(&self) -> Vec<String> {
        self.inner
            .target_rows
            .borrow()
            .iter()
            .map(|r| r.row.subtitle().map(|s| s.to_string()).unwrap_or_default())
            .collect()
    }

    /// Whether target row `index` can be chosen at all, read back from the
    /// real widget's own sensitivity rather than from the data it was built
    /// from.
    ///
    /// By index, not by title, and so is [`OpenDialog::select_target`]: a
    /// device's name is arbitrary user text, so two rows can share a title
    /// -- a device named "Anyone" is enough -- and a title lookup would
    /// silently answer for whichever came first. Index against
    /// [`OpenDialog::target_labels`], which is in the same order.
    pub fn is_target_selectable(&self, index: usize) -> bool {
        self.inner
            .target_rows
            .borrow()
            .get(index)
            .is_some_and(|r| r.row.is_sensitive() && r.check.is_sensitive())
    }

    /// Chooses target row `index`, the way a click on it would. `false` --
    /// and nothing selected -- when there is no such row, or when it is one
    /// that cannot be chosen.
    pub fn select_target(&self, index: usize) -> bool {
        let rows = self.inner.target_rows.borrow();
        let Some(row) = rows.get(index).filter(|r| r.check.is_sensitive()) else {
            return false;
        };
        row.check.set_active(true);
        true
    }

    /// The group's own description line, or `None` when it has none --
    /// [`OpenDialog::set_devices_unreadable`]'s state.
    pub fn target_group_description(&self) -> Option<String> {
        self.inner
            .target_group
            .description()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    }

    /// The scope pressing Open would send, or `None` when no selectable
    /// target is active -- see [`selected_scope_of`] for why that is not a
    /// default.
    pub fn selected_scope(&self) -> Option<ScopeSpec> {
        selected_scope_of(&self.inner)
    }

    /// Whether target row `index` carries the significant-choice icon,
    /// checked against the live widget tree -- the icon's own `parent()` --
    /// rather than only whether `significant_icon` is `Some`. `Some` alone
    /// would only prove an icon was constructed; a future edit that built
    /// one and never reached `add_suffix` would leave it `Some` while
    /// nothing actually rendered, and `parent()` is what catches that.
    ///
    /// By index for the same reason [`OpenDialog::is_target_selectable`] is:
    /// a saved device's name is arbitrary user text, so a device named
    /// "Anyone" gives this list two rows with one title, and a title lookup
    /// would answer for whichever came first -- the device, which carries no
    /// marking, standing in for the row that does. Index against
    /// [`OpenDialog::target_labels`], which is in the same order.
    pub fn is_marked_significant(&self, index: usize) -> bool {
        self.inner.target_rows.borrow().get(index).is_some_and(|r| {
            r.significant_icon
                .as_ref()
                .is_some_and(|icon| icon.parent().is_some())
        })
    }

    /// The one dry sentence about what "Anyone" means -- see this module's
    /// own doc comment.
    pub fn note_for_anyone(&self) -> String {
        anyone_note()
    }

    /// `None` for anything that is not a real, non-zero port -- the exact
    /// rule the helper enforces.
    pub fn port(&self) -> Option<u16> {
        parse_port_for_submit(&self.inner.port_row.text())
    }

    pub fn set_port_text(&self, text: &str) {
        self.inner.port_row.set_text(text);
    }

    pub fn protocol(&self) -> Protocol {
        selected_protocol_of(&self.inner)
    }

    /// Whether pressing Open right now would send anything at all -- read
    /// from [`OpenDialog::request`] itself rather than from the port alone,
    /// so it cannot claim a request exists that `request` would decline to
    /// build. In practice the port is the only thing that makes it `false`:
    /// a duration chip and a selectable target are always active, by
    /// construction.
    pub fn can_submit(&self) -> bool {
        self.request().is_some()
    }

    /// The request pressing Open would send, or `None` under the same
    /// condition [`OpenDialog::can_submit`] reports `false` for.
    pub fn request(&self) -> Option<Request> {
        build_request(&self.inner)
    }

    /// The real "Open" button, for a test that wants to check its own state
    /// (sensitivity, focusability) rather than only the semantic
    /// [`OpenDialog::can_submit`].
    pub fn open_button(&self) -> &gtk::Button {
        &self.inner.open_button
    }

    /// Registers `f` to run with the [`WireRule`] a successful Open press
    /// produced. Left uncalled by anything in this crate when this method
    /// was first added; that changed once something needed to react to a
    /// successful open (a refresh, to pick up the new rule) and registered
    /// through here.
    pub fn on_opened(&self, f: impl Fn(&WireRule) + 'static) {
        *self.inner.on_opened.borrow_mut() = Some(Box::new(f));
    }

    /// The real `adw::Dialog` this wraps -- the parent anything presented
    /// *over* this dialog needs, which is what the Open button presents its
    /// own Docker explanation over.
    pub fn dialog(&self) -> &adw::Dialog {
        &self.inner.dialog
    }

    /// Presents the real `adw::Dialog`, transient for `parent`.
    pub fn present(&self, parent: Option<&impl IsA<gtk::Widget>>) {
        self.inner.dialog.present(parent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::validate::parse_scope;

    // Pure-function coverage, independent of GTK -- these run in the
    // crate's ordinary unit-test binary. The GTK-backed proof that the real
    // widgets carry this same data lives in `tests/open_dialog.rs`.

    #[test]
    fn the_duration_options_are_exactly_the_five_the_spec_names() {
        let labels: Vec<&str> = duration_options().iter().map(|(l, _)| *l).collect();
        assert_eq!(
            labels,
            vec!["15 minutes", "1 hour", "4 hours", "8 hours", "Until reboot"]
        );
    }

    #[test]
    fn no_duration_option_exceeds_the_ceiling() {
        for (label, lifetime) in duration_options() {
            if let Lifetime::For(d) = lifetime {
                assert!(d <= MAX_DURATION, "{label} ({d:?}) exceeds the ceiling");
            }
        }
    }

    #[test]
    fn the_one_hour_option_is_built_from_the_shared_default_constant() {
        // Belt and braces against the chip and the core's own default
        // drifting apart: this fails if a future edit hardcodes a second
        // "3600" here instead of reusing DEFAULT_DURATION.
        assert_eq!(
            duration_options()[1],
            ("1 hour", Lifetime::For(DEFAULT_DURATION))
        );
    }

    #[test]
    fn the_ceiling_option_is_built_from_the_shared_max_duration_constant() {
        // Mirrors `the_one_hour_option_is_built_from_the_shared_default_
        // constant` above, for the ceiling chip instead of the default one:
        // without this, lowering `MAX_DURATION` would leave this chip still
        // reading "8 hours" while sending whatever the constant actually is
        // now, with every other test here still green.
        assert_eq!(
            duration_options()[3],
            ("8 hours", Lifetime::For(MAX_DURATION))
        );
    }

    #[test]
    fn the_note_on_anyone_is_one_dry_sentence_with_no_scolding() {
        // Guards `anyone_note()` itself, which now covers four call sites,
        // not three: this dialog's own target row/icon/`note_for_anyone`,
        // plus `open_now.rs`'s "open to anyone" marking on an already-open
        // rule.
        let note = anyone_note();
        assert_eq!(note.matches('.').count(), 1, "one sentence: {note}");
        for scolding in ["careful", "dangerous", "warning", "risk", "are you sure"] {
            assert!(!note.to_lowercase().contains(scolding), "{note}");
        }
        assert!(note.contains("anyone your machine can reach"));
    }

    fn resolved_device(name: &str, addr: &str) -> DeviceEntry {
        DeviceEntry {
            name: name.to_string(),
            resolved: Ok(addr.parse().unwrap()),
        }
    }

    fn unresolved_device(name: &str, reason: &str) -> DeviceEntry {
        DeviceEntry {
            name: name.to_string(),
            resolved: Err(reason.to_string()),
        }
    }

    #[test]
    fn this_network_is_first_and_plain_before_a_subnet_is_known() {
        let targets = build_targets(None, &[]);
        assert_eq!(targets[0].label, "This network");
        assert_eq!(targets[0].scope, Some(ScopeSpec::CurrentSubnet));
        assert!(!targets[0].significant);
    }

    #[test]
    fn this_network_names_the_actual_subnet_once_known() {
        let net: Ipv4Net = "192.168.177.0/24".parse().unwrap();
        let targets = build_targets(Some(net), &[]);
        assert_eq!(targets[0].label, "This network (192.168.177.0/24)");
    }

    #[test]
    fn anyone_is_last_and_the_only_significant_entry() {
        let targets = build_targets(None, &[resolved_device("phone", "10.10.10.245")]);
        assert_eq!(targets.last().unwrap().label, "Anyone");
        assert_eq!(targets.last().unwrap().scope, Some(ScopeSpec::Anywhere));
        assert!(targets.last().unwrap().significant);
        assert!(targets[..targets.len() - 1].iter().all(|t| !t.significant));
    }

    #[test]
    fn saved_devices_sit_between_this_network_and_anyone_in_the_order_given() {
        // The spec's own order. `build_targets` is the one place the
        // insertion happens, so this is where it can be checked without a
        // display.
        let targets = build_targets(
            None,
            &[
                resolved_device("phone", "10.10.10.245"),
                resolved_device("laptop", "10.10.10.17"),
            ],
        );
        let labels: Vec<&str> = targets.iter().map(|t| t.label.as_str()).collect();
        assert_eq!(labels, vec!["This network", "phone", "laptop", "Anyone"]);
    }

    #[test]
    fn a_resolved_device_carries_the_address_it_would_open_towards() {
        let targets = build_targets(None, &[resolved_device("phone", "10.10.10.245")]);
        assert_eq!(
            targets[1].scope,
            Some(ScopeSpec::Host("10.10.10.245".parse().unwrap()))
        );
        assert_eq!(
            targets[1].subtitle.as_deref(),
            Some("resolves to 10.10.10.245")
        );
    }

    #[test]
    fn an_unresolvable_device_is_still_listed_and_says_why_but_names_no_scope() {
        // Hiding it would read as the device having been deleted. Keeping it
        // with a scope would offer an address porthole does not have.
        let reason = "`phone` (bc:24:11:5e:1c:6e) is not on this network right now";
        let targets = build_targets(None, &[unresolved_device("phone", reason)]);
        assert_eq!(targets[1].label, "phone");
        assert_eq!(targets[1].scope, None);
        assert_eq!(targets[1].subtitle.as_deref(), Some(reason));
    }

    #[test]
    fn an_unresolvable_devices_reason_is_the_resolvers_own_text_not_a_rewording() {
        // The two ways resolution fails -- the device is not on this
        // network, and the lookup itself could not run -- reach this dialog
        // as different sentences and stay different sentences. A subtitle
        // composed here from a bare `Option` could only ever say one of
        // them, for both.
        let absent = "`phone` (bc:24:11:5e:1c:6e) is not on this network right now";
        let broken = "command failed: ip -4 neigh show";
        assert_eq!(device_subtitle(&unresolved_device("phone", absent)), absent);
        assert_eq!(device_subtitle(&unresolved_device("phone", broken)), broken);
    }

    #[test]
    fn port_zero_does_not_parse_for_submit() {
        assert_eq!(parse_port_for_submit("0"), None);
    }

    #[test]
    fn a_real_port_parses_for_submit() {
        assert_eq!(parse_port_for_submit("5173"), Some(5173));
        assert_eq!(parse_port_for_submit(" 5173 "), Some(5173));
    }

    #[test]
    fn scope_wire_strings_round_trip_through_the_helpers_own_parser() {
        // This is what ties the dialog's wire vocabulary to the one the
        // helper actually re-validates -- not just "some string", the exact
        // one `parse_scope` accepts and turns back into the same ScopeSpec.
        let cases = [
            ScopeSpec::CurrentSubnet,
            ScopeSpec::Anywhere,
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
            ScopeSpec::Host("10.10.10.42".parse().unwrap()),
        ];
        for scope in cases {
            let wire = scope_wire_string(&scope);
            assert_eq!(parse_scope(&wire).unwrap(), scope, "round trip for {wire}");
        }
    }

    #[test]
    fn lifetime_seconds_use_zero_for_until_reboot_not_a_real_duration() {
        assert_eq!(lifetime_wire_seconds(Lifetime::UntilReboot), 0);
        assert_eq!(
            lifetime_wire_seconds(Lifetime::For(Duration::from_secs(3600))),
            3600
        );
    }
}
