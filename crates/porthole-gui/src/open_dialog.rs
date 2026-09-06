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
//! **"Anyone".** [`build_targets`] always puts it last, marks it (an icon,
//! not colour alone -- colour alone fails a colour-blind user and a
//! high-contrast theme), and never preselects it. [`anyone_note`] is the one
//! dry sentence the spec asks for: "niente toni allarmistici o didattici,
//! solo una frase asciutta su cosa comporta." A warning that lectures gets
//! dismissed unread, which makes the genuinely significant choice less safe,
//! not more.
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
//! [`build_targets`] takes the current subnet as a plain argument and
//! returns a `Vec`, rather than the target list being a fixed set of
//! widgets. Milestone 5's saved devices are an insertion between "This
//! network" and "Anyone" in that one function -- a data change, not a
//! redesign.
//!
//! ## One thing this task left for a later one, on purpose
//!
//! [`OpenDialog::on_opened`] is a hook a caller can register to learn a
//! request actually succeeded (the new [`WireRule`] the helper returned).
//! This task left it uncalled, because refreshing "Open now" belongs with
//! whatever later gives this window a real, repeatable refresh action, not
//! with the dialog that merely triggered one open -- and task 6 is that
//! later task: `window.rs`'s header-bar button and each of the "Listening"
//! section's own per-row Open buttons now register it, so a successful
//! open re-populates both sections and the status line from the helper and
//! `/proc` again, the same refresh construction itself already runs.
//!
//! And, like [`crate::open_now::OpenNowSection`]'s close button before it,
//! the "Open" button's real D-Bus round trip has no automated test: the
//! container this milestone tests in runs no live helper, so a click's
//! success or failure path is exercised by inspection, not by CI. What *is*
//! tested is everything the round trip depends on being right before it ever
//! reaches the bus -- the request built from the widgets, and the exact
//! strings and seconds that request turns into.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;
use ipnet::Ipv4Net;

use porthole_core::ipc::{PortholeProxy, WireRule};
use porthole_core::model::{Lifetime, Protocol, ScopeSpec, DEFAULT_DURATION};

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
/// see this module's own doc comment for why the ceiling matters. Every
/// `Lifetime::For` here is `<= MAX_DURATION` by construction; the "1 hour"
/// entry is built from [`DEFAULT_DURATION`] rather than a second hardcoded
/// `3600`, so the two can never quietly drift apart.
fn duration_options() -> Vec<(&'static str, Lifetime)> {
    vec![
        ("15 minutes", Lifetime::For(Duration::from_secs(15 * 60))),
        ("1 hour", Lifetime::For(DEFAULT_DURATION)),
        ("4 hours", Lifetime::For(Duration::from_secs(4 * 60 * 60))),
        ("8 hours", Lifetime::For(Duration::from_secs(8 * 60 * 60))),
        ("Until reboot", Lifetime::UntilReboot),
    ]
}

/// One dry sentence about what "Anyone" means, reused verbatim everywhere
/// this dialog mentions it (the target row's subtitle, its icon's tooltip,
/// and [`OpenDialog::note_for_anyone`]) so the three cannot drift into
/// different claims about the same choice.
fn anyone_note() -> String {
    "Opens the port to anyone your machine can reach, not just devices on this network.".to_string()
}

/// One row of the target list: what the user can open towards, and whether
/// it is significant enough to need marking.
struct TargetOption {
    label: String,
    scope: ScopeSpec,
    /// Only "Anyone" is `true`. Marked in the rendered row by an icon, not
    /// colour alone.
    significant: bool,
}

/// "This network" first, named by its actual subnet once a caller has
/// supplied one (plain "This network" before that -- still a real, selected
/// option, not a placeholder); "Anyone" always last and the only entry
/// marked significant. Milestone 5 inserts saved devices between the two --
/// this is the one place that insertion happens, which is what makes it a
/// data change rather than a redesign.
fn build_targets(current_network: Option<Ipv4Net>) -> Vec<TargetOption> {
    vec![
        TargetOption {
            label: match current_network {
                Some(net) => format!("This network ({net})"),
                None => "This network".to_string(),
            },
            scope: ScopeSpec::CurrentSubnet,
            significant: false,
        },
        TargetOption {
            label: "Anyone".to_string(),
            scope: ScopeSpec::Anywhere,
            significant: true,
        },
    ]
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
/// `gtk::CheckButton` a test or a click reads back, and the icon that exists
/// only for the significant entry -- its presence *is* the marking
/// [`OpenDialog::is_marked_significant`] reports, not a separately tracked
/// flag that could drift from what is actually on screen.
struct TargetRow {
    scope: ScopeSpec,
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
    /// a subnet -- milestone 5 rebuilds it again to insert saved devices.
    target_rows: RefCell<Vec<TargetRow>>,
    current_network: Cell<Option<Ipv4Net>>,
    /// Which target row is selected, tracked independently of the widgets
    /// so a rebuild (a new subnet becoming known) can restore the user's
    /// choice instead of silently resetting it to "This network".
    selected_target_index: Cell<usize>,
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

fn selected_scope_of(inner: &Inner) -> ScopeSpec {
    inner
        .target_rows
        .borrow()
        .iter()
        .find(|r| r.check.is_active())
        .map(|r| r.scope.clone())
        .unwrap_or(ScopeSpec::CurrentSubnet)
}

fn build_request(inner: &Inner) -> Option<Request> {
    Some(Request {
        port: parse_port_for_submit(&inner.port_row.text())?,
        protocol: selected_protocol_of(inner),
        lifetime: selected_lifetime_of(inner),
        scope: selected_scope_of(inner),
    })
}

/// Rebuilds every row in `inner.target_group` from [`build_targets`],
/// keeping whichever index was selected before (clamped to the new list's
/// length) rather than resetting the user's choice back to "This network"
/// every time a subnet becomes known.
fn rebuild_targets(inner: &Rc<Inner>) {
    for row in inner.target_rows.replace(Vec::new()) {
        inner.target_group.remove(&row.row);
    }

    let options = build_targets(inner.current_network.get());
    let keep_index = inner
        .selected_target_index
        .get()
        .min(options.len().saturating_sub(1));

    let mut rows = Vec::with_capacity(options.len());
    let mut first_check: Option<gtk::CheckButton> = None;
    for (index, option) in options.into_iter().enumerate() {
        let significant = option.significant;

        let check = gtk::CheckButton::new();
        match &first_check {
            Some(first) => check.set_group(Some(first)),
            None => first_check = Some(check.clone()),
        }
        check.set_active(index == keep_index);

        let inner_for_toggle = inner.clone();
        check.connect_toggled(move |c| {
            if c.is_active() {
                inner_for_toggle.selected_target_index.set(index);
            }
        });

        let action_row = adw::ActionRow::builder()
            .title(option.label)
            .activatable_widget(&check)
            .build();
        action_row.add_prefix(&check);

        let significant_icon = if significant {
            action_row.set_subtitle(&anyone_note());
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
            selected_target_index: Cell::new(0),
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

    /// A dialog pre-filled with `port`, the way a click on the listening
    /// list's own Open button arrives at this dialog.
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

    /// The real target rows' own displayed titles.
    pub fn target_labels(&self) -> Vec<String> {
        self.inner
            .target_rows
            .borrow()
            .iter()
            .map(|r| r.row.title().to_string())
            .collect()
    }

    pub fn selected_scope(&self) -> ScopeSpec {
        selected_scope_of(&self.inner)
    }

    /// Whether the target row titled `label` carries the significant-choice
    /// icon -- the actual visual marking, not a copy of the data that
    /// produced it.
    pub fn is_marked_significant(&self, label: &str) -> bool {
        self.inner
            .target_rows
            .borrow()
            .iter()
            .find(|r| r.row.title() == label)
            .is_some_and(|r| r.significant_icon.is_some())
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

    /// Whether pressing Open right now would send anything at all. Only the
    /// port can make this `false`: a duration chip and a target are always
    /// selected, by construction.
    pub fn can_submit(&self) -> bool {
        self.port().is_some()
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
    /// produced. See this module's own doc comment: nothing in this crate
    /// calls this yet.
    pub fn on_opened(&self, f: impl Fn(&WireRule) + 'static) {
        *self.inner.on_opened.borrow_mut() = Some(Box::new(f));
    }

    /// Presents the real `adw::Dialog`, transient for `parent`.
    pub fn present(&self, parent: Option<&impl IsA<gtk::Widget>>) {
        self.inner.dialog.present(parent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::model::MAX_DURATION;
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
    fn the_note_on_anyone_is_one_dry_sentence_with_no_scolding() {
        let note = anyone_note();
        assert_eq!(note.matches('.').count(), 1, "one sentence: {note}");
        for scolding in ["careful", "dangerous", "warning", "risk", "are you sure"] {
            assert!(!note.to_lowercase().contains(scolding), "{note}");
        }
        assert!(note.contains("anyone your machine can reach"));
    }

    #[test]
    fn this_network_is_first_and_plain_before_a_subnet_is_known() {
        let targets = build_targets(None);
        assert_eq!(targets[0].label, "This network");
        assert_eq!(targets[0].scope, ScopeSpec::CurrentSubnet);
        assert!(!targets[0].significant);
    }

    #[test]
    fn this_network_names_the_actual_subnet_once_known() {
        let net: Ipv4Net = "192.168.177.0/24".parse().unwrap();
        let targets = build_targets(Some(net));
        assert_eq!(targets[0].label, "This network (192.168.177.0/24)");
    }

    #[test]
    fn anyone_is_last_and_the_only_significant_entry() {
        let targets = build_targets(None);
        assert_eq!(targets.last().unwrap().label, "Anyone");
        assert_eq!(targets.last().unwrap().scope, ScopeSpec::Anywhere);
        assert!(targets.last().unwrap().significant);
        assert!(targets[..targets.len() - 1].iter().all(|t| !t.significant));
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
