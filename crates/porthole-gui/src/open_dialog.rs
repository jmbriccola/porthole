//! The open dialog: where a user chooses what to open, for how long, and
//! towards whom.
//!
//! Two of its choices are the project's central safety decisions, not
//! preferences.
//!
//! **The duration ceiling.** [`duration_options`] holds the five fixed
//! choices the spec names -- 15 minutes, 1 hour (the default), 4 hours, 8
//! hours, until reboot -- none of them above
//! [`porthole_core::model::MAX_DURATION`], which is what makes porthole's
//! "temporary" promise true. A chip offering more than the ceiling would be
//! refused by the helper, and refusing something the app itself put on
//! screen is an avoidable dead end.
//!
//! A sixth chip, "Custom", reveals a field for any duration `porthole open
//! --for` accepts, so this dialog is not narrower than the tool it fronts on
//! the one axis the product is about. What that field's text means is
//! decided by [`porthole_core::validate::parse_duration`] -- the same
//! function the privileged side runs on what reaches it -- called here
//! rather than restated, so the two cannot come to disagree about zero, the
//! ceiling, or the grammar. The refusal is that function's. What this file
//! does with it is narrower and worth stating exactly: it puts that error's
//! own text on screen and leaves the Open button insensitive, so a duration
//! the tool will not take is visible before anything is sent rather than
//! after.
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
//! Beside that list's heading is a button, and
//! [`OpenDialog::on_manage_devices`] is the slot for what it does. This
//! dialog does not know what that is: the saved-devices dialog it reaches is
//! `window.rs`'s business, exactly as [`OpenDialog::on_opened`] already is.
//! What that button is for is the gap it closes -- the address book was
//! readable here and writable only from a terminal.
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
//! ## The other act this dialog performs
//!
//! [`OpenDialog::for_forward`] builds the same widgets for a different
//! request: `forward` rather than `open`, for the container that publishes
//! a given port on this machine. The two are not variants of one act --
//! `open` permits traffic to something the network already reached, a
//! forward redirects a port into something it did not -- and this project
//! keeps acts with different consequences apart, down to separate polkit
//! actions with separate messages. What is shared is only what a person has
//! to decide: for how long, and towards whom.
//!
//! One control is missing in that mode rather than disabled. The helper
//! forwards TCP only, so the protocol chooser is hidden and the port
//! field's own description says which protocol this is -- a control that
//! can only be refused is not a choice, and a disabled one with no
//! explanation is worse than none.
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

use crate::busy::BusyIndicator;

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

/// The five fixed duration chips, in this exact order and exactly these
/// five -- see this module's own doc comment for why the ceiling matters.
/// The "Custom" chip beside them names no lifetime of its own and is not
/// here; it stands for whatever [`parse_custom_duration`] makes of the
/// field it reveals.
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
/// identical choice -- `open_now.rs`'s marking on an already-anywhere-scoped
/// rule -- and calls this directly rather than keeping its own, separate
/// copy of the sentence (an earlier version did exactly that, worded
/// slightly differently, outside every guard that keeps these three in
/// sync).
///
/// ## It names no act, and that is the whole constraint on its wording
///
/// The four sites are not four views of one act. Two of them belong to an
/// `open` (this dialog built by [`OpenDialog::for_port`], and an open rule's
/// row) and two to a `forward` ([`OpenDialog::for_forward`], and a forward's
/// row): "Anyone" means the same thing in both -- the rich rule drops its
/// `source address` clause, so it matches traffic from anywhere -- and it is
/// the *only* thing about the two acts that is the same.
///
/// So this sentence must describe the scope and nothing else. It used to
/// open with "Opens the port to…", which was not merely the wrong verb on a
/// forwarding dialog: an accept for the external port is the one rule
/// `porthole_core::backend::firewalld`'s own `forward` was measured into
/// *not* writing, because on a host with a service of its own bound to that
/// number it would expose that service too. The sentence described to a user
/// the exact effect the design refuses to produce.
///
/// `the_note_on_anyone_is_one_dry_sentence_with_no_scolding` is what holds
/// this: it fails on any wording that names either act.
///
/// The object was wrong too, and for longer than the verb was. "anyone
/// **your machine can reach**" describes outbound reachability, which is not
/// what a rule does: the rich rule drops its `source address` clause, so
/// what changes is which sources this machine will answer. The same guard
/// now fails on that direction as well.
pub(crate) fn anyone_note() -> String {
    "Lets in anyone who can reach this machine, not just devices on this network.".to_string()
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

/// The label on the chip that reveals the custom-duration field.
const CUSTOM_DURATION_LABEL: &str = "Custom";

/// What one duration chip stands for: either a lifetime fixed at build
/// time, or whatever the custom field currently holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurationChoice {
    Fixed(Lifetime),
    Custom,
}

/// What the custom-duration field holds right now.
enum CustomDuration {
    /// Nothing typed. Not an error to put on screen -- a field the user has
    /// only just revealed has not got anything wrong yet -- but not a
    /// duration either, so nothing is submittable.
    Empty,
    /// [`porthole_core::validate::parse_duration`]'s own rendered error,
    /// verbatim. Not reworded here: the same sentence is what the helper
    /// answers a request the GUI failed to stop, and two wordings of one
    /// refusal is how the interface and the tool start disagreeing.
    Invalid(String),
    Valid(Duration),
}

/// Reads `text` with [`porthole_core::validate::parse_duration`] -- zero,
/// the ceiling and the one-value-one-unit grammar are all that function's
/// rules, applied here to the field rather than described a second time.
///
/// Trimmed first, exactly as [`parse_port_for_submit`] trims: surrounding
/// spaces are not something a person meant to type, and `parse_duration`
/// rejects them.
fn parse_custom_duration(text: &str) -> CustomDuration {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return CustomDuration::Empty;
    }
    match porthole_core::validate::parse_duration(trimmed) {
        Ok(duration) => CustomDuration::Valid(duration),
        Err(e) => CustomDuration::Invalid(e.to_string()),
    }
}

/// One duration chip: what it stands for, and the real `gtk::ToggleButton`
/// a test or a click reads back.
struct DurationChip {
    choice: DurationChoice,
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
    /// Held so [`OpenDialog::for_forward`] can say, under the port field,
    /// what a forward does with what arrives there.
    port_group: adw::PreferencesGroup,
    /// Held for the same reason, to be hidden: the helper forwards TCP
    /// only, and a choice that can only be refused is not one.
    protocol_group: adw::PreferencesGroup,
    /// The port Docker publishes the container on, when this dialog
    /// forwards rather than opens -- `None` for an ordinary open, which is
    /// what [`OpenDialog::new`] builds. It decides which method the button
    /// sends and whether the Docker explanation is shown at all; the rest
    /// of the dialog is the same either way.
    forward: Cell<Option<u16>>,
    /// TCP is index 0/default; this is the other half of that linked pair.
    udp_toggle: gtk::ToggleButton,
    /// Fixed for the dialog's whole lifetime -- unlike `target_rows`, no
    /// caller ever rebuilds the duration list, so this needs no `RefCell`.
    duration_chips: Vec<DurationChip>,
    /// Shown only while the "Custom" chip is the active one.
    custom_revealer: gtk::Revealer,
    custom_row: adw::EntryRow,
    /// [`CustomDuration::Invalid`]'s text, and hidden whenever there is
    /// none. Hidden rather than emptied so nothing reserves a blank line.
    custom_error: gtk::Label,
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
    /// The button beside the "Open towards" heading, and the slot
    /// `window.rs` fills so pressing it can present the saved-devices
    /// dialog. This dialog knows nothing about that one -- the same shape
    /// `on_opened` already uses, and for the same reason: only `window.rs`
    /// knows about more than one of these at a time.
    manage_devices_button: gtk::Button,
    on_manage_devices: RefCell<Option<Box<dyn Fn()>>>,
    open_button: gtk::Button,
    /// This dialog's own busy indication for the `open` its button sends.
    /// `refresh_submit_state` reads it as well as `disable_while_busy`
    /// holding `open_button`: a keystroke in the port field while the
    /// helper is still deciding would otherwise recompute the button
    /// sensitive again mid-flight.
    busy: BusyIndicator,
    on_opened: RefCell<Option<OpenedCallback>>,
}

impl Inner {
    fn show_toast(&self, message: &str) {
        self.toast_overlay.add_toast(adw::Toast::new(message));
    }
}

/// The protocol pressing the button would send.
///
/// **A forward is TCP, and this is what makes that a fact.** The port
/// field's description on a forward dialog says "Forwards are TCP", and
/// [`OpenDialog::for_forward`] hides `protocol_group` -- but hiding a
/// toggle is not clearing it, and this read the toggle regardless. Nothing
/// today can activate a hidden one, so the sentence was true by the order
/// the widgets happen to be built in rather than by anything holding it
/// true. `porthole-core` refuses a UDP forward (exit 13), so the failure
/// mode was a refusal rather than an exposure; it is still a sentence the
/// code did not enforce.
fn selected_protocol_of(inner: &Inner) -> Protocol {
    if inner.forward.get().is_some() {
        return Protocol::Tcp;
    }
    if inner.udp_toggle.is_active() {
        Protocol::Udp
    } else {
        Protocol::Tcp
    }
}

/// The lifetime pressing Open would send, or `None` when the active chip
/// names none: "Custom" with a field that is empty, or one holding text
/// [`parse_custom_duration`] refuses.
///
/// `None`, not a default, and for the same reason [`selected_scope_of`]
/// answers `None`: every default available here is a duration the user did
/// not ask for, and silently substituting one for a value the tool refuses
/// is the clamping this field exists not to do. [`build_request`] returns
/// `None` too, and the Open button sends nothing.
fn selected_lifetime_of(inner: &Inner) -> Option<Lifetime> {
    match inner
        .duration_chips
        .iter()
        .find(|c| c.button.is_active())
        .map(|c| c.choice)
    {
        Some(DurationChoice::Fixed(lifetime)) => Some(lifetime),
        Some(DurationChoice::Custom) => match parse_custom_duration(&inner.custom_row.text()) {
            CustomDuration::Valid(duration) => Some(Lifetime::For(duration)),
            CustomDuration::Empty | CustomDuration::Invalid(_) => None,
        },
        None => None,
    }
}

/// Puts the custom field into whatever state the chips and its own text
/// currently ask for, and sets the Open button's sensitivity from
/// [`build_request`] itself rather than from the port alone.
///
/// Called from every signal that can change any of those three -- the port
/// entry, each chip, and the custom field. One function rather than a
/// handler each: a later signal has one place to be connected to, instead
/// of three that would have to agree.
fn refresh_submit_state(inner: &Inner) {
    let custom_active = inner
        .duration_chips
        .iter()
        .any(|c| c.choice == DurationChoice::Custom && c.button.is_active());
    inner.custom_revealer.set_reveal_child(custom_active);

    let problem = match (
        custom_active,
        parse_custom_duration(&inner.custom_row.text()),
    ) {
        (true, CustomDuration::Invalid(message)) => Some(message),
        _ => None,
    };
    match &problem {
        Some(message) => {
            inner.custom_error.set_text(message);
            inner.custom_error.set_visible(true);
            inner.custom_row.add_css_class("error");
        }
        None => {
            inner.custom_error.set_visible(false);
            inner.custom_row.remove_css_class("error");
        }
    }

    inner
        .open_button
        .set_sensitive(!inner.busy.is_busy() && build_request(inner).is_some());
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
        lifetime: selected_lifetime_of(inner)?,
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
    // Not on a forward. This explanation exists to tell someone opening a
    // port that Docker already publishes it, which is news; on a forward it
    // is the premise, and the sentence it would show is `advise`'s own
    // loopback one -- "opening this port here does not make it reachable" --
    // about a port this dialog is not opening.
    if inner.forward.get().is_some() {
        return None;
    }
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

/// [`open_over_dbus`]'s counterpart for the other act: the same bus, the
/// same un-resolved `scope` string, and one more number -- the port Docker
/// publishes the container on, which is what the helper resolves to a
/// container address of its own accord. This client sends no address.
///
/// Sends exactly what `porthole-cli`'s own `client::forward` sends. The
/// helper authorizes this one every time, whatever the scope; nothing here
/// decides that, and nothing here can skip it.
async fn forward_over_dbus(
    port: u16,
    protocol: &str,
    scope: &str,
    seconds: u32,
    published_port: u16,
) -> Result<WireRule, String> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|e| format!("could not reach the porthole helper: {e}"))?;
    let proxy = PortholeProxy::new(&connection)
        .await
        .map_err(|e| format!("could not reach the porthole helper: {e}"))?;
    proxy
        .forward(port, protocol, scope, seconds, published_port)
        .await
        .map_err(|e| helper_message(&e))
}

/// Where a user chooses what to open, for how long, and towards whom.
///
/// `Clone` is another handle on the same dialog, never a second dialog:
/// `window.rs` keeps one so a saved device written while this dialog is on
/// screen can be pushed straight back into its target list.
#[derive(Clone)]
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

        // A `gtk::FlowBox`, not the single homogeneous "linked" row this
        // was: that row could not shrink at all, and was the whole of this
        // dialog's minimum width. Its five chips did not wrap and did not
        // ellipsize, so its minimum equalled its natural -- 570 px, measured
        // in the container, which with this content box's own 18 px side
        // margins is exactly the 606 px libadwaita then clipped in any
        // narrower window. A `FlowBox` reflows instead: `min_children_per_
        // line(1)` is what lets its minimum fall to one chip's width.
        let duration_box = gtk::FlowBox::builder()
            .orientation(gtk::Orientation::Horizontal)
            .selection_mode(gtk::SelectionMode::None)
            .homogeneous(true)
            .min_children_per_line(1)
            .max_children_per_line(3)
            .row_spacing(6)
            .column_spacing(6)
            .build();
        let mut duration_chips = Vec::new();
        let mut first_duration_button: Option<gtk::ToggleButton> = None;
        let chips = duration_options()
            .into_iter()
            .map(|(label, lifetime)| (label, DurationChoice::Fixed(lifetime)))
            .chain(std::iter::once((
                CUSTOM_DURATION_LABEL,
                DurationChoice::Custom,
            )));
        for (label, choice) in chips {
            let button = gtk::ToggleButton::builder().label(label).build();
            match &first_duration_button {
                Some(first) => button.set_group(Some(first)),
                None => first_duration_button = Some(button.clone()),
            }
            if choice == DurationChoice::Fixed(Lifetime::For(DEFAULT_DURATION)) {
                button.set_active(true);
            }
            // `insert(.., -1)` appends. `FlowBox::append` is gtk4-rs's
            // `v4_6`-gated binding and this crate takes gtk4's default
            // features; `gtk_flow_box_insert` has been there since 4.0.
            duration_box.insert(&button, -1);
            // The chip a click and a Tab both land on is the button. The
            // `GtkFlowBoxChild` the line above wraps it in is focusable by
            // default, which would put a second, empty stop in the dialog's
            // keyboard order for every chip.
            if let Some(cell) = button.parent() {
                cell.set_focusable(false);
            }
            duration_chips.push(DurationChip { choice, button });
        }

        let custom_row = adw::EntryRow::builder()
            .title("Custom duration (for example 20m)")
            .build();
        let custom_list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        // What gives a row outside an `AdwPreferencesGroup` the same
        // rounded card the "Port" row above has.
        custom_list.add_css_class("boxed-list");
        custom_list.append(&custom_row);

        let custom_error = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .visible(false)
            .build();
        custom_error.add_css_class("error");
        custom_error.add_css_class("caption");

        let custom_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .margin_top(6)
            .build();
        custom_box.append(&custom_list);
        custom_box.append(&custom_error);
        let custom_revealer = gtk::Revealer::builder()
            .child(&custom_box)
            .reveal_child(false)
            .build();

        let duration_container = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();
        duration_container.append(&duration_box);
        duration_container.append(&custom_revealer);

        let duration_group = adw::PreferencesGroup::builder()
            .title("For how long")
            .build();
        duration_group.add(&duration_container);

        let target_group = adw::PreferencesGroup::builder()
            .title("Open towards")
            .build();
        // Beside the heading of the list it adds to: the need for a saved
        // device arises here, while choosing who to open towards, and until
        // this button existed the only way to create one was a terminal.
        let manage_devices_button = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text("Save a device")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        target_group.set_header_suffix(Some(&manage_devices_button));

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
        // The spinner sits beside the Open button, in the same row, so
        // what is waiting is next to what was pressed. Hidden until
        // `crate::busy::BUSY_DELAY` has gone by -- see `busy.rs`.
        let busy = BusyIndicator::new();
        busy.spinner()
            .set_tooltip_text(Some("Waiting for the porthole helper"));
        let actions = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .halign(gtk::Align::End)
            .build();
        actions.append(busy.spinner());
        actions.append(&open_button);

        content.append(&target_group);
        content.append(&actions);

        // The dialog scrolls rather than being cut off. `adw::Dialog` puts
        // no scroller around its child, so whatever the child asks for is
        // what it asks the window for: measured in the container at the
        // window's own default 480x560, this content asks for 750 px of
        // height, libadwaita warns `AdwFloatingSheet exceeds
        // AdwBreakpointBin height: requested 750 px, 550 px available`, and
        // the Open button is simply not on screen -- with no scrollbar to
        // reach it. `hscrollbar_policy(Never)` keeps the width side exactly
        // as it was: the minimum still comes from the content, so nothing
        // here can hide a widget that refuses to narrow.
        let scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .propagate_natural_width(true)
            .propagate_natural_height(true)
            .child(&content)
            .build();

        let toast_overlay = adw::ToastOverlay::new();
        toast_overlay.set_child(Some(&scroller));

        let dialog = adw::Dialog::builder()
            .title("Open a port")
            .content_width(420)
            .child(&toast_overlay)
            .build();

        let inner = Rc::new(Inner {
            dialog,
            toast_overlay,
            port_row: port_row.clone(),
            port_group,
            protocol_group,
            forward: Cell::new(None),
            udp_toggle,
            duration_chips,
            custom_revealer,
            custom_row: custom_row.clone(),
            custom_error,
            target_group,
            target_rows: RefCell::new(Vec::new()),
            current_network: Cell::new(None),
            devices: RefCell::new(Vec::new()),
            selected_target: RefCell::new(TargetKey::CurrentSubnet),
            docker: RefCell::new(None),
            manage_devices_button: manage_devices_button.clone(),
            on_manage_devices: RefCell::new(None),
            open_button: open_button.clone(),
            busy: busy.clone(),
            on_opened: RefCell::new(None),
        });
        busy.disable_while_busy(&open_button);

        rebuild_targets(&inner);

        // Every signal that can change what `build_request` answers goes to
        // the same function. The Open button's sensitivity is no longer the
        // port's alone: a "Custom" chip over an empty or refused field makes
        // a request unbuildable with a perfectly good port typed.
        let inner_for_change = inner.clone();
        port_row.connect_changed(move |_| refresh_submit_state(&inner_for_change));
        let inner_for_custom = inner.clone();
        custom_row.connect_changed(move |_| refresh_submit_state(&inner_for_custom));
        for chip in &inner.duration_chips {
            let inner_for_chip = inner.clone();
            chip.button
                .connect_toggled(move |_| refresh_submit_state(&inner_for_chip));
        }

        let inner_for_manage = inner.clone();
        manage_devices_button.connect_clicked(move |_| {
            if let Some(f) = inner_for_manage.on_manage_devices.borrow().as_ref() {
                f();
            }
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
                // Started here rather than at the press: the Docker
                // explanation above is the user reading something, not
                // porthole waiting for anything. Held across the call and
                // dropped on the way out of this block, whichever way that
                // is -- see `busy.rs`.
                let busy = inner.busy.begin();
                // Which of the two acts this dialog is for was decided at
                // construction and cannot change while it is on screen --
                // see `OpenDialog::for_forward`.
                let outcome = match inner.forward.get() {
                    Some(published_port) => {
                        forward_over_dbus(request.port, &protocol, &scope, seconds, published_port)
                            .await
                    }
                    None => open_over_dbus(request.port, &protocol, &scope, seconds).await,
                };
                drop(busy);
                match outcome {
                    Ok(rule) => {
                        if let Some(f) = inner.on_opened.borrow().as_ref() {
                            f(&rule);
                        }
                        // Only if it is still on screen. An `open` is a
                        // round trip nothing here can cancel, so the user
                        // can dismiss this dialog while one is outstanding
                        // and the reply still arrives -- and closing an
                        // `adw::Dialog` that is no longer presented logs a
                        // GTK critical. A presented dialog has a root; a
                        // dismissed one does not.
                        if inner.dialog.root().is_some() {
                            inner.dialog.close();
                        }
                    }
                    Err(message) => {
                        // The dialog stays open on a failure, so the button
                        // has to come back to whatever the form now
                        // actually justifies -- `disable_while_busy` alone
                        // would hand it back sensitive regardless.
                        refresh_submit_state(&inner);
                        inner.show_toast(&message);
                    }
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

    /// The same dialog for the other act: pressing its button sends the
    /// helper's `forward` for the container that publishes
    /// `published_port` on this machine, never `open`.
    ///
    /// What a person has to decide is the same -- for how long, and towards
    /// whom -- so the duration chips, the target list and the saved devices
    /// are all as they were. Four things differ on screen:
    ///
    /// - the port field, renamed to the port the local network connects to
    ///   (`porthole forward --as`) and pre-filled with the published port,
    ///   because that is what omitting `--as` means;
    /// - a sentence under it saying where what arrives there goes, and
    ///   naming the published port it goes to;
    /// - the target list's heading and the button's label, so the act being
    ///   chosen for is named at the two places a person looks;
    /// - the protocol, which is not offered at all: the helper forwards TCP
    ///   only, and the description above carries that fact rather than a
    ///   control sitting there refusing.
    ///
    /// A fifth difference is **not** on screen and is not claimed to be: the
    /// dialog's title. This dialog carries no `adw::HeaderBar`, so its title
    /// is what a screen reader announces and what a test can identify it by,
    /// never text a sighted user reads. It is set all the same, for both of
    /// those.
    ///
    /// A sixth is an absence, which says nothing by itself: the Docker
    /// explanation is suppressed -- see `docker_alert_for` for why showing
    /// it here would be worse than showing nothing.
    ///
    /// The container's address is not among any of them, and never crosses
    /// from here: the helper resolves `published_port` against Docker's own
    /// table at the moment it acts.
    pub fn for_forward(published_port: u16) -> Self {
        let dialog = Self::new();
        let inner = &dialog.inner;
        inner.forward.set(Some(published_port));
        inner.dialog.set_title("Forward a port");
        inner.port_row.set_title("Port on the network");
        inner.port_group.set_description(Some(&format!(
            "What arrives on this port from the network is redirected to the container \
             that publishes {published_port} on this machine. Forwards are TCP."
        )));
        inner.protocol_group.set_visible(false);
        inner.target_group.set_title("Forward towards");
        inner.open_button.set_label("Forward");
        dialog.set_port_text(&published_port.to_string());
        dialog
    }

    /// The real duration chips' own displayed labels, read back from the
    /// actual `gtk::ToggleButton`s rather than recomputed independently of
    /// them. The five fixed choices, then "Custom".
    pub fn duration_labels(&self) -> Vec<String> {
        self.inner
            .duration_chips
            .iter()
            .map(|c| c.button.label().map(|s| s.to_string()).unwrap_or_default())
            .collect()
    }

    /// One real chip button, by index against
    /// [`OpenDialog::duration_labels`], so a caller can press it
    /// (`emit_clicked`) instead of setting state a click would have set.
    pub fn duration_button(&self, index: usize) -> Option<gtk::ToggleButton> {
        self.inner
            .duration_chips
            .get(index)
            .map(|c| c.button.clone())
    }

    /// `None` when the active chip names no lifetime -- see
    /// [`selected_lifetime_of`].
    pub fn selected_lifetime(&self) -> Option<Lifetime> {
        selected_lifetime_of(&self.inner)
    }

    /// Every chip lifetime that is fixed at build time. The "Custom" chip
    /// contributes none: what it stands for is whatever is typed into the
    /// field it reveals, which is why it is checked against the ceiling by
    /// [`parse_custom_duration`] on every keystroke rather than once here.
    pub fn all_lifetimes(&self) -> Vec<Lifetime> {
        self.inner
            .duration_chips
            .iter()
            .filter_map(|c| match c.choice {
                DurationChoice::Fixed(lifetime) => Some(lifetime),
                DurationChoice::Custom => None,
            })
            .collect()
    }

    /// Whether the custom-duration field is on screen right now, read from
    /// the real `gtk::Revealer` rather than from which chip is active.
    pub fn custom_duration_is_revealed(&self) -> bool {
        self.inner.custom_revealer.reveals_child()
    }

    /// Types `text` into the real custom-duration field, the way a person
    /// would -- the row's own `changed` signal fires, so everything that
    /// signal drives runs.
    pub fn set_custom_duration_text(&self, text: &str) {
        self.inner.custom_row.set_text(text);
    }

    /// The message currently shown under the custom-duration field, or
    /// `None` when none is. Read from the real label, including its own
    /// visibility: a label holding stale text it is no longer showing must
    /// not answer here.
    pub fn custom_duration_error(&self) -> Option<String> {
        let label = &self.inner.custom_error;
        label
            .is_visible()
            .then(|| label.text().to_string())
            .filter(|t| !t.is_empty())
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

    /// What the target list is headed -- "Open towards" or "Forward
    /// towards", which is the heading a person reads directly above the
    /// choice they are about to make.
    pub fn target_group_title(&self) -> String {
        self.inner.target_group.title().to_string()
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

    /// What the port field is actually called on screen.
    ///
    /// Not the same thing in the two acts, and this is the one difference a
    /// person looking at the dialog cannot miss: the number an `open` takes
    /// is the port a service on this machine already listens on, and the
    /// number a forward takes is a port on the network that nothing here
    /// answers on yet. Read off the real `adw::EntryRow`, so a test checking
    /// it is checking what is rendered.
    ///
    /// Worth pinning separately from [`OpenDialog::dialog`]'s own title:
    /// this dialog has no `adw::HeaderBar`, so its title is metadata (and
    /// what a screen reader announces), never text on screen. A check that
    /// only compared titles would prove which constructor ran and nothing
    /// about what a person sees.
    pub fn port_field_title(&self) -> String {
        self.inner.port_row.title().to_string()
    }

    /// The sentence under the port field, or `None` when there is none --
    /// an ordinary open, where a field called "Port" needs no explaining.
    pub fn port_group_description(&self) -> Option<String> {
        self.inner
            .port_group
            .description()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    }

    /// Whether the protocol chooser is on screen at all.
    ///
    /// `false` only on a forwarding dialog: the helper forwards TCP only, so
    /// the control is hidden rather than shown refusing, and the port
    /// field's own description carries the fact instead. Read off the
    /// group's own `visible` property, not a second record of the decision.
    pub fn offers_a_protocol_choice(&self) -> bool {
        self.inner.protocol_group.is_visible()
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

    /// The UDP toggle itself, so a caller can press it rather than set state
    /// a press would have set -- the reason [`OpenDialog::duration_button`]
    /// exists.
    ///
    /// On a forwarding dialog the whole protocol row is hidden and nothing a
    /// person can do reaches this button. That is what made "Forwards are
    /// TCP" true by construction *order* rather than by construction, and
    /// what this accessor exists to let a test drive around:
    /// [`selected_protocol_of`] is what makes it a fact.
    pub fn udp_button(&self) -> gtk::ToggleButton {
        self.inner.udp_toggle.clone()
    }

    /// Whether pressing Open right now would send anything at all -- read
    /// from [`OpenDialog::request`] itself rather than from the port alone,
    /// so it cannot claim a request exists that `request` would decline to
    /// build. Two things make it `false`: a port
    /// `porthole_core::validate::parse_port` refuses, and a "Custom"
    /// duration `porthole_core::validate::parse_duration` refuses (or has
    /// not been given yet). A selectable target is always active, by
    /// construction.
    pub fn can_submit(&self) -> bool {
        self.request().is_some()
    }

    /// The request pressing Open would send, or `None` under the same
    /// condition [`OpenDialog::can_submit`] reports `false` for.
    pub fn request(&self) -> Option<Request> {
        build_request(&self.inner)
    }

    /// Which of the two acts this dialog performs: `Some(published_port)`
    /// when pressing its button sends the helper's `forward` for the
    /// container publishing that port, `None` when it sends `open`.
    ///
    /// This is the value the click handler itself reads, not a second
    /// record of the same decision -- so a caller checking it is checking
    /// what would actually be sent.
    pub fn forwards(&self) -> Option<u16> {
        self.inner.forward.get()
    }

    /// The real "Open" button, for a test that wants to check its own state
    /// (sensitivity, focusability) rather than only the semantic
    /// [`OpenDialog::can_submit`].
    pub fn open_button(&self) -> &gtk::Button {
        &self.inner.open_button
    }

    /// This dialog's own busy indication for the `open` its button sends --
    /// `is_busy()` for "porthole is waiting for an answer", `is_showing()`
    /// for "and it has been waiting long enough to say so on screen". A
    /// test reads these to check that an open clears them again however it
    /// ends, the dialog being dismissed mid-flight included.
    pub fn busy(&self) -> &BusyIndicator {
        &self.inner.busy
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
    /// The button beside the "Open towards" heading, for a caller that
    /// wants to press it (`emit_clicked`) or read its state back.
    pub fn manage_devices_button(&self) -> &gtk::Button {
        &self.inner.manage_devices_button
    }

    /// What that button does, registered by `window.rs` -- see
    /// [`OpenDialog::on_opened`] for the same shape and the same reason.
    pub fn on_manage_devices(&self, f: impl Fn() + 'static) {
        self.inner.on_manage_devices.replace(Some(Box::new(f)));
    }

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
    fn a_custom_duration_the_helper_would_take_is_taken_here_too() {
        for (text, secs) in [("20m", 1200u64), ("45s", 45), ("2h", 7200), (" 20m ", 1200)] {
            match parse_custom_duration(text) {
                CustomDuration::Valid(d) => assert_eq!(d, Duration::from_secs(secs), "{text}"),
                CustomDuration::Empty => panic!("{text} read as empty"),
                CustomDuration::Invalid(m) => panic!("{text} refused: {m}"),
            }
        }
    }

    #[test]
    fn an_empty_custom_duration_is_not_an_error_and_is_not_a_duration() {
        // A field the user has only just revealed has not got anything
        // wrong yet, so there is nothing to say about it -- but there is
        // also nothing to send.
        assert!(matches!(parse_custom_duration(""), CustomDuration::Empty));
        assert!(matches!(
            parse_custom_duration("   "),
            CustomDuration::Empty
        ));
    }

    #[test]
    fn zero_and_anything_over_the_ceiling_are_refused_here() {
        for bad in [
            "0m", "0s", "9h", "481m", "28801s", "24h", "20", "1h30m", "-5m", "abc",
        ] {
            assert!(
                matches!(parse_custom_duration(bad), CustomDuration::Invalid(_)),
                "{bad} was not refused"
            );
        }
    }

    #[test]
    fn the_refusal_shown_is_the_cores_own_sentence_not_a_second_wording() {
        // The point of calling `parse_duration` rather than restating its
        // rules: this asserts the *text* too, so a reworded copy in this
        // file would fail here rather than drift quietly away from what the
        // helper answers for the same input.
        for bad in ["0m", "9h", "20"] {
            let expected = porthole_core::validate::parse_duration(bad)
                .unwrap_err()
                .to_string();
            match parse_custom_duration(bad) {
                CustomDuration::Invalid(message) => assert_eq!(message, expected, "{bad}"),
                _ => panic!("{bad} was not refused"),
            }
        }
    }

    #[test]
    fn the_ceiling_this_field_refuses_at_is_max_duration_itself() {
        // Not "8h": `MAX_DURATION` in seconds, and one second past it. A
        // future change to the constant moves both sides of this together,
        // which is the property that makes the field and the helper agree
        // without a second literal here.
        let at_ceiling = format!("{}s", MAX_DURATION.as_secs());
        let over = format!("{}s", MAX_DURATION.as_secs() + 1);
        assert!(matches!(
            parse_custom_duration(&at_ceiling),
            CustomDuration::Valid(_)
        ));
        assert!(matches!(
            parse_custom_duration(&over),
            CustomDuration::Invalid(_)
        ));
    }

    #[test]
    fn the_note_on_anyone_is_one_dry_sentence_with_no_scolding() {
        // Guards `anyone_note()` itself, which now covers four call sites,
        // not three: this dialog's own target row/icon/`note_for_anyone`,
        // plus `open_now.rs`'s marking on an already-anywhere-scoped rule.
        let note = anyone_note();
        assert_eq!(note.matches('.').count(), 1, "one sentence: {note}");
        for scolding in ["careful", "dangerous", "warning", "risk", "are you sure"] {
            assert!(!note.to_lowercase().contains(scolding), "{note}");
        }
        // The direction matters and was wrong. "anyone your machine can
        // reach" describes *outbound* reachability; the rich rule drops its
        // `source address` clause, so what changes is who can reach the
        // machine. A reader of the old sentence concluded that opening to
        // "Anyone" let their machine talk to more of the world; a reader of
        // this one concludes that more of the world can talk to this port,
        // which is the fact.
        assert!(
            note.contains("anyone who can reach this machine"),
            "the note must say who reaches the machine, not who the machine \
             reaches: {note}"
        );
        assert!(
            !note.contains("your machine can reach"),
            "the wrong direction, which the sentence carried for four call \
             sites: {note}"
        );

        // And it names neither act. Two of the four sites belong to an
        // `open` and two to a `forward`, so a sentence naming either is
        // false at half of them -- and the one it used to name, "opens the
        // port", is the accept `firewalld.rs`'s `forward` was measured into
        // never writing. Without this the previous wording passes every
        // assertion above, which is exactly how it survived.
        let lowered = note.to_lowercase();
        for act in ["open", "forward", "redirect"] {
            assert!(
                !lowered.contains(act),
                "the note is shared by both acts and must name neither ({act}): {note}"
            );
        }
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
