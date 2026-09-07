//! The saved-devices dialog: where the address book is read and written.
//!
//! Before this module the window could only *read* the address book. A
//! device could be offered as a target in the open dialog, and there was no
//! way to put one there except a terminal -- which made the feature
//! invisible to anyone using porthole as an application. This is where one
//! is created.
//!
//! ## Two ways to name a device, one rule for each field
//!
//! `porthole devices add` is discovery-only: it prints the neighbour table
//! and takes a number, so a MAC cannot be mistyped and a device that is not
//! present cannot be saved. This dialog keeps that picker and adds a field
//! for typing a MAC by hand, for a device that is currently switched off.
//! The picker fills the field rather than standing beside it as a second
//! source of truth: pressing a row is a way of writing into the one entry
//! the save actually reads.
//!
//! What that field accepts is decided by
//! [`porthole_core::devices::parse_mac`], and what the name field accepts by
//! [`porthole_core::devices::validate_device_name`] -- the same two
//! functions `porthole devices add` calls and the same two `Book::load`
//! re-applies to a hand-edited file. Called here, never restated: a name
//! containing `/` or `:` is refused for the reason that function gives (such
//! a name is read by `--to` as a network or an IP address, so the device
//! could be saved and then never reached), and a refusal this dialog worded
//! for itself is how the interface and the tool start disagreeing about what
//! is saveable. The refusals on screen are those functions' own text.
//!
//! ## What saving a typed MAC does and does not establish
//!
//! A typed MAC is saved whether or not the device is here. That is the point
//! of the field: the device may be switched off. So the save is not gated on
//! the device being found, and the dialog does not pretend the save verified
//! anything either -- after writing the book it re-reads it, resolves every
//! device in it exactly as `porthole devices list` does, and puts
//! `porthole_core::devices::resolve`'s own sentence on screen for the device
//! just saved when that resolution did not succeed. A device in that state
//! still gets a row in the open dialog's target list, carrying its own
//! reason and unselectable; `porthole open --to <name>` refuses it with exit
//! code 6.
//!
//! A resolution that *did* succeed is reported as what it is -- the address
//! the device holds right now -- and nothing more. `porthole_core::net::
//! neighbours`'s own doc comment is explicit that a neighbour entry means
//! the kernel has a mapping recorded and has not disproved it, `STALE`
//! entries included; it is not a reachability test and nothing here sends a
//! packet to make one.
//!
//! ## Where the address book is, and who never sees it
//!
//! `~/.config/porthole/devices.toml`, read and written in this process. The
//! privileged helper never learns that devices exist: it is handed an
//! already-resolved address at the moment a port is opened, which is what
//! keeps its validation surface small. Nothing in this module goes near the
//! bus.
//!
//! Reading the book resolves every device in it, and each resolution runs a
//! subprocess. So every read and every write here goes to GLib's own I/O
//! thread pool via `gio::spawn_blocking`, never to the UI thread -- the same
//! shape `window.rs`'s own device load already uses.

use std::cell::{Cell, RefCell};
use std::net::Ipv4Addr;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use porthole_core::command::RealRunner;
use porthole_core::devices::{self, Device, DeviceAddress};
use porthole_core::net;

use crate::quiet::{quiet_note, TroubleNote};

/// One saved device as this dialog renders it: its name, the address the
/// book records for it, and either the address it resolves to right now or
/// the reason it does not.
///
/// The address and the resolution are two different things and both are
/// shown. `bc:24:11:5e:1c:6e` is what was saved and never changes; the
/// address behind it is a DHCP lease that does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedDevice {
    pub name: String,
    /// The MAC or hostname the book records, as written.
    pub address: String,
    /// `Ok` is the address the device holds right now; `Err` is
    /// [`porthole_core::devices::resolve`]'s own rendered text.
    pub resolved: Result<Ipv4Addr, String>,
}

/// One entry of the kernel's neighbour table, as the picker offers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighbourChoice {
    pub mac: String,
    pub address: Ipv4Addr,
    pub interface: String,
    /// What this machine's resolver answered for `address`, where it
    /// answered anything. A hint for the person choosing a row; the MAC is
    /// what the row saves.
    pub name: Option<String>,
}

/// What the neighbour row under a picked device reads.
///
/// The name goes first because it is the part a person can recognise, and
/// stays in the subtitle because the title is the MAC -- which is the
/// identity, the thing the row writes into the field, and the thing the
/// book records. A saved device's title is a name its owner chose; putting
/// a resolver's answer in that same position would make the two look like
/// the same kind of thing.
///
/// A row the resolver answered nothing for reads exactly as it did before:
/// address and interface, with nothing standing in for the missing name.
fn neighbour_subtitle(choice: &NeighbourChoice) -> String {
    match &choice.name {
        Some(name) => format!("{name} · {} on {}", choice.address, choice.interface),
        None => format!("{} on {}", choice.address, choice.interface),
    }
}

/// What a saved device's row reads under its name.
///
/// Two shapes, because the two facts are not the same. A device that
/// resolved is reported as resolving, in the same words the open dialog's
/// own target row uses. A device that did not carries
/// [`porthole_core::devices::resolve`]'s own sentence, which already names
/// the device and the address it was looked up under -- so nothing is
/// prefixed to it here.
fn saved_subtitle(device: &SavedDevice) -> String {
    match &device.resolved {
        Ok(address) => format!("{} · resolves to {address} right now", device.address),
        Err(reason) => reason.clone(),
    }
}

/// What a field a person is still typing into currently holds.
///
/// Same three states, and the same reason for the first one, as the open
/// dialog's own custom-duration field: an empty field has not got anything
/// wrong yet, so it is not an error to put on screen -- but it is not a
/// value either, and nothing is saveable without one.
enum Field {
    Empty,
    /// The refusing function's own rendered error, verbatim.
    Invalid(String),
    Valid(String),
}

impl Field {
    fn error(&self) -> Option<&str> {
        match self {
            Field::Invalid(message) => Some(message),
            _ => None,
        }
    }

    fn value(&self) -> Option<&str> {
        match self {
            Field::Valid(value) => Some(value),
            _ => None,
        }
    }
}

/// Reads the name field with
/// [`porthole_core::devices::validate_device_name`] -- the empty name, a
/// name the scope grammar would swallow (`subnet`, `any`, an IP, a CIDR)
/// and a name containing `/` or `:` are all that function's rules, applied
/// to the field rather than described a second time here.
fn parsed_name(text: &str) -> Field {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Field::Empty;
    }
    match devices::validate_device_name(trimmed) {
        Ok(()) => Field::Valid(trimmed.to_string()),
        Err(e) => Field::Invalid(e.to_string()),
    }
}

/// Reads the MAC field with [`porthole_core::devices::parse_mac`], which is
/// also what lower-cases it: a MAC picked out of the neighbour table is
/// already lower-case, and one typed in capitals must be saved as the same
/// thing.
fn parsed_mac(text: &str) -> Field {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Field::Empty;
    }
    match devices::parse_mac(trimmed) {
        Ok(mac) => Field::Valid(mac),
        Err(e) => Field::Invalid(e.to_string()),
    }
}

/// The device the Save button would write, or `None` when either field does
/// not currently hold a value the address book would take.
fn build_device(inner: &Inner) -> Option<Device> {
    let name = parsed_name(&inner.name_row.text());
    let mac = parsed_mac(&inner.mac_row.text());
    Some(Device {
        name: name.value()?.to_string(),
        address: DeviceAddress::Mac(mac.value()?.to_string()),
    })
}

/// Puts both fields' errors on screen (or takes them off), marks the
/// neighbour row whose MAC the field currently holds, and sets the Save
/// button's sensitivity from [`build_device`] itself.
///
/// One function reached from every signal that can change any of it -- both
/// entries and every neighbour row -- rather than a handler each, for the
/// reason the open dialog's own `refresh_submit_state` gives: a later signal
/// has one place to be connected to instead of several that would have to
/// agree.
fn refresh_save_state(inner: &Inner) {
    let name = parsed_name(&inner.name_row.text());
    let mac = parsed_mac(&inner.mac_row.text());
    show_field_error(&inner.name_error, inner.name_row.upcast_ref(), name.error());
    show_field_error(&inner.mac_error, inner.mac_row.upcast_ref(), mac.error());

    let chosen = mac.value().map(|m| m.to_string());
    for row in inner.neighbour_rows.borrow().iter() {
        row.picked
            .set_visible(Some(row.mac.as_str()) == chosen.as_deref());
    }

    inner
        .save_button
        .set_sensitive(!inner.saving.get() && build_device(inner).is_some());
}

/// A field's refusal, on screen under the card and marked on the row
/// itself. Hidden rather than emptied so nothing reserves a blank line, and
/// the row's own `error` class so which of the two fields is meant does not
/// rest on reading the message.
fn show_field_error(label: &gtk::Label, row: &gtk::Widget, message: Option<&str>) {
    match message {
        Some(message) => {
            label.set_text(message);
            label.set_visible(true);
            row.add_css_class("error");
        }
        None => {
            label.set_visible(false);
            row.remove_css_class("error");
        }
    }
}

/// One neighbour row: the MAC it offers, the real `adw::ActionRow` a click
/// or a test activates, and the tick that marks it as the one the MAC field
/// currently holds.
struct NeighbourRow {
    mac: String,
    row: adw::ActionRow,
    picked: gtk::Image,
}

/// One saved-device row: the real widget, and its own Forget button. The
/// name is not kept beside them -- [`DevicesDialog::saved_labels`] reads it
/// back off the row, so what a caller sees is what is actually on screen
/// rather than a second copy that could disagree with it.
struct SavedRow {
    row: adw::ActionRow,
    forget: gtk::Button,
}

/// What was just written to the book, so the note under the Save button can
/// say which of the two things happened. `Book::add` replaces any device of
/// the same name, exactly as `porthole devices add` does, and a person who
/// has just overwritten a device should be told that rather than left to
/// notice the list did not grow.
struct Announcement {
    name: String,
    replaced: bool,
}

/// The book and the neighbour table, each with its own failure: one can be
/// unreadable while the other answers, and neither renders as the other
/// being empty.
struct Loaded {
    saved: Result<Vec<SavedDevice>, String>,
    seen: Result<Vec<NeighbourChoice>, String>,
}

/// Reads the address book and the neighbour table. Blocking -- resolving a
/// device runs a subprocess, and so does listing neighbours -- so every
/// caller runs this on GLib's I/O thread pool.
///
/// Each device's own resolution failure stays that device's own: an absent
/// phone does not hide the laptop that is here. Only the book itself failing
/// to load produces the outer `Err`, since then there are no devices to
/// report at all. Identical in shape, and for the identical reason, to
/// `window.rs`'s own `load_devices`.
fn load_everything() -> Loaded {
    let runner = RealRunner;
    let path = devices::default_path();
    let saved = match devices::Book::load(&path) {
        Ok(book) => Ok(book
            .devices()
            .iter()
            .map(|d| SavedDevice {
                name: d.name.clone(),
                address: match &d.address {
                    DeviceAddress::Mac(mac) => mac.clone(),
                    DeviceAddress::Host(host) => host.clone(),
                },
                resolved: devices::resolve(&book, &d.name, &runner).map_err(|e| e.to_string()),
            })
            .collect()),
        Err(e) => Err(e.to_string()),
    };
    let seen = net::neighbours(&runner)
        .map(|found| {
            // One `getent` per address, bounded twice over -- see
            // `porthole_core::net::resolver_names`. This runs on the I/O
            // thread pool with the rest of `load_everything`, so the bound
            // is what keeps the dialog's own load from dragging, not what
            // keeps the UI thread responsive.
            let addresses: Vec<Ipv4Addr> = found.iter().map(|n| n.address).collect();
            let names = net::resolver_names(&runner, &addresses);
            found
                .into_iter()
                .zip(names)
                .map(|(n, name)| NeighbourChoice {
                    mac: n.mac,
                    address: n.address,
                    interface: n.interface,
                    name,
                })
                .collect()
        })
        .map_err(|e| e.to_string());
    Loaded { saved, seen }
}

/// Writes `device` into the book, answering whether it replaced one of the
/// same name. Blocking, like [`load_everything`], and run the same way.
fn save_device(device: &Device) -> Result<bool, String> {
    let path = devices::default_path();
    let mut book = devices::Book::load(&path).map_err(|e| e.to_string())?;
    let replaced = book.find(&device.name).is_some();
    book.add(device.clone());
    book.save(&path).map_err(|e| e.to_string())?;
    Ok(replaced)
}

/// Removes `name` from the book. Blocking, and run the same way.
fn forget_device(name: &str) -> Result<(), String> {
    let path = devices::default_path();
    let mut book = devices::Book::load(&path).map_err(|e| e.to_string())?;
    book.remove(name);
    book.save(&path).map_err(|e| e.to_string())
}

/// The note under the Save button after a write: what happened, and then
/// what the freshly re-read book says about the device just written.
///
/// The second sentence is [`porthole_core::devices::resolve`]'s own text
/// whenever the resolution failed -- the case the typed-MAC field exists
/// for. It is not reworded and nothing is prefixed to it: that sentence
/// already names the device and the address it was looked up under. When
/// the resolution succeeded, the sentence says what it resolves to right
/// now, in the same words the open dialog's own target row uses, and claims
/// nothing beyond that.
///
/// `true` in the returned pair means the note is about something the user
/// will want to act on later, not about a failure now: the device was
/// saved either way.
fn note_after_write(loaded: &Loaded, announcement: &Announcement) -> (String, bool) {
    let verb = if announcement.replaced {
        "Replaced"
    } else {
        "Saved"
    };
    let row = loaded
        .saved
        .as_ref()
        .ok()
        .and_then(|rows| rows.iter().find(|r| r.name == announcement.name));
    // An em dash rather than a full stop, so the sentence after it can be
    // the resolver's own text unaltered: that text begins lower-case (it is
    // an `Error`'s rendered form, e.g. "device not reachable: ...") and
    // reads as a fragment after a full stop.
    match row.map(|r| &r.resolved) {
        Some(Ok(address)) => (
            format!(
                "{verb} — `{}` resolves to {address} right now",
                announcement.name
            ),
            false,
        ),
        Some(Err(reason)) => (format!("{verb} — {reason}"), true),
        None => (format!("{verb} `{}`", announcement.name), false),
    }
}

type ChangedCallback = Box<dyn Fn()>;

struct Inner {
    dialog: adw::Dialog,
    toast_overlay: adw::ToastOverlay,
    name_row: adw::EntryRow,
    name_error: gtk::Label,
    mac_row: adw::EntryRow,
    mac_error: gtk::Label,
    /// Where the picker's rows go. Rebuilt whenever [`DevicesDialog::
    /// set_neighbours`] or [`DevicesDialog::set_neighbours_unavailable`] is
    /// called.
    neighbour_list: gtk::ListBox,
    neighbour_rows: RefCell<Vec<NeighbourRow>>,
    /// "Nothing has been seen on this network yet" -- an answered question
    /// with an empty answer.
    neighbours_quiet: gtk::Label,
    /// Shown only while some row carries a name, since it explains where
    /// those names came from and there is nothing to explain otherwise.
    names_caption: gtk::Label,
    /// Deliberately a different widget of a different type from the line
    /// above: "there is nothing here" and "porthole could not find out" must
    /// not be readable as each other. See `quiet.rs`.
    neighbours_trouble: TroubleNote,
    save_button: gtk::Button,
    /// What the last write did, and what the re-read book then said about
    /// it. Hidden when there is nothing to say.
    note: gtk::Label,
    /// Held while a write is outstanding, so a second press cannot send a
    /// second one. `refresh_save_state` reads it, not only the click
    /// handler: a keystroke in either field while a write is in flight
    /// would otherwise compute the button sensitive again.
    saving: Cell<bool>,
    saved_group: adw::PreferencesGroup,
    saved_rows: RefCell<Vec<SavedRow>>,
    /// Whatever is standing in for the list right now -- the quiet "no
    /// devices yet" line or the trouble note -- so it can be taken off
    /// again. `None` when real rows are showing.
    saved_placeholder: RefCell<Option<gtk::Widget>>,
    on_changed: RefCell<Option<ChangedCallback>>,
}

impl Inner {
    fn show_toast(&self, message: &str) {
        self.toast_overlay.add_toast(adw::Toast::new(message));
    }

    fn set_note(&self, message: Option<(String, bool)>) {
        match message {
            Some((text, warn)) => {
                self.note.set_text(&text);
                self.note.set_visible(true);
                if warn {
                    self.note.add_css_class("warning");
                } else {
                    self.note.remove_css_class("warning");
                }
            }
            None => {
                self.note.set_visible(false);
                self.note.remove_css_class("warning");
            }
        }
    }
}

/// Takes whatever is currently standing in for the saved-device list off
/// the group, and every row with it.
fn clear_saved(inner: &Inner) {
    for row in inner.saved_rows.replace(Vec::new()) {
        inner.saved_group.remove(&row.row);
    }
    if let Some(widget) = inner.saved_placeholder.replace(None) {
        inner.saved_group.remove(&widget);
    }
}

/// Rebuilds the saved-device list from `devices`, or puts the quiet "none
/// yet" line in its place.
fn rebuild_saved(inner: &Rc<Inner>, devices: &[SavedDevice]) {
    clear_saved(inner);
    if devices.is_empty() {
        let note = quiet_note(
            "No devices saved yet. Save one above and it becomes a target in the open dialog.",
        );
        inner.saved_group.add(&note);
        inner
            .saved_placeholder
            .replace(Some(note.upcast::<gtk::Widget>()));
        return;
    }

    let mut rows = Vec::with_capacity(devices.len());
    for device in devices {
        // `use_markup(false)`: a device's name and the resolution error
        // under it are not markup anyone here wrote -- the name is whatever
        // a person typed, and `AdwPreferencesRow` parses both title and
        // subtitle as Pango markup by default.
        let row = adw::ActionRow::builder()
            .title(&device.name)
            .subtitle(saved_subtitle(device))
            .use_markup(false)
            .build();

        let forget = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text(format!("Forget {}", device.name))
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        let inner_for_forget = inner.clone();
        let name = device.name.clone();
        forget.connect_clicked(move |_| {
            confirm_forget(&inner_for_forget, &name);
        });
        row.add_suffix(&forget);

        inner.saved_group.add(&row);
        rows.push(SavedRow { row, forget });
    }
    inner.saved_rows.replace(rows);
}

/// The saved-device list replaced by the reason there is none -- which is
/// not the same fact as there being no saved devices, and is deliberately
/// not rendered as it.
fn show_saved_unreadable(inner: &Rc<Inner>, reason: &str) {
    clear_saved(inner);
    let trouble = TroubleNote::new();
    trouble.set_title("Could not read the saved devices");
    trouble.set_description(reason);
    inner.saved_group.add(trouble.widget());
    inner
        .saved_placeholder
        .replace(Some(trouble.widget().clone().upcast::<gtk::Widget>()));
}

/// Rebuilds the picker from `seen`. Activating a row writes its MAC into
/// the field below the name -- the picker fills the one entry the save
/// reads rather than being a second source of truth beside it.
fn rebuild_neighbours(inner: &Rc<Inner>, seen: &[NeighbourChoice]) {
    for row in inner.neighbour_rows.replace(Vec::new()) {
        inner.neighbour_list.remove(&row.row);
    }
    inner.neighbours_trouble.widget().set_visible(false);
    inner.neighbours_quiet.set_visible(seen.is_empty());
    inner.neighbour_list.set_visible(!seen.is_empty());
    inner
        .names_caption
        .set_visible(seen.iter().any(|c| c.name.is_some()));

    let mut rows = Vec::with_capacity(seen.len());
    for choice in seen {
        let row = adw::ActionRow::builder()
            .title(&choice.mac)
            .subtitle(neighbour_subtitle(choice))
            .use_markup(false)
            .activatable(true)
            .build();
        let picked = gtk::Image::from_icon_name("object-select-symbolic");
        picked.set_valign(gtk::Align::Center);
        picked.set_visible(false);
        row.add_suffix(&picked);

        let inner_for_row = inner.clone();
        let mac = choice.mac.clone();
        row.connect_activated(move |_| {
            inner_for_row.mac_row.set_text(&mac);
        });

        inner.neighbour_list.append(&row);
        rows.push(NeighbourRow {
            mac: choice.mac.clone(),
            row,
            picked,
        });
    }
    inner.neighbour_rows.replace(rows);
    refresh_save_state(inner);
}

/// The picker replaced by the reason there is none. An empty neighbour
/// table and a neighbour table that could not be read are two different
/// facts, and the typed-MAC field stays usable under either.
fn show_neighbours_unavailable(inner: &Rc<Inner>, reason: &str) {
    for row in inner.neighbour_rows.replace(Vec::new()) {
        inner.neighbour_list.remove(&row.row);
    }
    inner.neighbour_list.set_visible(false);
    inner.neighbours_quiet.set_visible(false);
    inner.names_caption.set_visible(false);
    inner
        .neighbours_trouble
        .set_title("Could not list this network");
    inner.neighbours_trouble.set_description(reason);
    inner.neighbours_trouble.widget().set_visible(true);
    refresh_save_state(inner);
}

fn apply(inner: &Rc<Inner>, loaded: &Loaded) {
    match &loaded.saved {
        Ok(devices) => rebuild_saved(inner, devices),
        Err(reason) => show_saved_unreadable(inner, reason),
    }
    match &loaded.seen {
        Ok(seen) => rebuild_neighbours(inner, seen),
        Err(reason) => show_neighbours_unavailable(inner, reason),
    }
}

/// Re-reads the book and the neighbour table off the UI thread and renders
/// what comes back, then -- for a read that followed a write -- says what
/// the write did and what the re-read makes of it.
fn reload_into(inner: &Rc<Inner>, announcement: Option<Announcement>) {
    let inner = inner.clone();
    glib::spawn_future_local(async move {
        let loaded = gtk::gio::spawn_blocking(load_everything)
            .await
            .unwrap_or_else(|_| Loaded {
                saved: Err("reading the saved devices panicked".to_string()),
                seen: Err("listing this network panicked".to_string()),
            });
        apply(&inner, &loaded);
        if let Some(announcement) = announcement {
            inner.set_note(Some(note_after_write(&loaded, &announcement)));
        }
    });
}

/// The response id that actually forgets a device, and the one that backs
/// out -- which is also the alert's close response, so dismissing it any
/// other way is the same outcome as pressing Cancel.
const FORGET_CONFIRM: &str = "forget";
const FORGET_CANCEL: &str = "cancel";

/// Asks first. A saved device is the one thing in porthole that cannot
/// always be recreated by looking: the MAC of a device that is switched off
/// is not in the neighbour table to pick again, which is the whole reason
/// the typed field exists.
fn confirm_forget(inner: &Rc<Inner>, name: &str) {
    let alert = adw::AlertDialog::builder()
        .heading("Forget this device?")
        .body(format!(
            "`{name}` stops being offered as a target. Nothing that is currently open changes."
        ))
        .body_use_markup(false)
        .close_response(FORGET_CANCEL)
        .default_response(FORGET_CANCEL)
        .build();
    alert.add_response(FORGET_CANCEL, "Cancel");
    alert.add_response(FORGET_CONFIRM, "Forget");
    alert.set_response_appearance(FORGET_CONFIRM, adw::ResponseAppearance::Destructive);

    let inner = inner.clone();
    let name = name.to_string();
    glib::spawn_future_local(async move {
        if alert.choose_future(&inner.dialog).await != FORGET_CONFIRM {
            return;
        }
        let for_thread = name.clone();
        let outcome = gtk::gio::spawn_blocking(move || forget_device(&for_thread)).await;
        match outcome {
            Ok(Ok(())) => {
                inner.set_note(None);
                inner.show_toast(&format!("Forgot `{name}`."));
                reload_into(&inner, None);
                if let Some(f) = inner.on_changed.borrow().as_ref() {
                    f();
                }
            }
            Ok(Err(message)) => inner.show_toast(&message),
            Err(_) => inner.show_toast("forgetting the device panicked"),
        }
    });
}

/// Where a person creates a saved device, and forgets one.
#[derive(Clone)]
pub struct DevicesDialog {
    inner: Rc<Inner>,
}

impl Default for DevicesDialog {
    fn default() -> Self {
        Self::new()
    }
}

impl DevicesDialog {
    pub fn new() -> Self {
        let name_row = adw::EntryRow::builder().title("Name").build();
        let mac_row = adw::EntryRow::builder()
            .title("MAC address (for example bc:24:11:5e:1c:6e)")
            .build();
        let entry_list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        // What gives rows outside an `AdwPreferencesGroup`'s own list the
        // same rounded card the rows inside one have.
        entry_list.add_css_class("boxed-list");
        entry_list.append(&name_row);
        entry_list.append(&mac_row);

        let name_error = field_error_label();
        let mac_error = field_error_label();

        let picker_heading = gtk::Label::builder()
            .label("Seen on this network")
            .wrap(true)
            .xalign(0.0)
            .margin_top(6)
            .css_classes(["heading"])
            .build();

        let neighbours_quiet = quiet_note(
            "Nothing has been seen on this network yet. A device that is switched off will \
             not appear here; its MAC address can still be typed above.",
        );
        neighbours_quiet.set_visible(false);

        // What `getent hosts` was asked and what a row saves. It does not
        // say where an answer came from, because `getent` merges the host's
        // name sources and reports which of them answered for none of it.
        let names_caption = quiet_note(
            "The name on a row is what this machine's resolver answered for that address. The \
             MAC is what gets saved.",
        );
        names_caption.set_visible(false);
        let neighbours_trouble = TroubleNote::new();
        neighbours_trouble.widget().set_visible(false);

        let neighbour_list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        neighbour_list.add_css_class("boxed-list");
        neighbour_list.set_visible(false);

        let note = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .visible(false)
            .margin_top(6)
            .css_classes(["caption"])
            .build();

        let save_button = gtk::Button::builder()
            .label("Save device")
            .css_classes(["suggested-action"])
            .halign(gtk::Align::End)
            .margin_top(6)
            .sensitive(false)
            .build();

        let add_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .build();
        add_box.append(&entry_list);
        add_box.append(&name_error);
        add_box.append(&mac_error);
        add_box.append(&picker_heading);
        add_box.append(&neighbours_quiet);
        add_box.append(neighbours_trouble.widget());
        add_box.append(&neighbour_list);
        add_box.append(&names_caption);
        add_box.append(&note);
        add_box.append(&save_button);

        let add_group = adw::PreferencesGroup::builder()
            .title("Add a device")
            .description(
                "Pick a device this machine has seen, or type a MAC address for one that is \
                 switched off.",
            )
            .build();
        add_group.add(&add_box);

        let saved_group = adw::PreferencesGroup::builder()
            .title("Saved devices")
            // Not "resolved through this machine's neighbour table" flatly:
            // that is how a MAC is looked up, and a device saved by
            // hostname goes through the system resolver instead. The
            // caveat that matters belongs to the case it is true of.
            .description(
                "Looked up now — a MAC through this machine's neighbour table, entries it \
                 has not confirmed recently included.",
            )
            .build();

        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(18)
            .margin_top(18)
            .margin_bottom(18)
            .margin_start(18)
            .margin_end(18)
            .build();
        // The add form first, deliberately: a device saved from here appears
        // in the list immediately below the note that says it was saved,
        // rather than off the top of a dialog that has just been scrolled to
        // its form.
        content.append(&add_group);
        content.append(&saved_group);

        // The dialog scrolls rather than being cut off, and never grows a
        // horizontal scrollbar: the same shape, and the same reason, as the
        // open dialog. Its width still comes from the content, so nothing
        // here can hide a widget that refuses to narrow.
        let scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .propagate_natural_width(true)
            .propagate_natural_height(true)
            .child(&content)
            .build();

        let toast_overlay = adw::ToastOverlay::new();
        toast_overlay.set_child(Some(&scroller));

        // `follows_content_size`, which the open dialog does not need and
        // this one does: that dialog is handed its target list before it is
        // presented, and this one fills in afterwards -- the address book
        // and the neighbour table are read off the UI thread and land a
        // moment later, and a device saved or forgotten changes the height
        // again while the dialog is on screen. Measured in the container
        // without it: the dialog kept the height it had when it was
        // presented empty, roughly 430 px, and every row that arrived after
        // that was left below the fold, the Save button among them.
        let dialog = adw::Dialog::builder()
            .title("Saved devices")
            .content_width(420)
            .follows_content_size(true)
            .child(&toast_overlay)
            .build();

        let inner = Rc::new(Inner {
            dialog,
            toast_overlay,
            name_row: name_row.clone(),
            name_error,
            mac_row: mac_row.clone(),
            mac_error,
            neighbour_list,
            neighbour_rows: RefCell::new(Vec::new()),
            neighbours_quiet,
            names_caption,
            neighbours_trouble,
            save_button: save_button.clone(),
            note,
            saving: Cell::new(false),
            saved_group,
            saved_rows: RefCell::new(Vec::new()),
            saved_placeholder: RefCell::new(None),
            on_changed: RefCell::new(None),
        });

        // The list starts as the quiet "none yet" line rather than as an
        // empty group with nothing in it at all.
        rebuild_saved(&inner, &[]);

        let inner_for_name = inner.clone();
        name_row.connect_changed(move |_| refresh_save_state(&inner_for_name));
        let inner_for_mac = inner.clone();
        mac_row.connect_changed(move |_| refresh_save_state(&inner_for_mac));

        let inner_for_save = inner.clone();
        save_button.connect_clicked(move |_| {
            let Some(device) = build_device(&inner_for_save) else {
                return;
            };
            let inner = inner_for_save.clone();
            inner.saving.set(true);
            refresh_save_state(&inner);
            inner.set_note(None);
            glib::spawn_future_local(async move {
                let name = device.name.clone();
                let outcome = gtk::gio::spawn_blocking(move || save_device(&device)).await;
                inner.saving.set(false);
                match outcome {
                    Ok(Ok(replaced)) => {
                        // The fields are cleared only once the write
                        // actually happened: a failed save must leave what
                        // was typed where it was typed.
                        inner.name_row.set_text("");
                        inner.mac_row.set_text("");
                        reload_into(&inner, Some(Announcement { name, replaced }));
                        if let Some(f) = inner.on_changed.borrow().as_ref() {
                            f();
                        }
                    }
                    Ok(Err(message)) => inner.show_toast(&message),
                    Err(_) => inner.show_toast("saving the device panicked"),
                }
                refresh_save_state(&inner);
            });
        });

        Self { inner }
    }

    /// Re-reads the address book and the neighbour table, off the UI
    /// thread, and renders what comes back.
    ///
    /// Called by whoever presents this dialog rather than by its
    /// constructor, so a test can build one and drive it with fixture data
    /// instead of whatever this machine's own book and network happen to
    /// hold -- the same split `PortholeWindow::new_without_initial_load`
    /// exists for.
    pub fn reload(&self) {
        reload_into(&self.inner, None);
    }

    /// The saved devices this dialog shows.
    pub fn set_saved(&self, devices: &[SavedDevice]) {
        rebuild_saved(&self.inner, devices);
    }

    /// The reason there is no list, which is not the same fact as there
    /// being no devices.
    pub fn set_saved_unreadable(&self, reason: &str) {
        show_saved_unreadable(&self.inner, reason);
    }

    /// What the picker offers.
    pub fn set_neighbours(&self, seen: &[NeighbourChoice]) {
        rebuild_neighbours(&self.inner, seen);
    }

    /// The reason the picker offers nothing, which is not the same fact as
    /// this network being empty.
    pub fn set_neighbours_unavailable(&self, reason: &str) {
        show_neighbours_unavailable(&self.inner, reason);
    }

    /// The saved rows' own displayed names, read back from the real
    /// widgets.
    pub fn saved_labels(&self) -> Vec<String> {
        self.inner
            .saved_rows
            .borrow()
            .iter()
            .map(|r| r.row.title().to_string())
            .collect()
    }

    /// The saved rows' own displayed subtitles, read back the same way.
    pub fn saved_subtitles(&self) -> Vec<String> {
        self.inner
            .saved_rows
            .borrow()
            .iter()
            .map(|r| r.row.subtitle().map(|s| s.to_string()).unwrap_or_default())
            .collect()
    }

    /// One saved row's real Forget button, so a caller can press it.
    pub fn forget_button(&self, index: usize) -> Option<gtk::Button> {
        self.inner
            .saved_rows
            .borrow()
            .get(index)
            .map(|r| r.forget.clone())
    }

    /// The MACs the picker currently offers, read back from the real rows.
    pub fn neighbour_labels(&self) -> Vec<String> {
        self.inner
            .neighbour_rows
            .borrow()
            .iter()
            .map(|r| r.row.title().to_string())
            .collect()
    }

    /// One picker row, so a caller can activate it exactly as a click
    /// would.
    pub fn neighbour_row(&self, index: usize) -> Option<adw::ActionRow> {
        self.inner
            .neighbour_rows
            .borrow()
            .get(index)
            .map(|r| r.row.clone())
    }

    /// Whether the tick marking "this is the MAC in the field" is showing
    /// on row `index`.
    pub fn neighbour_is_picked(&self, index: usize) -> bool {
        self.inner
            .neighbour_rows
            .borrow()
            .get(index)
            .is_some_and(|r| r.picked.is_visible())
    }

    /// Whether the line explaining where a row's name came from is showing.
    pub fn names_caption_is_showing(&self) -> bool {
        self.inner.names_caption.is_visible()
    }

    /// The subtitle under each picker row, read back off the real widgets.
    pub fn neighbour_subtitles(&self) -> Vec<String> {
        self.inner
            .neighbour_rows
            .borrow()
            .iter()
            .map(|r| r.row.subtitle().unwrap_or_default().to_string())
            .collect()
    }

    /// Whether the picker's quiet "nothing seen yet" line is showing.
    pub fn neighbours_quiet_is_showing(&self) -> bool {
        self.inner.neighbours_quiet.is_visible()
    }

    /// The picker's own trouble note, when one is showing -- its title and
    /// the reason under it.
    pub fn neighbours_trouble(&self) -> Option<(String, String)> {
        if !self.inner.neighbours_trouble.widget().is_visible() {
            return None;
        }
        Some((
            self.inner.neighbours_trouble.title(),
            self.inner
                .neighbours_trouble
                .description()
                .unwrap_or_default(),
        ))
    }

    pub fn set_name_text(&self, text: &str) {
        self.inner.name_row.set_text(text);
    }

    pub fn set_mac_text(&self, text: &str) {
        self.inner.mac_row.set_text(text);
    }

    pub fn mac_text(&self) -> String {
        self.inner.mac_row.text().to_string()
    }

    /// The name field's refusal as it actually reads on screen, or `None`
    /// when nothing is being refused.
    pub fn name_error(&self) -> Option<String> {
        visible_text(&self.inner.name_error)
    }

    /// The MAC field's refusal, read back the same way.
    pub fn mac_error(&self) -> Option<String> {
        visible_text(&self.inner.mac_error)
    }

    /// What the last write said, as it actually reads on screen.
    pub fn note(&self) -> Option<String> {
        visible_text(&self.inner.note)
    }

    /// Whether that note is marked as something to act on later.
    pub fn note_is_marked(&self) -> bool {
        self.inner.note.has_css_class("warning")
    }

    pub fn save_button(&self) -> &gtk::Button {
        &self.inner.save_button
    }

    pub fn can_save(&self) -> bool {
        self.inner.save_button.is_sensitive()
    }

    /// Registered by whoever presented this dialog, and called after every
    /// write to the book -- so the window's own device cache, and any open
    /// dialog currently on screen, are re-read from the file this just
    /// changed.
    pub fn on_changed(&self, f: impl Fn() + 'static) {
        self.inner.on_changed.replace(Some(Box::new(f)));
    }

    pub fn dialog(&self) -> &adw::Dialog {
        &self.inner.dialog
    }

    pub fn present(&self, parent: Option<&impl IsA<gtk::Widget>>) {
        self.inner.dialog.present(parent);
    }
}

/// The shape both field refusals share: dim-scaled, wrapping, coloured by
/// the `error` style class, and hidden rather than emptied so nothing
/// reserves a blank line.
fn field_error_label() -> gtk::Label {
    let label = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .visible(false)
        .build();
    label.add_css_class("error");
    label.add_css_class("caption");
    label
}

/// A label's text when it is actually on screen. `None` for a hidden one --
/// a label keeps whatever it was last set to, and reading that back would
/// report a refusal nobody can see.
fn visible_text(label: &gtk::Label) -> Option<String> {
    if label.is_visible() {
        Some(label.label().to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choice(mac: &str) -> NeighbourChoice {
        NeighbourChoice {
            mac: mac.to_string(),
            address: "10.10.10.245".parse().unwrap(),
            interface: "wlo1".to_string(),
            name: None,
        }
    }

    #[test]
    fn a_subtitle_carries_a_name_when_there_is_one_and_nothing_when_there_is_not() {
        let mut with_name = choice("bc:24:11:5e:1c:6e");
        with_name.name = Some("phone.example".to_string());
        assert_eq!(
            neighbour_subtitle(&with_name),
            "phone.example · 10.10.10.245 on wlo1"
        );

        // No stand-in for a name that was not found: the row reads exactly
        // as it did before there were names at all.
        let without = choice("bc:24:11:5e:1c:6e");
        assert_eq!(neighbour_subtitle(&without), "10.10.10.245 on wlo1");
    }

    #[test]
    fn a_name_the_tool_refuses_is_refused_here_in_the_tools_own_words() {
        // The bug this guards: `office:pc` used to save cleanly and then be
        // permanently unusable, because `--to` reads a name containing `:`
        // as a failed IP address. The refusal is
        // `devices::validate_device_name`'s, called rather than restated.
        for name in ["office:pc", "home/laptop", "subnet", "any", "10.0.0.5"] {
            let expected = devices::validate_device_name(name).unwrap_err().to_string();
            match parsed_name(name) {
                Field::Invalid(message) => assert_eq!(message, expected),
                _ => panic!("`{name}` must be refused"),
            }
        }
    }

    #[test]
    fn an_ordinary_name_is_accepted_and_trimmed() {
        match parsed_name("  phone  ") {
            Field::Valid(name) => assert_eq!(name, "phone"),
            _ => panic!("`phone` must be accepted"),
        }
    }

    #[test]
    fn an_empty_field_is_not_an_error_but_is_not_a_value_either() {
        assert!(matches!(parsed_name("   "), Field::Empty));
        assert!(matches!(parsed_mac(""), Field::Empty));
        assert!(parsed_name("   ").error().is_none());
        assert!(parsed_name("   ").value().is_none());
    }

    #[test]
    fn a_typed_mac_is_read_by_the_same_function_the_book_reads_it_with() {
        match parsed_mac("BC:24:11:5E:1C:6E") {
            Field::Valid(mac) => assert_eq!(mac, "bc:24:11:5e:1c:6e"),
            _ => panic!("a capitalised MAC must be accepted, lower-cased"),
        }
        let expected = devices::parse_mac("nope").unwrap_err().to_string();
        match parsed_mac("nope") {
            Field::Invalid(message) => assert_eq!(message, expected),
            _ => panic!("`nope` must be refused"),
        }
    }

    #[test]
    fn a_saved_device_that_resolves_says_only_what_it_resolves_to() {
        let subtitle = saved_subtitle(&SavedDevice {
            name: "phone".to_string(),
            address: "bc:24:11:5e:1c:6e".to_string(),
            resolved: Ok("10.10.10.245".parse().unwrap()),
        });
        assert_eq!(
            subtitle,
            "bc:24:11:5e:1c:6e · resolves to 10.10.10.245 right now"
        );
        // Nothing here may read as a reachability test: the neighbour table
        // records what the kernel has seen and not disproved, `STALE`
        // entries included.
        for word in ["reachable", "verified", "online", "responding"] {
            assert!(!subtitle.contains(word), "{subtitle} must not claim {word}");
        }
    }

    #[test]
    fn a_saved_device_that_does_not_resolve_carries_the_resolvers_own_words() {
        // The text a caller gets from `devices::resolve` -- an `Error`'s
        // own rendered form, prefix included. Nothing is stripped from it
        // or added to it here.
        let reason = "device not reachable: `laptop` (bc:24:11:5e:1c:6e) is not on this \
                      network right now";
        assert_eq!(
            saved_subtitle(&SavedDevice {
                name: "laptop".to_string(),
                address: "bc:24:11:5e:1c:6e".to_string(),
                resolved: Err(reason.to_string()),
            }),
            reason
        );
    }

    #[test]
    fn saving_a_mac_that_is_not_here_says_so_without_saying_it_failed() {
        let reason = "device not reachable: `laptop` (bc:24:11:5e:1c:6e) is not on this \
                      network right now";
        let loaded = Loaded {
            saved: Ok(vec![SavedDevice {
                name: "laptop".to_string(),
                address: "bc:24:11:5e:1c:6e".to_string(),
                resolved: Err(reason.to_string()),
            }]),
            seen: Ok(Vec::new()),
        };
        let (text, marked) = note_after_write(
            &loaded,
            &Announcement {
                name: "laptop".to_string(),
                replaced: false,
            },
        );
        assert!(text.starts_with("Saved —"), "got: {text}");
        assert!(text.contains(reason), "got: {text}");
        assert!(marked, "a device that is not here is worth marking");
    }

    #[test]
    fn overwriting_a_device_of_the_same_name_says_so() {
        let loaded = Loaded {
            saved: Ok(vec![SavedDevice {
                name: "phone".to_string(),
                address: "bc:24:11:5e:1c:6e".to_string(),
                resolved: Ok("10.10.10.245".parse().unwrap()),
            }]),
            seen: Ok(vec![choice("bc:24:11:5e:1c:6e")]),
        };
        let (text, marked) = note_after_write(
            &loaded,
            &Announcement {
                name: "phone".to_string(),
                replaced: true,
            },
        );
        assert!(text.starts_with("Replaced —"), "got: {text}");
        assert!(text.contains("10.10.10.245"), "got: {text}");
        assert!(!marked, "a device that resolved needs no mark");
    }

    #[test]
    fn a_neighbour_row_says_which_interface_saw_it() {
        assert_eq!(
            neighbour_subtitle(&choice("bc:24:11:5e:1c:6e")),
            "10.10.10.245 on wlo1"
        );
    }
}
