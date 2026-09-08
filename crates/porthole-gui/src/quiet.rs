//! The one shape a section uses to say something quiet about itself.
//!
//! "No ports open", "Nothing else is listening", "Checking what's open…" --
//! each of these is one section of the window saying it has nothing to
//! show, or nothing yet. Every one of them used to be an `adw::StatusPage`,
//! a widget built to be a whole view: a large icon, generous padding, and
//! vertical expansion. Measured in this milestone's own container at the
//! window's own default width, one of those asked for 300px of height where
//! the same section asks for 94px with a rule actually rendered in it -- and
//! the window has two sections, so on a machine with nothing open the rest
//! of the window went below the fold and had to be scrolled to. A person
//! testing porthole on a Fedora Workstation VM asked why an empty section
//! scrolls, and whether the icon was carrying anything the text did not.
//!
//! [`quiet_note`] is what replaced them: one dim, wrapping line, no icon.
//! It is deliberately *not* what a failure to reach the helper renders as
//! -- those keep the `adw::StatusPage` with its `dialog-error-symbolic`
//! icon and `error` style class, a different widget of a different type, so
//! that "there is nothing open" and "porthole could not find out" cannot be
//! read as each other. See `open_now.rs`'s and `listening_section.rs`'s own
//! module docs.

use gtk::prelude::*;

/// A section-scaled line of quiet text: dim, wrapping, left-aligned, and
/// claiming no vertical expansion of its own.
///
/// Wrapping is what keeps this from setting the window's own minimum
/// width: a `gtk::Label` that does not wrap asks for its whole sentence on
/// one line, and every widget above it in the tree has to grant that -- the
/// defect this project's own dialog already hit once, with a single
/// unwrapped line forcing the window wide. A wrapping one asks only for its
/// longest word, and folds to whatever width it is actually given.
pub fn quiet_note(text: &str) -> gtk::Label {
    let label = gtk::Label::builder()
        .label(text)
        .wrap(true)
        .xalign(0.0)
        .halign(gtk::Align::Start)
        .valign(gtk::Align::Start)
        .css_classes(["dim-label"])
        .build();
    label.set_vexpand(false);
    label
}

/// The section-scaled shape for the other kind of state: one porthole
/// could not find out, which has to read as trouble.
///
/// Kept deliberately unlike [`quiet_note`] -- an icon, and the `error`
/// style class that colours it and its words -- because the pair that must
/// never be readable as each other is "there is nothing open" and "porthole
/// could not ask". Never colour alone: colour fails a colour-blind user and
/// a high-contrast theme, which is why the icon is there too.
///
/// Section-scaled for a reason found by looking at a render rather than by
/// reasoning: the `adw::StatusPage` this replaced puts its own
/// `gtk::ScrolledWindow` around its icon, title and description, and its
/// minimum height is far below what those need. Given a section's worth of
/// room next to a populated "Listening" list, it rendered as the top sliver
/// of a red circle with the title and the helper's own message clipped
/// away entirely -- a state whose whole purpose is to say what porthole
/// could not do, saying nothing. This box asks for the height its text
/// needs, so the text is what a short section shows.
#[derive(Clone)]
pub struct TroubleNote {
    widget: gtk::Box,
    icon: gtk::Image,
    title: gtk::Label,
    description: gtk::Label,
}

impl Default for TroubleNote {
    fn default() -> Self {
        Self::new()
    }
}

impl TroubleNote {
    pub fn new() -> Self {
        let icon = gtk::Image::from_icon_name("dialog-error-symbolic");
        icon.set_valign(gtk::Align::Start);

        let title = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .halign(gtk::Align::Start)
            .css_classes(["heading"])
            .build();
        let description = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .halign(gtk::Align::Start)
            .build();

        let text = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(3)
            .build();
        text.append(&title);
        text.append(&description);

        // `error` on the box, not on each child: the class colours what it
        // is set on and what that contains, which is how the whole-view
        // widget this replaced coloured its own icon and words.
        let widget = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .valign(gtk::Align::Start)
            .css_classes(["error"])
            .build();
        widget.append(&icon);
        widget.append(&text);

        Self {
            widget,
            icon,
            title,
            description,
        }
    }

    /// What a section appends into its own container.
    pub fn widget(&self) -> &gtk::Box {
        &self.widget
    }

    pub fn set_title(&self, title: &str) {
        self.title.set_label(title);
    }

    /// The caller's own message, verbatim. `use_markup` stays off: this
    /// text comes from the helper (or from a `/proc` read) and is not
    /// markup anyone here wrote.
    pub fn set_description(&self, description: &str) {
        self.description.set_label(description);
        self.description.set_use_markup(false);
    }

    /// The title as it actually reads on screen. Same name and same shape
    /// as `adw::StatusPage`'s own accessor, so what a test reads is the
    /// displayed text either way.
    pub fn title(&self) -> String {
        self.title.label().to_string()
    }

    pub fn description(&self) -> Option<String> {
        Some(self.description.label().to_string())
    }

    pub fn icon_name(&self) -> Option<String> {
        self.icon.icon_name().map(|n| n.to_string())
    }

    pub fn css_classes(&self) -> Vec<String> {
        self.widget
            .css_classes()
            .iter()
            .map(|c| c.to_string())
            .collect()
    }

    /// Whether this note is currently in `container`'s widget tree -- what
    /// a section's own `error_note()` accessor answers from.
    pub fn is_showing(&self) -> bool {
        self.widget.parent().is_some()
    }
}
