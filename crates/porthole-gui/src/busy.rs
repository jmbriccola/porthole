//! What the window shows while it is waiting for the helper to answer.
//!
//! Nothing did, before this module. A person testing porthole on a Fedora
//! Workstation VM said the application looked frozen every time it had to
//! change what it was showing -- and it did: pressing Open sent a D-Bus
//! call and then nothing moved until the answer came back. That wait is not
//! short. This project measured firewalld's own polkit timeout at roughly
//! 28 seconds, and an `open` really can take that long.
//!
//! ## What a busy indication is allowed to say
//!
//! Only that porthole is waiting for an answer. That is true from the
//! moment the call goes out. A rendered rule would say "this port is open",
//! which is not true until the helper says so -- adding the row optimistically
//! is the shape of defect this project keeps producing, and the user has
//! just finished reporting one instance of it. So nothing here draws
//! anything that stands for a result: a spinner, and the control that
//! started the operation held insensitive until it is over.
//!
//! ## Why the delay
//!
//! A local D-Bus round trip that nobody has to authorize comes back in
//! milliseconds. A spinner that appears and vanishes inside a tenth of a
//! second is a flicker, and a flicker is worse than nothing: it draws the
//! eye to something already finished. So [`BUSY_DELAY`] passes before
//! anything appears, and an operation that finishes first shows nothing at
//! all.
//!
//! 500ms is the number. Below about a tenth of a second a person reads the
//! result as instantaneous; at about a second they have noticed the wait and
//! started to wonder. 500ms sits between: long enough that a round trip
//! nobody had to authorize is over before it, short enough that the wait a
//! polkit prompt introduces is covered from close to its start. It is a
//! choice, not a measurement of this application.
//!
//! **The insensitivity is not delayed**, and is not a claim about progress:
//! it is what stops a second press sending a second request while the first
//! is unanswered. In the fast path the control it applies to is usually
//! gone before it could be seen -- a close takes its own row off screen, a
//! successful open closes the dialog it was pressed in.
//!
//! ## How it ends
//!
//! [`BusyIndicator::begin`] hands back a [`Busy`], and everything this
//! module does is undone in that value's `Drop`. A caller holds it across
//! its `await` and drops it on the way out -- every way out, since that is
//! what `Drop` means: the helper answered, the helper answered with an
//! error, there was no helper to reach, the dialog it was pressed in was
//! dismissed while the call was still outstanding. A spinner still turning
//! over an operation that finished is the same defect this module exists to
//! repair, wearing the opposite costume, so there is deliberately no way to
//! stop one except by dropping the value that started it.
//!
//! Overlapping operations share one indicator by counting: the spinner goes
//! when the last outstanding one is done, not the first.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

/// How long an operation has to stay unanswered before anything appears.
/// See this module's own doc comment for where the number comes from.
pub const BUSY_DELAY: Duration = Duration::from_millis(500);

struct Inner {
    spinner: gtk::Spinner,
    /// Held insensitive from the moment the first operation begins until
    /// the last one ends -- not delayed, and not a progress claim. See
    /// this module's own doc comment.
    disable: RefCell<Vec<gtk::Widget>>,
    /// How many operations are outstanding right now. The spinner belongs
    /// to the last one to finish, not the first.
    outstanding: Cell<usize>,
    /// The pending "show the spinner now" timer, if one has been armed and
    /// has not fired. Emptied by whichever of the timer and [`Busy::drop`]
    /// gets there first: `SourceId::remove` on a source that has already
    /// run is a panic, not a no-op.
    timer: RefCell<Option<glib::SourceId>>,
}

/// One place a busy indication can appear: a spinner, plus whatever
/// controls must not be pressed again while porthole is waiting.
#[derive(Clone)]
pub struct BusyIndicator {
    inner: Rc<Inner>,
}

impl Default for BusyIndicator {
    fn default() -> Self {
        Self::new()
    }
}

impl BusyIndicator {
    pub fn new() -> Self {
        // Built hidden, and hidden is what it goes back to: an invisible
        // widget takes no space, so a section does not change height when
        // one appears.
        let spinner = gtk::Spinner::builder()
            .visible(false)
            .valign(gtk::Align::Center)
            .build();
        Self {
            inner: Rc::new(Inner {
                spinner,
                disable: RefCell::new(Vec::new()),
                outstanding: Cell::new(0),
                timer: RefCell::new(None),
            }),
        }
    }

    /// The widget a caller puts wherever the indication belongs -- a row's
    /// own suffix, a dialog's action area, the header bar.
    pub fn spinner(&self) -> &gtk::Spinner {
        &self.inner.spinner
    }

    /// Registers a control that must be insensitive for as long as
    /// anything is outstanding here. Applied immediately if something
    /// already is.
    pub fn disable_while_busy(&self, widget: &impl IsA<gtk::Widget>) {
        let widget = widget.clone().upcast::<gtk::Widget>();
        if self.is_busy() {
            widget.set_sensitive(false);
        }
        self.inner.disable.borrow_mut().push(widget);
    }

    /// Starts one operation. The returned value is the operation: hold it
    /// across the `await` and let it drop, and the indication is over.
    #[must_use = "the busy indication lasts exactly as long as this value"]
    pub fn begin(&self) -> Busy {
        let first = self.inner.outstanding.get() == 0;
        self.inner.outstanding.set(self.inner.outstanding.get() + 1);
        if first {
            for widget in self.inner.disable.borrow().iter() {
                widget.set_sensitive(false);
            }
            let inner = self.inner.clone();
            let id = glib::timeout_add_local_once(BUSY_DELAY, move || {
                // It has fired, so there is nothing left for `Busy::drop`
                // to remove.
                inner.timer.borrow_mut().take();
                if inner.outstanding.get() > 0 {
                    inner.spinner.set_visible(true);
                    inner.spinner.start();
                }
            });
            *self.inner.timer.borrow_mut() = Some(id);
        }
        Busy {
            inner: self.inner.clone(),
        }
    }

    /// Whether anything is outstanding here right now. True from the
    /// moment [`BusyIndicator::begin`] is called, whether or not
    /// [`BUSY_DELAY`] has gone by -- this is "porthole is waiting", not
    /// "something is on screen".
    pub fn is_busy(&self) -> bool {
        self.inner.outstanding.get() > 0
    }

    /// Whether the spinner is actually on screen and turning -- read off
    /// the real widget, not recomputed from the count, since a state that
    /// is right in an accessor and absent from the widget is exactly the
    /// failure being guarded against.
    pub fn is_showing(&self) -> bool {
        self.inner.spinner.is_visible()
    }
}

/// One outstanding operation. See [`BusyIndicator::begin`].
pub struct Busy {
    inner: Rc<Inner>,
}

impl Drop for Busy {
    fn drop(&mut self) {
        let left = self.inner.outstanding.get().saturating_sub(1);
        self.inner.outstanding.set(left);
        if left > 0 {
            return;
        }
        if let Some(id) = self.inner.timer.borrow_mut().take() {
            id.remove();
        }
        self.inner.spinner.stop();
        self.inner.spinner.set_visible(false);
        for widget in self.inner.disable.borrow().iter() {
            widget.set_sensitive(true);
        }
    }
}
