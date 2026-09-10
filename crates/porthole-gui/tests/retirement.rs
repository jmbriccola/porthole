//! What the window does about a helper that is between lives.
//!
//! Since `porthole-helper` grew an idle exit it retires whenever it holds no
//! rules, after a grace period, and the bus activates a fresh instance on the
//! next call. On an idle machine that is several times a day. Two failures
//! come out of it, and both are things a second call turns into service
//! rather than things to report -- `porthole_core::ipc::worth_asking_again`
//! is where the pair is named and where what a retry can and cannot promise
//! is written down.
//!
//! ## What is real here and what is not
//!
//! **Real:** the bus, the well-known name changing hands, the error name on
//! the wire, and the ordering that makes a retry safe. The stand-in below
//! does what `porthole_helper::retire` does and in that order -- it lets the
//! successor take `com.jacopobriccola.Porthole` **first**, and only once the
//! name is provably somebody else's does it answer
//! `com.jacopobriccola.Porthole.Retiring`. That ordering is the whole reason
//! a client may be told to ask again at all: a refusal answered while the
//! leaving instance still owned the name would send the retry straight back
//! to it and spend the client's one retry on the same answer. So the retry
//! this file watches is routed by a real bus daemon to a different owner,
//! exactly as it is in production.
//!
//! **Not real:** the decision. Nothing here has a grace period, and no
//! process exits -- the "instances" are connections in this test binary. A
//! real helper cannot run in this container at all: it refuses to start
//! without a root-owned `/usr/bin/porthole` (`porthole_core::cli_path`), and
//! `cargo test -p porthole-gui` does not build one. The retirement that a
//! real `porthole-helper` really decides on, really announces and really
//! exits from is driven in `crates/porthole-helper/tests/idle_exit.rs` and
//! `crates/porthole-agent/tests/retirement.rs`, against the real binary on a
//! bus that can activate it. This file is the third component's half of the
//! same repair, and says which half it is rather than implying more.
//!
//! ## The guard against measuring nothing
//!
//! Every case here arms exactly one refusal and then asserts the refusal
//! **count**, not merely that the window ended up looking right. Without
//! that, a case whose call happened to reach the serving instance would
//! render perfectly and pass while never exercising a retry -- and so would a
//! window with the retry deleted, if the fixture never refused it anything.
//!
//! ## The bus these tests use
//!
//! `gui-test.sh` runs the whole target under `dbus-run-session`, which
//! provides a private *session* bus and nothing else. `main` below points
//! `DBUS_SYSTEM_BUS_ADDRESS` at that same private daemon before any window
//! exists, so the window's own `zbus::Connection::system()` reaches the
//! stand-in here -- the same arrangement `tests/signals.rs` uses and for the
//! same reason. Nothing here touches this machine's real buses, and the
//! stand-in opens no ports: it hands back rows a case put in it.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use adw::prelude::*;
use porthole_core::ipc::{
    WireDockerPort, WireRule, WireStatus, INTERFACE, PATH, RETIRING_ERROR, SERVICE,
};
use porthole_gui::open_dialog::OpenDialog;
use porthole_gui::window::PortholeWindow;

/// How long any of these will wait for something to cross the bus and reach
/// a widget. Generous on purpose: a software-rendered GTK window in a
/// container under a cold cargo build is not the thing under test.
const DEADLINE: Duration = Duration::from_secs(20);

const OPENED_AT: u64 = 1_757_100_000;
const EXPIRES_AT: u64 = 1_757_103_600;
const PORT: u16 = 5173;

/// What the real helper's refusal says, and the reason it is worth spelling
/// out here: a client without the retry shows it to a person verbatim, so it
/// names the remedy. Copied from `porthole_helper::retire`'s own `REFUSAL`
/// deliberately rather than shortened -- the point of this fixture is to
/// answer what the real thing answers.
const REFUSAL: &str = "the porthole helper was retiring when this request arrived and did not act \
                       on it: ask again, and the bus will start a fresh helper to serve it";

/// The refusal, under the name the real helper sends it under.
///
/// `#[zbus(prefix = ...)]` plus the variant name is what produces
/// `com.jacopobriccola.Porthole.Retiring`, which is the same machinery
/// `porthole_helper::error::HelperError` uses -- and
/// `the_refusal_this_fixture_sends_is_the_one_the_real_helper_sends` below
/// checks the string that actually crosses the bus against
/// `porthole_core::ipc::RETIRING_ERROR`, rather than trusting either
/// spelling.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "com.jacopobriccola.Porthole")]
enum StandInError {
    Retiring(String),
    Failed(String),
}

type Rules = Arc<Mutex<Vec<WireRule>>>;

/// Everything the generations of the stand-in share, and the channel that
/// makes one of them hand the name to the next.
struct Shared {
    /// The bus every generation is built on.
    address: String,
    rules: Rules,
    /// Set by a case just before the call it wants refused. One-shot: the
    /// first method that finds it set takes it and hands over.
    armed: AtomicBool,
    /// How many calls have actually been refused. The guard against a case
    /// that rendered correctly without ever meeting a refusal -- see this
    /// file's own module doc.
    refusals: AtomicUsize,
    /// "Let the next generation take the name." Held behind a mutex because
    /// a zbus interface has to be `Sync`, not because anything contends.
    ask: Mutex<mpsc::Sender<()>>,
    /// "It has it." The reply to the above, awaited before any refusal is
    /// answered.
    done: Mutex<mpsc::Receiver<()>>,
}

impl Shared {
    /// The leaving instance's whole job: give the name up, and only then
    /// refuse.
    ///
    /// Blocking, on zbus's own executor thread, and that is safe here for the
    /// reason it would not be otherwise: the handover is performed by a
    /// separate thread on a *separate* connection, so nothing this connection
    /// has to process is waiting behind this call. A design where the leaving
    /// connection had to do its own `ReleaseName` from inside a method would
    /// have deadlocked on exactly that.
    fn refuse_after_handing_the_name_over(&self) -> StandInError {
        self.ask
            .lock()
            .expect("not poisoned")
            .send(())
            .expect("the handover thread outlives every case");
        self.done
            .lock()
            .expect("not poisoned")
            .recv_timeout(DEADLINE)
            .expect("the successor took the name");
        self.refusals.fetch_add(1, Ordering::SeqCst);
        StandInError::Retiring(REFUSAL.to_string())
    }

    /// Whether this call is the one a case armed.
    fn is_the_refused_one(&self) -> bool {
        self.armed.swap(false, Ordering::SeqCst)
    }

    fn refusals(&self) -> usize {
        self.refusals.load(Ordering::SeqCst)
    }
}

/// One instance of the stand-in helper. Every generation is the same code
/// serving the same rules; what differs is which of them currently owns
/// `com.jacopobriccola.Porthole`.
struct Instance {
    shared: Arc<Shared>,
}

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl Instance {
    async fn list(&self) -> Result<Vec<WireRule>, StandInError> {
        if self.shared.is_the_refused_one() {
            return Err(self.shared.refuse_after_handing_the_name_over());
        }
        Ok(self.shared.rules.lock().expect("not poisoned").clone())
    }

    async fn status(&self) -> Result<WireStatus, StandInError> {
        if self.shared.is_the_refused_one() {
            return Err(self.shared.refuse_after_handing_the_name_over());
        }
        Ok(WireStatus {
            backend: "firewalld".to_string(),
            firewall_available: true,
            firewall_active: true,
            firewall_active_unknown: false,
            firewall_version: "2.3.0".to_string(),
            detail: "firewalld is running".to_string(),
            location: "FedoraWorkstation".to_string(),
            interface: "wlp2s0".to_string(),
            address: "10.10.10.20".to_string(),
            cidr: "10.10.10.0/24".to_string(),
            rules: self.shared.rules.lock().expect("not poisoned").clone(),
        })
    }

    async fn docker_ports(&self) -> Result<Vec<WireDockerPort>, StandInError> {
        if self.shared.is_the_refused_one() {
            return Err(self.shared.refuse_after_handing_the_name_over());
        }
        Ok(Vec::new())
    }

    async fn open(
        &self,
        port: u16,
        _protocol: &str,
        _scope: &str,
        _seconds: u32,
    ) -> Result<WireRule, StandInError> {
        if self.shared.is_the_refused_one() {
            return Err(self.shared.refuse_after_handing_the_name_over());
        }
        let rule = wire_rule(port);
        self.shared
            .rules
            .lock()
            .expect("not poisoned")
            .push(rule.clone());
        Ok(rule)
    }

    async fn close_by_id(
        &self,
        id: &str,
        _from_timer: bool,
        _forget: bool,
    ) -> Result<WireRule, StandInError> {
        if self.shared.is_the_refused_one() {
            return Err(self.shared.refuse_after_handing_the_name_over());
        }
        let mut rules = self.shared.rules.lock().expect("not poisoned");
        let index = rules
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| StandInError::Failed(format!("{id} is not open")))?;
        Ok(rules.remove(index))
    }
}

/// Take `com.jacopobriccola.Porthole` for a fresh connection, from whoever
/// holds it.
///
/// `AllowReplacement` on every generation including the first, so the one
/// after it can do the same; `ReplaceExisting` so it takes the name rather
/// than queueing behind it; `DoNotQueue` so a generation that could not have
/// the name fails here and now instead of quietly becoming the owner later.
fn take_the_name(shared: &Arc<Shared>) -> zbus::blocking::Connection {
    use zbus::fdo::{RequestNameFlags, RequestNameReply};

    let connection = zbus::blocking::connection::Builder::address(shared.address.as_str())
        .expect("a bus address")
        .serve_at(
            PATH,
            Instance {
                shared: shared.clone(),
            },
        )
        .expect("a valid object path")
        .build()
        .expect("the private bus accepts a client");
    let reply = connection
        .request_name_with_flags(
            SERVICE,
            RequestNameFlags::AllowReplacement
                | RequestNameFlags::ReplaceExisting
                | RequestNameFlags::DoNotQueue,
        )
        .expect("the bus answers RequestName");
    assert_eq!(
        reply,
        RequestNameReply::PrimaryOwner,
        "a generation that is not the owner would leave every later call \
         answered by the instance that was supposed to be leaving"
    );
    connection
}

fn wire_rule(port: u16) -> WireRule {
    WireRule {
        id: format!("{port}/tcp"),
        port,
        protocol: "tcp".to_string(),
        target: "10.10.10.0/24".to_string(),
        scope: "network".to_string(),
        backend: "firewalld".to_string(),
        opened_at: OPENED_AT,
        expires_at: EXPIRES_AT,
        uid: 1000,
        // Not a forward: an empty address is what says so.
        container_addr: String::new(),
        container_port: 0,
        published_port: 0,
    }
}

/// Runs `f` inside a real `adw::Application` activation -- the same helper
/// every other GTK-touching file in this crate carries, for the same reason:
/// the widgets have to be built inside a real activation.
fn activate<F: FnOnce(&adw::Application) + 'static>(app_id: &str, f: F) {
    let app = adw::Application::builder().application_id(app_id).build();
    let f = Rc::new(RefCell::new(Some(f)));
    app.connect_activate(move |app| {
        if let Some(f) = f.borrow_mut().take() {
            f(app);
        }
        app.quit();
    });
    app.run_with_args::<&str>(&[]);
}

/// Drains the main context until `condition` holds, or `timeout` elapses --
/// the same bounded shape every other file here uses, so a path that never
/// settles fails the test rather than hanging the process.
fn pump_until(condition: impl Fn() -> bool, timeout: Duration) -> bool {
    let context = gtk::glib::MainContext::default();
    let deadline = Instant::now() + timeout;
    loop {
        while context.iteration(false) {}
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return condition();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

type Case = (&'static str, fn(&Arc<Shared>) -> Result<(), String>);

// ---------------------------------------------------------------------------

/// The fixture's own check, and it comes first: everything below is worth
/// nothing if what this stand-in sends is not what a real helper sends.
///
/// Nothing in this file's own code makes the two agree -- the name is
/// produced by zbus from a prefix attribute and a variant name, and
/// `porthole_core::ipc::RETIRING_ERROR` is a string constant -- so the string
/// that actually crossed the bus is what is compared, taken off a plain proxy
/// call rather than out of the window.
fn the_refusal_this_fixture_sends_is_the_one_the_real_helper_sends(
    shared: &Arc<Shared>,
) -> Result<(), String> {
    let before = shared.refusals();
    shared.armed.store(true, Ordering::SeqCst);

    let connection = zbus::blocking::connection::Builder::address(shared.address.as_str())
        .map_err(|e| e.to_string())?
        .build()
        .map_err(|e| e.to_string())?;
    let proxy = zbus::blocking::Proxy::new(&connection, SERVICE, PATH, INTERFACE)
        .map_err(|e| e.to_string())?;

    let error = proxy
        .call_method("List", &())
        .err()
        .ok_or("an armed stand-in served the call instead of refusing it")?;
    match error {
        zbus::Error::MethodError(name, detail, _) => {
            if name.as_str() != RETIRING_ERROR {
                return Err(format!(
                    "this fixture refuses under `{name}`, and a client asks again on \
                     `{RETIRING_ERROR}` -- so every case below would be testing a name \
                     nothing recognises"
                ));
            }
            let detail = detail.unwrap_or_default();
            if !detail.contains("ask again") {
                return Err(format!(
                    "the refusal must name the remedy, since a client without the retry \
                     shows it verbatim: {detail}"
                ));
            }
        }
        other => return Err(format!("not a typed D-Bus error at all: {other}")),
    }

    if shared.refusals() != before + 1 {
        return Err(
            "the refusal was not counted, so no case below can prove it met one".to_string(),
        );
    }
    // And the other half: the name really moved, so the retry a client makes
    // reaches somebody else. Asked of the bus rather than of this file.
    let served = proxy
        .call_method("List", &())
        .map_err(|e| format!("the retry was refused too, so the name never moved: {e}"))?;
    let _: Vec<WireRule> = served.body().deserialize().map_err(|e| e.to_string())?;
    Ok(())
}

/// The window's own refresh: three calls, made every time anything says what
/// is open may have changed, and the reads that fill everything on screen.
///
/// Before the retry the first of them met the refusal and the window rendered
/// it: "Porthole helper reported an error", with the helper's own sentence
/// about retiring underneath, and no rules at all -- about a helper that was
/// perfectly well and one call away.
fn a_refresh_that_meets_a_retiring_helper_shows_what_the_next_one_says(
    shared: &Arc<Shared>,
) -> Result<(), String> {
    *shared.rules.lock().expect("not poisoned") = vec![wire_rule(PORT)];
    let before = shared.refusals();
    shared.armed.store(true, Ordering::SeqCst);

    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.RetiringRefresh",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();
            let populated = pump_until(|| win.open_now().rows().len() == 1, DEADLINE);
            seen.replace(Some((
                populated,
                win.open_now().rows().len(),
                win.open_now().error_note().map(|note| {
                    format!(
                        "{} -- {}",
                        note.title(),
                        note.description().unwrap_or_default()
                    )
                }),
                (win.status_bar().text(), win.status_bar().is_prominent()),
                win.open_button().is_sensitive(),
            )));
            win.close();
        },
    );

    let (populated, rows, error_note, (status, prominent), open_button_live) =
        result.borrow_mut().take().ok_or("activation never ran")?;

    if shared.refusals() != before + 1 {
        return Err(format!(
            "the window's refresh never met the refusal this case armed ({} refusals, \
             expected {}), so it proves nothing about retrying one",
            shared.refusals(),
            before + 1
        ));
    }
    if let Some(note) = error_note {
        return Err(format!(
            "a routine, recoverable, self-healing event was rendered as trouble: {note}"
        ));
    }
    if !populated || rows != 1 {
        return Err(format!(
            "the window ended up showing {rows} rules where the helper that answered \
             the retry reports 1"
        ));
    }
    // The status line is filled by the second of the refresh's three calls,
    // so it is the other half of the same repair: a banner rather than the
    // ordinary dim line is how this window says something is wrong, and there
    // is nothing wrong here.
    if prominent {
        return Err(format!(
            "the status bar raised its prominent banner over a helper that had merely \
             retired: {status:?}"
        ));
    }
    if !status.contains("firewalld") {
        return Err(format!(
            "the status line never got a real answer at all: {status:?}"
        ));
    }
    if !open_button_live {
        return Err(
            "the window stopped offering to open a port, which is what it does \
                    only for a helper it can never read"
                .to_string(),
        );
    }
    Ok(())
}

/// The button a person is actually watching when this happens.
///
/// `close` is the command the idle exit charges for -- `list` and `status`
/// never reach the helper, and `open`/`forward` sit behind a polkit dialog
/// measured in human seconds -- and it is the likeliest to arrive during a
/// retirement, because closing the last rule is what starts the grace period
/// that ends in one. Pressing it used to produce a toast carrying the
/// helper's refusal and a row left standing.
fn a_close_pressed_against_a_retiring_helper_closes_the_port(
    shared: &Arc<Shared>,
) -> Result<(), String> {
    *shared.rules.lock().expect("not poisoned") = vec![wire_rule(PORT)];
    let before = shared.refusals();

    let armed = shared.clone();
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.RetiringClose",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();
            if !pump_until(|| win.open_now().rows().len() == 1, DEADLINE) {
                seen.replace(Some((false, false, 1, true)));
                return;
            }
            let button = win.open_now().close_button_for(0).expect("a rendered row");
            let busy = win.open_now().close_busy_for(0).expect("a rendered row");

            // Armed only now: the refresh above had to be served, so that the
            // refusal this case is about is the *close* and not a read.
            armed.armed.store(true, Ordering::SeqCst);
            button.emit_clicked();

            let answered = pump_until(|| !busy.is_busy(), DEADLINE);
            let closed = pump_until(|| win.open_now().rows().is_empty(), DEADLINE);
            seen.replace(Some((
                answered,
                closed,
                win.open_now().rows().len(),
                busy.is_showing(),
            )));
            win.close();
        },
    );

    let (answered, closed, rows, still_spinning) =
        result.borrow_mut().take().ok_or("activation never ran")?;

    if shared.refusals() != before + 1 {
        return Err(format!(
            "the close never met the refusal this case armed ({} refusals, expected {}), \
             so it proves nothing about retrying one",
            shared.refusals(),
            before + 1
        ));
    }
    if !answered {
        return Err("the close never stopped reporting an outstanding operation".to_string());
    }
    if still_spinning {
        return Err("the row went on spinning after the close was answered".to_string());
    }
    if !closed || rows != 0 {
        return Err(format!(
            "the row is still standing ({rows} of them), so the close was reported as a \
             failure and the port was never closed"
        ));
    }
    if !shared.rules.lock().expect("not poisoned").is_empty() {
        return Err(
            "the retry never reached the instance that took the name, so nothing \
                    was actually closed"
                .to_string(),
        );
    }
    Ok(())
}

/// The other button, and the press most likely to meet a retirement at all:
/// the first thing a person does after not having used porthole for a while,
/// which is exactly the state that made the helper retire.
///
/// A retried `open` can also come back `AlreadyOpen`, when the first attempt
/// took effect and lost its reply -- that is the helper's own sentence about
/// a port that is open, which is the truth about the machine, and it is not
/// what this case produces: `Retiring` is answered by an instance that
/// deliberately did **not** act.
fn an_open_pressed_against_a_retiring_helper_opens_the_port(
    shared: &Arc<Shared>,
) -> Result<(), String> {
    shared.rules.lock().expect("not poisoned").clear();
    let before = shared.refusals();

    let armed = shared.clone();
    let result = Rc::new(RefCell::new(None));
    let seen = result.clone();
    activate(
        "com.jacopobriccola.Porthole.Test.RetiringOpen",
        move |app| {
            let win = PortholeWindow::new(app);
            win.present();
            if !pump_until(|| win.open_now().empty_note().is_some(), DEADLINE) {
                seen.replace(Some((false, false, true)));
                return;
            }

            let dialog = OpenDialog::for_port(PORT);
            dialog.present(Some(&*win));
            let presented = dialog.dialog().root().is_some();

            // Armed only now, so the refusal belongs to the `open` and not to
            // the refresh that filled the window behind it.
            armed.armed.store(true, Ordering::SeqCst);
            dialog.open_button().emit_clicked();

            let closed = pump_until(|| dialog.dialog().root().is_none(), DEADLINE);
            seen.replace(Some((presented, closed, dialog.busy().is_busy())));
            win.close();
        },
    );

    let (presented, closed, still_busy) =
        result.borrow_mut().take().ok_or("activation never ran")?;

    if shared.refusals() != before + 1 {
        return Err(format!(
            "the open never met the refusal this case armed ({} refusals, expected {}), \
             so it proves nothing about retrying one",
            shared.refusals(),
            before + 1
        ));
    }
    if !presented {
        return Err("the dialog was never on screen, so this case pressed nothing".to_string());
    }
    if still_busy {
        return Err("the dialog is still reporting an outstanding open".to_string());
    }
    if !closed {
        return Err(
            "the dialog stayed on screen, which is what it does when the open was \
                    reported as a failure"
                .to_string(),
        );
    }
    if !shared
        .rules
        .lock()
        .expect("not poisoned")
        .iter()
        .any(|r| r.port == PORT)
    {
        return Err(
            "no `open` ever reached the instance that took the name, so the port \
                    was never opened"
                .to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------

fn main() {
    // Before any window exists: the window reaches the helper on the *system*
    // bus, and the only daemon in this container is the private session one
    // `dbus-run-session` started. See this file's own module doc.
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .expect("gui-test.sh runs this target under dbus-run-session");
    std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", &address);

    let (ask, asked) = mpsc::channel::<()>();
    let (finished, done) = mpsc::channel::<()>();
    let shared = Arc::new(Shared {
        address: address.clone(),
        rules: Arc::new(Mutex::new(Vec::new())),
        armed: AtomicBool::new(false),
        refusals: AtomicUsize::new(0),
        ask: Mutex::new(ask),
        done: Mutex::new(done),
    });

    // The first generation, and the successor of every refusal after it. The
    // handover runs on a thread of its own so that the connection being left
    // never has to do any work while one of its own methods is waiting -- see
    // `Shared::refuse_after_handing_the_name_over`.
    let mut generations = vec![take_the_name(&shared)];
    let shared_for_handover = shared.clone();
    std::thread::spawn(move || {
        while asked.recv().is_ok() {
            generations.push(take_the_name(&shared_for_handover));
            if finished.send(()).is_err() {
                return;
            }
        }
    });

    let cases: [Case; 4] = [
        (
            "the_refusal_this_fixture_sends_is_the_one_the_real_helper_sends",
            the_refusal_this_fixture_sends_is_the_one_the_real_helper_sends,
        ),
        (
            "a_refresh_that_meets_a_retiring_helper_shows_what_the_next_one_says",
            a_refresh_that_meets_a_retiring_helper_shows_what_the_next_one_says,
        ),
        (
            "a_close_pressed_against_a_retiring_helper_closes_the_port",
            a_close_pressed_against_a_retiring_helper_closes_the_port,
        ),
        (
            "an_open_pressed_against_a_retiring_helper_opens_the_port",
            an_open_pressed_against_a_retiring_helper_opens_the_port,
        ),
    ];

    let failed = Cell::new(false);
    for (name, case) in cases {
        match case(&shared) {
            Ok(()) => println!("test {name} ... ok"),
            Err(message) => {
                println!("test {name} ... FAILED: {message}");
                failed.set(true);
            }
        }
    }

    if failed.get() {
        std::process::exit(1);
    }
}
