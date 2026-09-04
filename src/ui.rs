//! Progress rendering: spinners, step counters and status lines.
//!
//! Three rules hold everything together:
//!
//! 1. **Progress goes to stderr.** stdout carries the result — a spinner mixed
//!    into it makes `--json` unparsable, which is exactly the bug this replaced.
//! 2. **Nothing is drawn unless stderr is a terminal.** Pipes, CI logs and test
//!    harnesses get clean output with no escape sequences.
//! 3. **Nothing is drawn for fast work.** A spinner is only shown once an
//!    operation has run past `SHOW_AFTER`, so quick calls do not flicker.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use colored::Colorize;

const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const TICK: Duration = Duration::from_millis(80);
/// Work finishing faster than this never gets a spinner: the flash of one
/// appearing and vanishing reads as a glitch, not as feedback.
const SHOW_AFTER: Duration = Duration::from_millis(300);
/// Erase from the cursor to the end of the line.
const CLEAR_LINE: &str = "\r\x1b[2K";
const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

static QUIET: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(false);
/// Set while a spinner may have written a partial line, so the error path knows
/// it has to clean up before printing.
static DIRTY: AtomicBool = AtomicBool::new(false);
/// The emergency brake. Only the error path sets it: it stops every running
/// spinner without owning any of them, which is what makes `report()` safe to
/// call from inside `with_spinner`.
static STOP_ALL: AtomicBool = AtomicBool::new(false);

/// Decide once, at startup, whether animation is appropriate here.
pub fn init(quiet: bool) {
    let suppressed = quiet
        || std::env::var("MLAB_NO_PROGRESS").map(|v| v != "0").unwrap_or(false)
        || std::env::var("CI").map(|v| !v.is_empty() && v != "0" && v != "false").unwrap_or(false);

    QUIET.store(suppressed, Ordering::SeqCst);
    ENABLED.store(!suppressed && std::io::stderr().is_terminal(), Ordering::SeqCst);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

pub fn quiet() -> bool {
    QUIET.load(Ordering::SeqCst)
}

/// Leave the terminal usable no matter how the process ends. Called from the
/// error path, which exits without unwinding — so no destructor would run.
pub fn restore() {
    STOP_ALL.store(true, Ordering::SeqCst);
    if DIRTY.load(Ordering::SeqCst) {
        // Give the drawing thread one tick to notice, so it cannot repaint the
        // line after we have wiped it.
        thread::sleep(TICK + Duration::from_millis(20));
        clear_line();
    }
}

fn clear_line() {
    if DIRTY.swap(false, Ordering::SeqCst) {
        let mut err = std::io::stderr();
        let _ = write!(err, "{CLEAR_LINE}{SHOW_CURSOR}");
        let _ = err.flush();
    }
}

struct State {
    message: Mutex<String>,
    /// Optional "3/8" style counter rendered after the message.
    step: AtomicU64,
    steps: AtomicU64,
    running: AtomicBool,
}

pub struct Spinner {
    state: Arc<State>,
    handle: Option<JoinHandle<()>>,
    start: Instant,
}

impl Spinner {
    pub fn start(message: impl Into<String>) -> Self {
        let state = Arc::new(State {
            message: Mutex::new(message.into()),
            step: AtomicU64::new(0),
            steps: AtomicU64::new(0),
            running: AtomicBool::new(true),
        });
        let start = Instant::now();

        let handle = if enabled() {
            let state = Arc::clone(&state);
            Some(thread::spawn(move || animate(state, start)))
        } else {
            None
        };

        Self { state, handle, start }
    }

    /// A spinner that also reports progress through a known number of steps.
    pub fn with_steps(message: impl Into<String>, steps: u64) -> Self {
        let s = Self::start(message);
        s.state.steps.store(steps, Ordering::SeqCst);
        s
    }

    pub fn set(&self, message: impl Into<String>) {
        if let Ok(mut m) = self.state.message.lock() {
            *m = message.into();
        }
    }

    pub fn advance(&self) {
        self.state.step.fetch_add(1, Ordering::SeqCst);
    }

    /// Stop drawing and wipe the line, leaving nothing behind.
    pub fn clear(mut self) {
        self.shutdown();
    }

    /// Stop, then leave a one-line summary in place of the spinner.
    pub fn succeed(mut self, message: impl AsRef<str>) {
        self.shutdown();
        note("✔".green().bold(), message.as_ref(), Some(self.start.elapsed()));
    }

    pub fn warn(mut self, message: impl AsRef<str>) {
        self.shutdown();
        note("!".yellow().bold(), message.as_ref(), None);
    }

    fn shutdown(&mut self) {
        self.state.running.store(false, Ordering::SeqCst);
        // Joining first guarantees the thread cannot repaint after the wipe.
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        clear_line();
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn animate(state: Arc<State>, start: Instant) {
    let mut frame = 0usize;
    let mut drawn = false;
    let mut err = std::io::stderr();

    while state.running.load(Ordering::SeqCst) && !STOP_ALL.load(Ordering::SeqCst) {
        if start.elapsed() >= SHOW_AFTER {
            if !drawn {
                DIRTY.store(true, Ordering::SeqCst);
                let _ = write!(err, "{HIDE_CURSOR}");
                drawn = true;
            }

            let message = state
                .message
                .lock()
                .map(|m| m.clone())
                .unwrap_or_default();
            let steps = state.steps.load(Ordering::SeqCst);
            let counter = if steps > 0 {
                format!(" [{}/{}]", state.step.load(Ordering::SeqCst).min(steps), steps)
            } else {
                String::new()
            };

            if STOP_ALL.load(Ordering::SeqCst) {
                break;
            }

            let _ = write!(
                err,
                "{CLEAR_LINE}  {} {}{}  {}",
                FRAMES[frame % FRAMES.len()].cyan(),
                message,
                counter.dimmed(),
                format_elapsed(start.elapsed()).dimmed(),
            );
            let _ = err.flush();
            frame += 1;
        }

        thread::sleep(TICK);
    }
}

/// A standalone status line, on stderr like everything else here.
pub fn note(marker: colored::ColoredString, message: &str, elapsed: Option<Duration>) {
    if quiet() {
        return;
    }
    let suffix = match elapsed {
        Some(d) if d >= Duration::from_secs(1) => format!("  {}", format_elapsed(d).dimmed()),
        _ => String::new(),
    };
    eprintln!("  {marker} {message}{suffix}");
}

pub fn warning(message: &str) {
    note("!".yellow().bold(), message, None);
}

pub fn success(message: &str) {
    note("✔".green().bold(), message, None);
}

pub fn info(message: &str) {
    note("›".cyan().bold(), message, None);
}

pub fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m{:02}s", secs / 60, secs % 60)
    }
}

/// Run `f` behind a spinner. The spinner is wiped before `f`'s result is
/// printed, so progress and output never interleave.
pub fn with_spinner<T>(message: &str, f: impl FnOnce() -> T) -> T {
    let spinner = Spinner::start(message);
    let out = f();
    spinner.clear();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests all steer the same process-wide switches, and the harness
    /// runs them in parallel: without this they race each other.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        let g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        STOP_ALL.store(false, Ordering::SeqCst);
        DIRTY.store(false, Ordering::SeqCst);
        g
    }

    #[test]
    fn elapsed_reads_as_seconds_then_minutes() {
        assert_eq!(format_elapsed(Duration::from_secs(0)), "0s");
        assert_eq!(format_elapsed(Duration::from_secs(59)), "59s");
        assert_eq!(format_elapsed(Duration::from_secs(60)), "1m00s");
        assert_eq!(format_elapsed(Duration::from_secs(3661)), "61m01s");
    }

    #[test]
    fn quiet_mode_disables_drawing_whatever_the_terminal_says() {
        let _g = guard();
        init(true);
        assert!(quiet());
        assert!(!enabled());
    }

    #[test]
    fn a_spinner_still_runs_its_work_when_animation_is_off() {
        let _g = guard();
        init(true);
        let value = with_spinner("working", || 21 * 2);
        assert_eq!(value, 42);
    }

    #[test]
    fn steps_and_messages_can_be_updated_while_running() {
        let _g = guard();
        init(true);
        let s = Spinner::with_steps("checking", 4);
        s.advance();
        s.advance();
        s.set("still checking");
        assert_eq!(s.state.step.load(Ordering::SeqCst), 2);
        assert_eq!(s.state.steps.load(Ordering::SeqCst), 4);
        assert_eq!(&*s.state.message.lock().unwrap(), "still checking");
        s.clear();
    }

    #[test]
    fn restore_is_safe_to_call_when_nothing_was_drawn() {
        let _g = guard();
        restore();
        restore();
    }

    #[test]
    fn a_normal_stop_does_not_arm_the_emergency_brake() {
        // Otherwise the first spinner in a process would silence every later
        // one — `scan file --follow` runs two back to back.
        let _g = guard();
        init(true);
        Spinner::start("one").clear();
        assert!(!STOP_ALL.load(Ordering::SeqCst));
    }
}
