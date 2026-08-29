//! The log sinks the `logger` configuration section describes: the console (stdout, or
//! stderr with `log_to_stderr`) and a file, each with its own level, every record stamped
//! with a millisecond UTC time and, with `log_calling_function`, the module it came from.
//! `RUST_LOG` names a level that replaces the console's. SIGHUP (see `signals`) sets
//! `REOPEN`; `main`'s watch loop then calls `reopen`, which reopens the file by name, which
//! is what logrotate needs.

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Set by the SIGHUP handler; `main`'s watch loop clears it and calls `reopen`.
pub static REOPEN: AtomicBool = AtomicBool::new(false);

/// The sinks, for `reopen`.
static SINKS: OnceLock<Arc<Mutex<Sinks>>> = OnceLock::new();

/// Reopen the log file by name. `Ok(false)` when no file sink is configured.
pub fn reopen() -> Result<bool, String> {
    let Some(sinks) = SINKS.get() else { return Ok(false) };
    let mut s = ratum::lock(sinks);
    let Some((file, _, path)) = &mut s.file else { return Ok(false) };
    match open(path) {
        Ok(f) => {
            *file = f;
            Ok(true)
        }
        Err(e) => Err(format!("cannot reopen log file {path}: {e}")),
    }
}

/// The C gateway's levels: 0 all, 1 debug, 2 info, 3 warn, 4 error, 5 fatal. Rust has no
/// level above error, so 5 keeps errors; anything higher turns the sink off.
pub fn level_of(n: u8) -> LevelFilter {
    match n {
        0 => LevelFilter::Trace,
        1 => LevelFilter::Debug,
        2 => LevelFilter::Info,
        3 => LevelFilter::Warn,
        4 | 5 => LevelFilter::Error,
        _ => LevelFilter::Off,
    }
}

struct Sinks {
    console: Option<(Box<dyn Write + Send>, LevelFilter)>,
    file: Option<(File, LevelFilter, String)>,
}

pub struct Logger {
    sinks: Arc<Mutex<Sinks>>,
    max: LevelFilter,
    calling_function: bool,
}

fn open(path: &str) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// `YYYY-MM-DD HH:MM:SS.mmm` in UTC, from the civil-from-days conversion of the epoch day.
fn timestamp() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let days = (secs / 86400) as i64;
    let sod = secs % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{millis:03}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= self.max
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let target =
            if self.calling_function { format!("[{}] ", r.target()) } else { String::new() };
        let line = format!("{} {:<5} {target}{}\n", timestamp(), r.level(), r.args());
        let mut s = ratum::lock(&self.sinks);
        if let Some((w, level)) = &mut s.console
            && r.level() <= *level
        {
            let _ = w.write_all(line.as_bytes());
        }
        if let Some((f, level, _)) = &mut s.file
            && r.level() <= *level
        {
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn flush(&self) {
        let mut s = ratum::lock(&self.sinks);
        if let Some((w, _)) = &mut s.console {
            let _ = w.flush();
        }
        if let Some((f, _, _)) = &mut s.file {
            let _ = f.flush();
        }
    }
}

/// Install the logger. Returns what could not be applied, to log once it is installed.
pub fn init(cfg: &crate::config::Logger) -> Vec<(Level, String)> {
    let mut notes = Vec::new();
    let mut console_level = level_of(cfg.log_level_console);
    if let Ok(spec) = std::env::var("RUST_LOG") {
        match spec.trim().parse::<LevelFilter>() {
            Ok(level) => console_level = level,
            Err(_) => notes.push((
                Level::Warn,
                format!("RUST_LOG={spec:?} is not a level name (off, error, warn, info, debug, trace); ignored"),
            )),
        }
    }
    let console: Option<(Box<dyn Write + Send>, LevelFilter)> = if cfg.log_to_console {
        let w: Box<dyn Write + Send> = if cfg.log_to_stderr {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        };
        Some((w, console_level))
    } else {
        None
    };
    let file = if cfg.log_to_file && !cfg.log_file.is_empty() {
        match open(&cfg.log_file) {
            Ok(f) => Some((f, level_of(cfg.log_level_file), cfg.log_file.clone())),
            // Fatal, as in the C gateway: a configured log file that cannot be written is
            // a deployment error, not a condition to run without.
            Err(e) => {
                eprintln!("cannot open log file {}: {e}", cfg.log_file);
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    let max = [
        console.as_ref().map_or(LevelFilter::Off, |c| c.1),
        file.as_ref().map_or(LevelFilter::Off, |f| f.1),
    ]
    .into_iter()
    .max()
    .unwrap_or(LevelFilter::Off);
    let sinks = Arc::new(Mutex::new(Sinks { console, file }));
    let _ = SINKS.set(Arc::clone(&sinks));
    let logger = Logger { sinks, max, calling_function: cfg.log_calling_function };
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(max);
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_map_as_the_c_gateway_numbers_them() {
        assert_eq!(level_of(0), LevelFilter::Trace);
        assert_eq!(level_of(2), LevelFilter::Info);
        assert_eq!(level_of(5), LevelFilter::Error);
        assert_eq!(level_of(6), LevelFilter::Off);
    }

    #[test]
    fn timestamps_are_utc_civil_dates() {
        let t = timestamp();
        assert_eq!(t.len(), 23, "{t}");
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], " ");
        assert_eq!(&t[19..20], ".");
    }
}
