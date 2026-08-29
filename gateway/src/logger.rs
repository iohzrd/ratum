//! The log sinks the `logger` configuration section describes: the console (stdout, or
//! stderr with `log_to_stderr`) and a file, each with its own level, every record stamped
//! with a millisecond UTC time and, with `log_calling_function`, the module it came from.
//! `RUST_LOG` names a level that replaces the console's. The file is held open for the
//! process's life, so rotate it with logrotate's `copytruncate`.
//!
//! The logger holds no lock: `&File` implements `Write`, and stdout and stderr lock
//! themselves for the length of one `write_all`, so each sink writes a record whole.

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// The C gateway's levels: 0 all, 1 debug, 2 info, 3 warn, 4 error, 5 fatal. Rust has no
/// level above error, so 5 keeps errors; anything higher turns the sink off.
fn level_of(n: u8) -> LevelFilter {
    match n {
        0 => LevelFilter::Trace,
        1 => LevelFilter::Debug,
        2 => LevelFilter::Info,
        3 => LevelFilter::Warn,
        4 | 5 => LevelFilter::Error,
        _ => LevelFilter::Off,
    }
}

enum Output {
    Stdout,
    Stderr,
    File(File),
}

/// One destination and the most verbose level it takes.
struct Sink {
    output: Output,
    level: LevelFilter,
}

impl Sink {
    /// A write that fails has nowhere to be reported, so its error is discarded.
    fn write(&self, line: &[u8]) {
        let _ = match &self.output {
            Output::Stdout => std::io::stdout().write_all(line),
            Output::Stderr => std::io::stderr().write_all(line),
            Output::File(f) => (&*f).write_all(line),
        };
    }

    fn flush(&self) {
        let _ = match &self.output {
            Output::Stdout => std::io::stdout().flush(),
            Output::Stderr => std::io::stderr().flush(),
            Output::File(f) => (&*f).flush(),
        };
    }
}

pub struct Logger {
    sinks: Vec<Sink>,
    /// The most verbose of the sinks' levels: a record above it goes nowhere.
    max: LevelFilter,
    calling_function: bool,
}

/// `YYYY-MM-DD HH:MM:SS.mmm` for `secs` since the Unix epoch, in UTC, by the civil-from-days
/// conversion of the epoch day.
fn format_time(secs: u64, millis: u32) -> String {
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

fn now() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format_time(now.as_secs(), now.subsec_millis())
}

impl Logger {
    /// The line a record is written as: the time, the level, the module when
    /// `log_calling_function` is set, the message, a newline.
    fn line(&self, r: &Record) -> String {
        let mut line = String::with_capacity(96);
        let _ = write!(line, "{} {:<5} ", now(), r.level());
        if self.calling_function {
            let _ = write!(line, "[{}] ", r.target());
        }
        let _ = writeln!(line, "{}", r.args());
        line
    }
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= self.max
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let line = self.line(r);
        for sink in self.sinks.iter().filter(|s| r.level() <= s.level) {
            sink.write(line.as_bytes());
        }
    }

    fn flush(&self) {
        for sink in &self.sinks {
            sink.flush();
        }
    }
}

/// The logger the configuration describes and what could not be applied, to log once it is
/// installed. `Err` names a log file that cannot be opened.
fn build(cfg: &crate::config::Logger) -> Result<(Logger, Vec<(Level, String)>), String> {
    let mut notes = Vec::new();
    let mut sinks = Vec::with_capacity(2);

    if cfg.log_to_console {
        let mut level = level_of(cfg.log_level_console);
        if let Ok(spec) = std::env::var("RUST_LOG") {
            match spec.trim().parse::<LevelFilter>() {
                Ok(l) => level = l,
                Err(_) => notes.push((
                    Level::Warn,
                    format!("RUST_LOG={spec:?} is not a level name (off, error, warn, info, debug, trace); ignored"),
                )),
            }
        }
        let output = if cfg.log_to_stderr { Output::Stderr } else { Output::Stdout };
        sinks.push(Sink { output, level });
    }
    if cfg.log_to_file && !cfg.log_file.is_empty() {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.log_file)
            .map_err(|e| format!("cannot open log file {}: {e}", cfg.log_file))?;
        sinks.push(Sink { output: Output::File(file), level: level_of(cfg.log_level_file) });
    }

    let max = sinks.iter().map(|s| s.level).max().unwrap_or(LevelFilter::Off);
    Ok((Logger { sinks, max, calling_function: cfg.log_calling_function }, notes))
}

/// Install the logger. `Err` is the reason it could not be built, which is fatal (as in the
/// C gateway: a log file that cannot be written is a deployment error, not a condition to
/// run without); `Ok` carries what could not be applied, to log once it is installed.
pub fn init(cfg: &crate::config::Logger) -> Result<Vec<(Level, String)>, String> {
    let (logger, notes) = build(cfg)?;
    let max = logger.max;
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(max);
    }
    Ok(notes)
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
    fn times_are_utc_civil_dates() {
        assert_eq!(format_time(0, 0), "1970-01-01 00:00:00.000");
        assert_eq!(format_time(951_782_400, 7), "2000-02-29 00:00:00.007");
        assert_eq!(format_time(1_700_000_000, 123), "2023-11-14 22:13:20.123");
        assert_eq!(format_time(4_102_444_799, 999), "2099-12-31 23:59:59.999");
    }

    /// What a file sink at `Info` writes for one record.
    fn written(level: Level, target: &str, msg: &str) -> String {
        let path = std::env::temp_dir()
            .join(format!("ratum-logger-{}-{level}-{target}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let file = OpenOptions::new().create(true).append(true).open(&path).unwrap();
        let logger = Logger {
            sinks: vec![Sink { output: Output::File(file), level: LevelFilter::Info }],
            max: LevelFilter::Info,
            calling_function: true,
        };
        logger.log(
            &Record::builder().level(level).target(target).args(format_args!("{msg}")).build(),
        );
        logger.flush();
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        text
    }

    #[test]
    fn a_record_is_one_stamped_line_and_a_level_the_sink_does_not_take_is_dropped() {
        let line = written(Level::Warn, "stratum", "hello");
        assert!(line.ends_with(" WARN  [stratum] hello\n"), "{line:?}");
        assert_eq!(line.len(), 23 + " WARN  [stratum] hello\n".len(), "{line:?}");
        assert_eq!(&line[4..5], "-");
        assert_eq!(written(Level::Debug, "stratum", "hidden"), "");
    }
}
