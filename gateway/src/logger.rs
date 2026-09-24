//! The log sinks the configuration names, a console or stderr sink and a file, each at its own
//! level, the timestamp format the C gateway writes, and the file's daily rotation and its reopen
//! on SIGHUP.

use crate::config::{LoggerConfig, StartupNote};
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Set by the SIGHUP handler and read before the next record is written to the file.
static REOPEN: AtomicBool = AtomicBool::new(false);

/// Asks the file sink to open its path again before it writes its next record, so a rotation
/// performed outside the process (logrotate's rename, then SIGHUP) is followed. Called from a
/// signal handler, so it only stores to an atomic.
pub fn request_reopen() {
    REOPEN.store(true, Ordering::Relaxed);
}

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

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// The open log file, the path it was opened from, and the UTC day of the last record written to
/// it, which names the file that daily rotation renames it to.
struct LogFile {
    file: File,
    path: PathBuf,
    day: i64,
    rotate_daily: bool,
}

impl LogFile {
    /// Opens the path again, keeping the open handle when it cannot be opened: a log file is not
    /// a reason to end the process, and the records still reach the file the handle refers to.
    fn reopen(&mut self) {
        match open_append(&self.path) {
            Ok(file) => self.file = file,
            Err(e) => eprintln!(
                "cannot open the log file {} again: {e}; writing to the handle already open",
                self.path.display()
            ),
        }
    }

    /// Renames the file to `<path>.YYYY-MM-DD` of the day it holds and opens the path again, as
    /// the C gateway does at midnight. The day is the record's, so an idle process rotates on its
    /// first record of the new day.
    fn rotate(&mut self) {
        let (y, m, d) = civil_from_days(self.day);
        let mut to = self.path.clone().into_os_string();
        to.push(format!(".{y:04}-{m:02}-{d:02}"));
        let to = PathBuf::from(to);
        if let Err(e) = std::fs::rename(&self.path, &to) {
            eprintln!(
                "cannot rename the log file {} to {} for rotation: {e}",
                self.path.display(),
                to.display()
            );
            return;
        }
        self.reopen();
    }

    /// Reopens the file when SIGHUP asked for it and rotates it on the first record of a new UTC
    /// day, before that record is written.
    fn maintain(&mut self, secs: u64, reopen: bool) {
        let day = (secs / ratum::SECS_PER_DAY) as i64;
        if reopen {
            self.reopen();
        } else if self.rotate_daily && day > self.day {
            self.rotate();
        }
        self.day = day;
    }
}

enum Output {
    Stdout,
    Stderr,
    File(Mutex<LogFile>),
}

struct Sink {
    output: Output,
    level: LevelFilter,
}

impl Sink {
    fn write(&self, line: &[u8], secs: u64) {
        let _ = match &self.output {
            Output::Stdout => std::io::stdout().lock().write_all(line),
            Output::Stderr => std::io::stderr().lock().write_all(line),
            Output::File(file) => {
                let mut file = file.lock().unwrap_or_else(|e| e.into_inner());
                file.maintain(secs, REOPEN.swap(false, Ordering::Relaxed));
                file.file.write_all(line)
            }
        };
    }

    fn flush(&self) {
        let _ = match &self.output {
            Output::Stdout => std::io::stdout().lock().flush(),
            Output::Stderr => std::io::stderr().lock().flush(),
            Output::File(file) => file.lock().unwrap_or_else(|e| e.into_inner()).file.flush(),
        };
    }
}

pub struct Logger {
    sinks: Vec<Sink>,
    max_level: LevelFilter,
    calling_function: bool,
}

const DAYS_TO_UNIX_EPOCH: i64 = 719_468;
const DAYS_PER_ERA: i64 = 146_097;
const YEARS_PER_ERA: i64 = 400;

/// The civil year, month and day of a day count from the Unix epoch.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + DAYS_TO_UNIX_EPOCH;
    let era = z.div_euclid(DAYS_PER_ERA);
    let doe = z.rem_euclid(DAYS_PER_ERA);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * YEARS_PER_ERA;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn format_time(secs: u64, millis: u32) -> String {
    let (y, m, d) = civil_from_days((secs / ratum::SECS_PER_DAY) as i64);
    let sod = secs % ratum::SECS_PER_DAY;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{millis:03}",
        sod / ratum::SECS_PER_HOUR,
        (sod % ratum::SECS_PER_HOUR) / ratum::SECS_PER_MINUTE,
        sod % ratum::SECS_PER_MINUTE
    )
}

fn now() -> (u64, u32) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (now.as_secs(), now.subsec_millis())
}

impl Logger {
    fn line(&self, r: &Record, secs: u64, millis: u32) -> String {
        let mut line = String::with_capacity(96);
        let _ = write!(line, "{} {:<5} ", format_time(secs, millis), r.level());
        if self.calling_function {
            let _ = write!(line, "[{}] ", r.target());
        }
        let _ = writeln!(line, "{}", r.args());
        line
    }
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= self.max_level
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let (secs, millis) = now();
        let line = self.line(r, secs, millis);
        for sink in self.sinks.iter().filter(|s| r.level() <= s.level) {
            sink.write(line.as_bytes(), secs);
        }
    }

    fn flush(&self) {
        for sink in &self.sinks {
            sink.flush();
        }
    }
}

fn build(cfg: &LoggerConfig) -> Result<(Logger, Vec<StartupNote>), String> {
    let mut notes = Vec::new();
    let mut sinks = Vec::with_capacity(2);

    if cfg.log_to_console {
        let mut level = level_of(cfg.log_level_console);
        if let Ok(spec) = std::env::var("RUST_LOG") {
            match spec.trim().parse::<LevelFilter>() {
                Ok(l) => level = l,
                Err(_) => notes.push(StartupNote {
                    level: Level::Warn,
                    message: format!("RUST_LOG={spec:?} is not a level name (off, error, warn, info, debug, trace); ignored"),
                }),
            }
        }
        let output = if cfg.log_to_stderr { Output::Stderr } else { Output::Stdout };
        sinks.push(Sink { output, level });
    }
    if cfg.log_to_file && !cfg.log_file.is_empty() {
        let path = PathBuf::from(&cfg.log_file);
        let file = open_append(&path)
            .map_err(|e| format!("cannot open log file {}: {e}", cfg.log_file))?;
        let log_file = LogFile {
            file,
            path,
            day: (now().0 / ratum::SECS_PER_DAY) as i64,
            rotate_daily: cfg.log_rotate_daily,
        };
        sinks.push(Sink {
            output: Output::File(Mutex::new(log_file)),
            level: level_of(cfg.log_level_file),
        });
    }

    let max_level = sinks.iter().map(|s| s.level).max().unwrap_or(LevelFilter::Off);
    Ok((Logger { sinks, max_level, calling_function: cfg.log_calling_function }, notes))
}

pub fn init(cfg: &LoggerConfig) -> Result<Vec<StartupNote>, String> {
    let (logger, notes) = build(cfg)?;
    let max_level = logger.max_level;
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(max_level);
    }
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2023-11-14 22:13:20 UTC, the instant the timestamp test names.
    const SECS: u64 = 1_700_000_000;
    const DAY: i64 = (SECS / ratum::SECS_PER_DAY) as i64;

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
        assert_eq!(format_time(SECS, 123), "2023-11-14 22:13:20.123");
        assert_eq!(format_time(4_102_444_799, 999), "2099-12-31 23:59:59.999");
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ratum-logger-{}-{name}", std::process::id()))
    }

    fn written(level: Level, target: &str, msg: &str) -> String {
        let path = temp_path(&format!("{level}-{target}"));
        let _ = std::fs::remove_file(&path);
        let logger = Logger {
            sinks: vec![Sink {
                output: Output::File(Mutex::new(LogFile {
                    file: open_append(&path).unwrap(),
                    path: path.clone(),
                    day: DAY,
                    rotate_daily: false,
                })),
                level: LevelFilter::Info,
            }],
            max_level: LevelFilter::Info,
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

    fn log_file(name: &str, rotate_daily: bool) -> (LogFile, PathBuf) {
        let path = temp_path(name);
        let _ = std::fs::remove_file(&path);
        let file = LogFile {
            file: open_append(&path).unwrap(),
            path: path.clone(),
            day: DAY,
            rotate_daily,
        };
        (file, path)
    }

    #[test]
    fn a_new_day_renames_the_file_to_the_day_it_holds_and_writes_on_to_the_path() {
        let (mut file, path) = log_file("rotate", true);
        file.file.write_all(b"yesterday\n").unwrap();
        file.maintain(SECS + ratum::SECS_PER_DAY, false);
        file.file.write_all(b"today\n").unwrap();
        let rotated = path
            .with_file_name(format!("{}.2023-11-14", path.file_name().unwrap().to_str().unwrap()));
        assert_eq!(std::fs::read_to_string(&rotated).unwrap(), "yesterday\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "today\n");
        let _ = std::fs::remove_file(&rotated);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_same_day_and_a_cleared_log_rotate_daily_both_leave_the_file_open() {
        let (mut file, path) = log_file("no-rotate", false);
        file.maintain(SECS + ratum::SECS_PER_DAY, false);
        file.file.write_all(b"one file\n").unwrap();
        let (mut file, kept) = log_file("same-day", true);
        file.maintain(SECS + 1, false);
        file.file.write_all(b"one file\n").unwrap();
        for p in [&path, &kept] {
            assert_eq!(std::fs::read_to_string(p).unwrap(), "one file\n");
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn a_reopen_request_opens_the_path_again_after_a_rename_outside_the_process() {
        let (mut file, path) = log_file("reopen", true);
        file.file.write_all(b"before\n").unwrap();
        let moved = path.with_extension("1");
        std::fs::rename(&path, &moved).unwrap();
        file.maintain(SECS + ratum::SECS_PER_DAY, true);
        file.file.write_all(b"after\n").unwrap();
        assert_eq!(std::fs::read_to_string(&moved).unwrap(), "before\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
        let _ = std::fs::remove_file(&moved);
        let _ = std::fs::remove_file(&path);
    }
}
