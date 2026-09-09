use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

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

struct Sink {
    output: Output,
    level: LevelFilter,
}

impl Sink {
    /// Runs `f` on whichever stream this sink writes to. Both callers ignore the result:
    /// a logger that cannot report a failure has nowhere to report it.
    fn on_stream(&self, f: impl FnOnce(&mut dyn Write) -> std::io::Result<()>) {
        let _ = match &self.output {
            Output::Stdout => f(&mut std::io::stdout().lock()),
            Output::Stderr => f(&mut std::io::stderr().lock()),
            Output::File(file) => f(&mut &*file),
        };
    }

    fn write(&self, line: &[u8]) {
        self.on_stream(|w| w.write_all(line));
    }

    fn flush(&self) {
        self.on_stream(|w| w.flush());
    }
}

pub struct Logger {
    sinks: Vec<Sink>,
    max: LevelFilter,
    calling_function: bool,
}

const DAYS_TO_UNIX_EPOCH: i64 = 719_468;
const DAYS_PER_ERA: i64 = 146_097;
const YEARS_PER_ERA: i64 = 400;

fn format_time(secs: u64, millis: u32) -> String {
    let days = (secs / ratum::SECS_PER_DAY) as i64;
    let sod = secs % ratum::SECS_PER_DAY;
    let z = days + DAYS_TO_UNIX_EPOCH;
    let era = z.div_euclid(DAYS_PER_ERA);
    let doe = z.rem_euclid(DAYS_PER_ERA);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * YEARS_PER_ERA;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{millis:03}",
        sod / ratum::SECS_PER_HOUR,
        (sod % ratum::SECS_PER_HOUR) / ratum::SECS_PER_MINUTE,
        sod % ratum::SECS_PER_MINUTE
    )
}

fn now() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format_time(now.as_secs(), now.subsec_millis())
}

impl Logger {
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

pub fn init(cfg: &crate::config::Logger) -> Result<Vec<(Level, String)>, String> {
    let (logger, notes) = build(cfg)?;
    let max = logger.max;
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(max);
    }
    Ok(notes)
}
