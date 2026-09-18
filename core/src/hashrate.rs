//! Hashrate as a rate in hashes per second, and the one-day history the status pages chart,
//! sampled once a minute on its own thread. A history given a file is read back from it at
//! startup and rewritten at every sample, so a restart keeps the samples it already took.

use log::warn;
use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const INTERVAL_SECS: u64 = crate::SECS_PER_MINUTE;
pub const INTERVAL: std::time::Duration = std::time::Duration::from_secs(INTERVAL_SECS);
/// How far back the history reaches: a sample older than this is discarded at the next push,
/// as is the oldest sample once there are more than `HISTORY_CAP` of them.
pub const HISTORY_SPAN_SECS: u64 = crate::SECS_PER_DAY;
const HISTORY_CAP: usize = (HISTORY_SPAN_SECS / INTERVAL_SECS) as usize;

/// The rate `work` difficulty-units of accepted work represent over `span`: each unit is
/// `HASHES_PER_DIFFICULTY` hashes. Zero for a span of no time. Both status interfaces report
/// hashrate through this, so they cannot measure it differently.
pub fn from_work(work: u128, span: std::time::Duration) -> f64 {
    let secs = span.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    work as f64 * crate::HASHES_PER_DIFFICULTY / secs
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HashrateSample {
    pub sampled_at: u64,
    pub hashes_per_second: f64,
}

/// The samples, newest last, and the file they are written to if there is one. The default is
/// kept in memory alone and is lost when the process exits.
#[derive(Debug, Default)]
pub struct HashrateHistory {
    samples: VecDeque<HashrateSample>,
    file: Option<PathBuf>,
}

impl HashrateHistory {
    /// The history held in `path`: the samples already in the file, minus any older than
    /// `HISTORY_SPAN_SECS`, and the file rewritten at every `push`. A file that cannot be read
    /// or parsed is reported and ignored, and the next push replaces it; a file that is not
    /// there yet is not an error.
    pub fn in_file(path: PathBuf) -> Self {
        let samples = read(&path).unwrap_or_else(|e| {
            warn!("hashrate history: cannot read {}: {e}", path.display());
            VecDeque::new()
        });
        let mut history = Self { samples, file: Some(path) };
        history.trim(crate::unix_now());
        history
    }

    pub fn push(&mut self, sample: HashrateSample) {
        let now = sample.sampled_at;
        self.samples.push_back(sample);
        self.trim(now);
        self.save();
    }

    /// Discards the samples taken more than `HISTORY_SPAN_SECS` before `now`, and the oldest
    /// of what is left until `HISTORY_CAP` remain.
    fn trim(&mut self, now: u64) {
        let cutoff = now.saturating_sub(HISTORY_SPAN_SECS);
        while self.samples.front().is_some_and(|s| s.sampled_at < cutoff) {
            self.samples.pop_front();
        }
        while self.samples.len() > HISTORY_CAP {
            self.samples.pop_front();
        }
    }

    fn save(&self) {
        let Some(path) = &self.file else { return };
        if let Err(e) = write_replacing(path, self.json().to_string().as_bytes()) {
            warn!("hashrate history: cannot write {}: {e}", path.display());
        }
    }

    /// The samples as `[sampled_at, hashes_per_second]` pairs, oldest first, the rate
    /// rounded to a whole number of hashes. This is both what the status interfaces serve and
    /// what the file holds.
    pub fn json(&self) -> serde_json::Value {
        self.samples
            .iter()
            .map(|s| serde_json::json!([s.sampled_at, s.hashes_per_second.round() as u64]))
            .collect()
    }
}

/// The samples in `path`, or none at all when there is no such file. A pair that is not two
/// numbers is skipped.
fn read(path: &Path) -> io::Result<VecDeque<HashrateSample>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(VecDeque::new()),
        Err(e) => return Err(e),
    };
    let value: serde_json::Value = serde_json::from_str(&text).map_err(io::Error::other)?;
    let pairs = value.as_array().ok_or_else(|| io::Error::other("not an array of samples"))?;
    Ok(pairs
        .iter()
        .filter_map(|pair| {
            let pair = pair.as_array()?;
            Some(HashrateSample {
                sampled_at: pair.first()?.as_u64()?,
                hashes_per_second: pair.get(1)?.as_f64()?,
            })
        })
        .collect())
}

/// Writes `data` to a file beside `path` and renames it over `path`, so a reader of `path`
/// sees either the previous samples or the new ones, never half a file.
fn write_replacing(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

/// Pushes a sample of `hashes_per_second()` into `history` now and once per `INTERVAL`, on
/// a thread named `name`.
pub fn sample_every(
    name: &str,
    history: Arc<Mutex<HashrateHistory>>,
    hashes_per_second: impl Fn() -> f64 + Send + 'static,
) {
    crate::thread::spawn_repeating(name, INTERVAL, move || {
        let sample = HashrateSample {
            sampled_at: crate::unix_now(),
            hashes_per_second: hashes_per_second(),
        };
        crate::lock(&history).push(sample);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(what: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ratum-hashrate-{what}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample(sampled_at: u64, hashes_per_second: f64) -> HashrateSample {
        HashrateSample { sampled_at, hashes_per_second }
    }

    #[test]
    fn history_keeps_the_newest_cap_samples() {
        let mut h = HashrateHistory::default();
        let start = crate::unix_now();
        for i in 0..(HISTORY_CAP as u64 + 5) {
            h.push(sample(start + i, 1.0));
        }
        assert_eq!(h.samples.len(), HISTORY_CAP);
        assert_eq!(
            h.samples.front().copied(),
            Some(sample(start + 5, 1.0)),
            "the oldest five were discarded"
        );
    }

    #[test]
    fn a_sample_older_than_the_span_is_discarded() {
        let mut h = HashrateHistory::default();
        let now = crate::unix_now();
        h.push(sample(now - HISTORY_SPAN_SECS - 1, 7.0));
        h.push(sample(now - HISTORY_SPAN_SECS, 8.0));
        h.push(sample(now, 9.0));
        assert_eq!(
            h.samples.iter().copied().collect::<Vec<_>>(),
            vec![sample(now - HISTORY_SPAN_SECS, 8.0), sample(now, 9.0)],
            "only the sample before the cutoff was discarded"
        );
    }

    #[test]
    fn a_history_in_a_file_is_read_back() {
        let scratch = Scratch::new("read-back");
        let path = scratch.join("hashrate.json");
        let now = crate::unix_now();
        {
            let mut h = HashrateHistory::in_file(path.clone());
            assert!(h.samples.is_empty(), "no file yet");
            h.push(sample(now - 120, 4.4));
            h.push(sample(now - 60, 5.5));
        }
        let mut reopened = HashrateHistory::in_file(path.clone());
        assert_eq!(
            reopened.samples.iter().copied().collect::<Vec<_>>(),
            vec![sample(now - 120, 4.0), sample(now - 60, 6.0)],
            "the samples come back as the file rounded them"
        );
        reopened.push(sample(now, 6.0));
        assert_eq!(
            read(&path).unwrap().len(),
            3,
            "the push wrote the file again with the new sample"
        );
        assert!(!path.with_extension("json.tmp").exists(), "the temporary file was renamed away");
    }

    #[test]
    fn samples_older_than_the_span_are_dropped_when_the_file_is_read() {
        let scratch = Scratch::new("stale-file");
        let path = scratch.join("hashrate.json");
        let now = crate::unix_now();
        {
            let mut h = HashrateHistory::in_file(path.clone());
            h.push(sample(now - HISTORY_SPAN_SECS - 3600, 3.0));
        }
        let h = HashrateHistory::in_file(path);
        assert!(h.samples.is_empty(), "a history a day old does not come back");
    }

    #[test]
    fn an_unreadable_file_leaves_the_history_empty() {
        let scratch = Scratch::new("unreadable");
        let path = scratch.join("hashrate.json");
        std::fs::write(&path, "{ not samples").unwrap();
        let mut h = HashrateHistory::in_file(path.clone());
        assert!(h.samples.is_empty());
        h.push(sample(crate::unix_now(), 1.0));
        assert_eq!(read(&path).unwrap().len(), 1, "the next push replaced the file");
    }
}
