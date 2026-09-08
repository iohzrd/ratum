//! What the pool's and the gateway's status pages share: the stylesheet and the script
//! helpers, in one copy for the three pages, and the hashrate history their charts plot. A
//! page holds the markers `<!--shared-css-->` and `<!--shared-js-->` where `assemble`
//! inserts them.

use std::collections::VecDeque;

pub const CSS: &str = include_str!("web/page.css");
pub const JS: &str = include_str!("web/page.js");

/// The hashrate history a chart plots: one sample per `HISTORY_INTERVAL_SECS`, kept for a
/// day. It begins when the interface starts, so a restart shows as a gap in the chart.
pub const HISTORY_INTERVAL_SECS: u64 = crate::SECS_PER_MINUTE;
pub const HISTORY_CAP: usize = (crate::SECS_PER_DAY / HISTORY_INTERVAL_SECS) as usize;

/// A sample ring of `(unix second, hashes per second)`.
pub type History = VecDeque<(u64, f64)>;

/// Append one sample and discard the oldest beyond `HISTORY_CAP`.
pub fn push_sample(history: &mut History, at: u64, hashes_per_second: f64) {
    history.push_back((at, hashes_per_second));
    while history.len() > HISTORY_CAP {
        history.pop_front();
    }
}

/// The page with the shared stylesheet and script in place of the markers.
pub fn assemble(page: &str) -> String {
    page.replace("<!--shared-css-->", &format!("<style>\n{CSS}</style>"))
        .replace("<!--shared-js-->", &format!("<script>\n{JS}</script>"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_history_keeps_a_day_of_samples() {
        let mut h = super::History::new();
        for i in 0..super::HISTORY_CAP as u64 + 10 {
            super::push_sample(&mut h, i, i as f64);
        }
        assert_eq!(h.len(), super::HISTORY_CAP);
        assert_eq!(h.front().map(|s| s.0), Some(10));
    }

    #[test]
    fn markers_are_replaced() {
        let out = super::assemble("<head><!--shared-css--></head><!--shared-js-->");
        assert!(out.contains("--bg:"));
        assert!(out.contains("function card("));
        assert!(!out.contains("<!--shared"));
    }
}
