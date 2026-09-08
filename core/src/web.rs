use std::collections::VecDeque;

pub const CSS: &str = include_str!("web/page.css");
pub const JS: &str = include_str!("web/page.js");

pub const HISTORY_INTERVAL_SECS: u64 = crate::SECS_PER_MINUTE;
pub const HISTORY_CAP: usize = (crate::SECS_PER_DAY / HISTORY_INTERVAL_SECS) as usize;

pub type History = VecDeque<(u64, f64)>;

pub fn push_sample(history: &mut History, at: u64, hashes_per_second: f64) {
    history.push_back((at, hashes_per_second));
    while history.len() > HISTORY_CAP {
        history.pop_front();
    }
}

pub fn assemble(page: &str) -> String {
    page.replace("<!--shared-css-->", &format!("<style>\n{CSS}</style>"))
        .replace("<!--shared-js-->", &format!("<script>\n{JS}</script>"))
}
