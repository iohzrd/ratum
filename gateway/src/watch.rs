//! The main thread once startup is done: it reports the client count and hashrate every five
//! minutes, and reports a node that has served no job.

use crate::gateway::Gateway;
use log::{error, info};
use std::time::{Duration, Instant};

const WATCH_TICK: Duration = Duration::from_secs(1);
const STATS_INTERVAL: Duration = Duration::from_secs(300);
const FIRST_JOB_PATIENCE: Duration = Duration::from_secs(25);
const NO_JOB_REPORT_INTERVAL: Duration = Duration::from_secs(5);

fn due(last: &mut Instant, interval: Duration) -> bool {
    if last.elapsed() < interval {
        return false;
    }
    *last = Instant::now();
    true
}

fn report_missing_job(gateway: &Gateway, started: Instant, last_report: &mut Instant) {
    if gateway.jobs.current().is_some() || started.elapsed() <= FIRST_JOB_PATIENCE {
        return;
    }
    if due(last_report, NO_JOB_REPORT_INTERVAL) {
        error!(
            "Did not see an initial stratum job after ~{} seconds. Is your node properly setup?",
            started.elapsed().as_secs()
        );
    }
}

fn report_stats(gateway: &Gateway, last: &mut Instant) {
    if !due(last, STATS_INTERVAL) {
        return;
    }
    let s = gateway.stratum.summary();
    info!(
        "Server stats: {} client{} / {:.2} Th/s",
        s.subscribed,
        if s.subscribed == 1 { "" } else { "s" },
        s.hashrate_hs / ratum::HASHES_PER_TERAHASH
    );
}

pub fn run(gateway: &Gateway) -> ! {
    let started = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_no_job_report = Instant::now();
    loop {
        std::thread::sleep(WATCH_TICK);
        report_missing_job(gateway, started, &mut last_no_job_report);
        report_stats(gateway, &mut last_stats);
    }
}
