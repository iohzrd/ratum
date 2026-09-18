//! mining.submit: the job the submitted id names, the header rebuilt from the miner's fields, the
//! checks that decide the reply, and the queueing of the share for the pool.

use super::{
    Connection, DUPLICATE, EXTRANONCE1_SIZE, EXTRANONCE2_SIZE, HIGH_HASH, STALE_PREVBLK,
    STALE_WORK, StratumError, UNAUTHORIZED_WORKER, UNKNOWN_WORK,
};
use crate::datum::QueuedShare;
use crate::job::Job;
use crate::stratum::notify_id::{JOB_ID_TIME_CHARS, NotifyId, NotifyPrefix};
use crate::username;
use log::warn;
use ratum::datum::messages::share::{HEADER_EXTRANONCE_PAD, HEADER_EXTRANONCE_SIZE};
use ratum::header::{SIA_WORD_LEN, SIA_WORDS_LEN, sia_words};
use ratum::{lock, target};
use serde_json::Value;
use std::io;
use std::sync::Arc;
use std::time::Instant;

const BLOCK_FOUND_LOG_LINES: usize = 3;

struct SubmitRequest {
    job: Arc<Job>,
    job_diff: u64,
    notify_id: NotifyId,
    extranonce: [u8; HEADER_EXTRANONCE_SIZE],
    sia_ntime: [u8; SIA_WORDS_LEN],
    sia_nonce: [u8; SIA_WORDS_LEN],
    miner_username: String,
}

impl Connection {
    fn served_diff(&self, r: NotifyId) -> Option<u64> {
        if r.prefix == NotifyPrefix::Quickdiff {
            Some(self.vardiff.quickdiff_value())
        } else {
            self.job_diffs[r.slot as usize]
        }
    }

    pub(super) fn on_submit(&mut self, id: &str, params: &Value) -> io::Result<()> {
        let req = match self.parse_submit(params) {
            Ok(req) => req,
            Err(diff) => {
                self.stats().shares.rejected.add(diff);
                return self.reply_error(id, UNKNOWN_WORK);
            }
        };
        let diff = req.job_diff;
        match self.evaluate(&req) {
            Ok(()) => {
                self.reply_result(id, Value::Bool(true))?;
                self.count_accepted(diff)
            }
            Err(reject) => {
                self.stats().shares.rejected.add(diff);
                self.reply_error(id, reject)
            }
        }
    }

    fn count_accepted(&mut self, diff: u64) -> io::Result<()> {
        let now = Instant::now();
        let mut st = self.stats();
        st.shares.accepted.add(diff);
        st.last_accepted_at = Some(now);
        drop(st);
        self.diff_since_window_start = self.diff_since_window_start.saturating_add(diff);
        if self.vardiff.on_share_accepted(now)
            && let Some(published) = self.gateway.jobs.current()
        {
            self.notify(&published.job, NotifyPrefix::Quickdiff, true)?;
        }
        Ok(())
    }

    /// A refusal is unknown work; it carries the difficulty the refused share is tallied at:
    /// the served difficulty of the job named, or the difficulty last sent while no job of
    /// the submitted id resolves.
    fn parse_submit(&self, params: &Value) -> Result<SubmitRequest, u64> {
        let unknown = self.vardiff.last_sent();
        let id_param = params.get(1).and_then(Value::as_str).ok_or(unknown)?;
        let (notify_id, stratum_job_id) = NotifyId::parse(id_param).ok_or(unknown)?;
        let job = self.gateway.jobs.at(notify_id.slot).ok_or(unknown)?;
        if job.stratum_job_id.get(..JOB_ID_TIME_CHARS) != stratum_job_id.get(..JOB_ID_TIME_CHARS) {
            return Err(unknown);
        }
        let job_diff = self.served_diff(notify_id).ok_or(unknown)?;

        let en2 = params.get(2).and_then(Value::as_str).ok_or(job_diff)?;
        if en2.len() != 2 * EXTRANONCE2_SIZE {
            return Err(job_diff);
        }
        let en2 = hex::decode(en2).map_err(|_| job_diff)?;
        let mut extranonce = [0u8; HEADER_EXTRANONCE_SIZE];
        let sid_at = HEADER_EXTRANONCE_PAD;
        let en2_at = EXTRANONCE1_SIZE;
        extranonce[sid_at..en2_at].copy_from_slice(&self.sid.to_be_bytes());
        extranonce[en2_at..].copy_from_slice(&en2);
        let sia_ntime =
            params.get(3).and_then(Value::as_str).and_then(parse_sia_field).ok_or(job_diff)?;
        let sia_nonce =
            params.get(4).and_then(Value::as_str).and_then(parse_sia_field).ok_or(job_diff)?;
        let miner_username = params.get(0).and_then(Value::as_str).unwrap_or("NULL").to_string();
        Ok(SubmitRequest {
            job,
            job_diff,
            notify_id,
            extranonce,
            sia_ntime,
            sia_nonce,
            miner_username,
        })
    }

    fn evaluate(&mut self, req: &SubmitRequest) -> Result<(), StratumError> {
        let job = &req.job;
        let prefix = req.notify_id.prefix;
        let target_byte = target::floor_log2(req.job_diff);
        let header = job
            .header(prefix.coinbase(), target_byte, req.extranonce, req.sia_ntime, req.sia_nonce)
            .ok_or(UNKNOWN_WORK)?;
        let hash = job.raw_pow_hash(&header);
        let is_block = job.abw.is_none() && target::meets_target(&hash, &job.block_target);
        let block = is_block.then(|| (hex::encode(hash), header.serialize()));
        if let Some((display, _)) = &block {
            for _ in 0..BLOCK_FOUND_LOG_LINES {
                warn!("******** BLOCK FOUND - {display} ********");
            }
        }

        // A block is queued for the pool before the node submission, which waits on
        // submitblock and preciousblock, as the C gateway calls `datum_protocol_pow_submit`
        // before `assembleBlockAndSubmit`. A block is queued whatever the share checks say.
        let checked = self.check_share(job, &hash, target_byte, &req.miner_username);
        if job.is_datum_job && (is_block || checked.is_ok()) {
            let wire_username = self.credited_username(req, &hash);
            self.gateway.pool.queue_share(QueuedShare {
                job: Arc::clone(job),
                prefix,
                is_block,
                target_byte,
                header,
                username: wire_username,
            });
        }
        if let Some((display, serialized)) = &block {
            crate::submit_block::found_block(
                &self.gateway,
                job,
                prefix.coinbase(),
                target_byte,
                serialized,
                display,
            );
        }
        checked
    }

    fn credited_username(&self, req: &SubmitRequest, hash: &[u8; 32]) -> String {
        let cfg = &self.gateway.config;
        username::apply_modifier(
            &cfg.stratum.username_modifiers,
            &cfg.mining.pool_address,
            &req.miner_username,
            hash,
        )
        .unwrap_or_else(|| req.miner_username.clone())
    }

    fn check_share(
        &self,
        job: &Arc<Job>,
        hash: &[u8; 32],
        target_byte: u8,
        username: &str,
    ) -> Result<(), StratumError> {
        let cfg = &self.gateway.config;
        if job.is_stale_prevblock() {
            return Err(STALE_PREVBLK);
        }
        if !target::meets_target(hash, &target::target_for_exponent(target_byte)) {
            return Err(HIGH_HASH);
        }
        if job.created_at.elapsed() > cfg.stale_window() {
            return Err(STALE_WORK);
        }
        if !lock(&self.gateway.stratum.seen_share_hashes).insert(*hash, job.created_at) {
            return Err(DUPLICATE);
        }
        if cfg.stratum.refuses_username(username) {
            return Err(UNAUTHORIZED_WORKER);
        }
        Ok(())
    }
}

pub fn parse_sia_field(s: &str) -> Option<[u8; SIA_WORDS_LEN]> {
    const HEX_CHARS: usize = 2 * SIA_WORDS_LEN;
    const NARROW_HEX_CHARS: usize = 2 * SIA_WORD_LEN;
    match s.len() {
        HEX_CHARS => hex::decode(s).ok()?.try_into().ok(),
        NARROW_HEX_CHARS => Some(sia_words(u32::from_str_radix(s, 16).ok()?, 0)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sia_fields_take_both_widths() {
        assert_eq!(parse_sia_field("0100000002000000"), Some([1, 0, 0, 0, 2, 0, 0, 0]));
        assert_eq!(parse_sia_field("00000001"), Some([1, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(parse_sia_field("0001"), None);
    }
}
