//! Sending queued shares to the pool and reading the verdicts back. Each job's sections are sent
//! once per connection, and a share whose job or anti-block-withholding commitment this connection
//! no longer holds is not sent at all.

use super::{Session, SessionError};
use crate::datum::{AbwState, QueuedShare};
use crate::job::CoinbaseKind;
use crate::stratum::notify_id::NotifyPrefix;
use log::{debug, warn};
use ratum::datum::coinbase::TARGET_BYTE_PLACEHOLDER;
use ratum::datum::messages::coinbaser::CoinbaserRequest;
use ratum::datum::messages::share::{self, Blake2bSection, CoinbaseSection, JobSection, PowSubmit};
use ratum::datum::messages::share_response::{RejectReason, ShareResponse, ShareVerdict};
use ratum::header::{FLAG_USE_TIME_OFFSET, V2_FLAG};
use ratum::target;
use std::time::{Duration, Instant};

const SHARE_ACK_GRACE: Duration = Duration::from_secs(25);

/// Which sections of a job the pool has already received on this connection, so a share
/// carries each once.
#[derive(Clone, Copy)]
pub(super) struct SentSections {
    /// The `Job::serial` these were sent for; a slot reused by a newer job starts again.
    job_serial: u64,
    job_section_sent: bool,
    pooled_coinbase_sent: bool,
    subsidy_only_coinbase_sent: bool,
}

impl SentSections {
    fn new(job_serial: u64) -> Self {
        Self {
            job_serial,
            job_section_sent: false,
            pooled_coinbase_sent: false,
            subsidy_only_coinbase_sent: false,
        }
    }

    fn mark_coinbase_sent(&mut self, kind: CoinbaseKind) -> bool {
        let sent = match kind {
            CoinbaseKind::Pooled => &mut self.pooled_coinbase_sent,
            CoinbaseKind::SubsidyOnly => &mut self.subsidy_only_coinbase_sent,
        };
        std::mem::replace(sent, true)
    }
}

impl Session<'_> {
    pub(super) fn on_share_response(&mut self, r: ShareResponse) {
        let diff = if r.target_byte == TARGET_BYTE_PLACEHOLDER {
            self.gateway.pool.min_difficulty().max(1)
        } else {
            target::difficulty_for_exponent(r.target_byte)
        };
        let accepted =
            matches!(r.verdict, ShareVerdict::Accepted | ShareVerdict::AcceptedTentatively);
        self.gateway.pool.tally(accepted, diff);
        let what = format!("job {} nonce {:08x} diff {diff}", r.job_id, r.nonce);
        match r.verdict {
            ShareVerdict::Accepted => debug!("DATUM share accepted: {what}"),
            ShareVerdict::AcceptedTentatively => {
                debug!("DATUM share accepted: {what} (tentatively)");
            }
            ShareVerdict::Rejected(RejectReason::Unknown(code)) => {
                warn!(
                    "DATUM share rejected: {what}: reason code {code} (not one this build names)"
                );
            }
            ShareVerdict::Rejected(reason) => {
                warn!("DATUM share rejected: {what}: {reason:?} ({})", reason.code());
            }
        }
        if accepted {
            self.last_share_accepted_at = Some(Instant::now());
        }
    }

    pub(super) fn send_pending(&mut self) -> Result<(), SessionError> {
        let pending = self.gateway.pool.session().coinbaser_request.take();
        if let Some(p) = pending {
            let req = CoinbaserRequest { value: p.value, prev_hash: p.prev_hash };
            debug!("coinbaser request: {} sats", p.value);
            self.send_mining(&req.encode())?;
            self.awaiting_coinbaser = Some(p);
        }
        if self.gateway.config.datum.protocol_v3
            && (!self.gateway.pool.is_active()
                || self.gateway.pool.abw_state() == AbwState::Awaiting)
        {
            return Ok(());
        }
        let batch = self.gateway.pool.take_queued_shares();
        for share in &batch {
            self.send_share(share)?;
        }
        Ok(())
    }

    fn sections_for(
        &mut self,
        share: &QueuedShare,
    ) -> (Option<JobSection>, Option<CoinbaseSection>) {
        let job = &share.job;
        let sent = self.sent_sections[job.slot as usize]
            .get_or_insert_with(|| SentSections::new(job.serial));
        if sent.job_serial != job.serial {
            *sent = SentSections::new(job.serial);
        }
        let job_section =
            (!std::mem::replace(&mut sent.job_section_sent, true)).then(|| job.job_section.clone());
        let kind = share.prefix.coinbase();
        let coinbase_section =
            (!sent.mark_coinbase_sent(kind)).then(|| job.coinbase(kind).section.clone());
        (job_section, coinbase_section)
    }

    fn send_share(&mut self, share: &QueuedShare) -> Result<(), SessionError> {
        let job = &share.job;
        if self.gateway.jobs.at(job.slot).is_none_or(|held| held.serial != job.serial) {
            debug!(
                "share for job {} that the table no longer holds (its slot was reused, or the \
                 job aged out of it); not sent",
                job.serial
            );
            return Ok(());
        }
        if let Some(a) = job.abw
            && !self.gateway.pool.session().abw.holds(a)
        {
            warn!(
                "share on ABW slot {} whose commitment this session does not hold (revealed, \
                 or seeded anew after a reconnect); not sent",
                a.slot
            );
            return Ok(());
        }
        let h = &share.header;
        let Some(extranonce) = share::share_extranonce(&h.extranonce) else {
            warn!("share header extranonce does not begin with four zero bytes; not sent");
            return Ok(());
        };
        let (job_section, coinbase_section) = self.sections_for(share);
        let cfg = &self.gateway.config;
        let username =
            crate::username::for_wire(&cfg.datum, &cfg.mining.pool_address, &share.username);
        let submit = pow_submit(share, extranonce, username, job_section, coinbase_section);
        debug!(
            "DATUM share: slot {} coinbase {} diff 2^{} user {:?}{}",
            job.slot,
            share.prefix.coinbase().wire_id(),
            share.target_byte,
            share.username,
            if share.is_block { " BLOCK" } else { "" }
        );
        self.send_mining(&submit.encode())?;
        let now = Instant::now();
        if self.last_share_sent_at.is_none_or(|t| now.duration_since(t) > SHARE_ACK_GRACE) {
            self.last_share_accepted_at = Some(now);
        }
        self.last_share_sent_at = Some(now);
        Ok(())
    }
}

/// The share message for a queued share: `extranonce` is the twelve bytes of its header's
/// extranonce field and `job`, `coinbase` the sections the pool has not yet received.
fn pow_submit(
    share: &QueuedShare,
    extranonce: [u8; share::EXTRANONCE_SIZE],
    username: String,
    job: Option<JobSection>,
    coinbase: Option<CoinbaseSection>,
) -> PowSubmit {
    let h = &share.header;
    let blake2b = Blake2bSection::from_header(h);
    PowSubmit {
        job_id: share.job.slot,
        coinbase_id: share.prefix.coinbase().wire_id(),
        is_block: share.is_block,
        subsidy_only: share.prefix == NotifyPrefix::EmptyWork,
        quickdiff: share.prefix == NotifyPrefix::Quickdiff,
        target_byte: share.target_byte,
        ntime: blake2b.time_fields().0,
        nonce: h.nonce,
        version: V2_FLAG | h.version as u32,
        extranonce,
        username,
        use_time_offset: h.flags & FLAG_USE_TIME_OFFSET != 0,
        job,
        coinbase,
        blake2b,
        abw_slot: share.job.abw.map(|a| a.slot),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datum::abw::AbwAssignment;
    use crate::fixtures::{config, template};
    use crate::job::Job;
    use crate::job::builder::{JobInputs, build};
    use ratum::header::{sia_words, xor_key_hash};
    use std::sync::Arc;

    /// Rebuilds the share the way the pool does, from the message alone.
    fn pool_raw_pow_hash(submit: &PowSubmit, abw_key: Option<[u8; 16]>) -> [u8; 32] {
        let job = submit.job.as_ref().expect("the first share carries the job");
        let cb = submit.coinbase.as_ref().expect("and the coinbase");
        let tx = job.coinbase_tx(cb, submit.target_byte).expect("the index is in the coinbase");
        let merkle_root = job.merkle_root(&tx, submit.subsidy_only);
        submit.header(job, &merkle_root, abw_key).expect("a header").pow_hashes().raw_pow_hash
    }

    fn raw_pow_hashes(
        job: &Arc<Job>,
        prefix: NotifyPrefix,
        abw_key: Option<[u8; 16]>,
    ) -> [[u8; 32]; 2] {
        let kind = prefix.coinbase();
        let target_byte = 14;
        let mut extranonce = [0u8; share::HEADER_EXTRANONCE_SIZE];
        extranonce[share::HEADER_EXTRANONCE_PAD..].fill(0x5a);
        let header = job
            .header(kind, target_byte, extranonce, sia_words(7, 8), sia_words(9, 10))
            .expect("a header");
        let gateway = job.raw_pow_hash(&header);
        let queued = QueuedShare {
            job: Arc::clone(job),
            prefix,
            is_block: false,
            target_byte,
            header,
            username: "bcrt1qexample".into(),
        };
        let submit = pow_submit(
            &queued,
            share::share_extranonce(&extranonce).unwrap(),
            queued.username.clone(),
            Some(job.job_section.clone()),
            Some(job.coinbase(kind).section.clone()),
        );
        let decoded = PowSubmit::decode(&submit.encode()).expect("the message decodes");
        [gateway, pool_raw_pow_hash(&decoded, abw_key)]
    }

    fn build_job(abw: Option<AbwAssignment>) -> Arc<Job> {
        let mut t = template();
        t.txns = vec![crate::template::Txn { raw: vec![1], txid: [3; 32], witness_hash: [4; 32] }];
        let inputs = JobInputs { abw, ..JobInputs::new(0, Arc::new(t)) };
        Arc::new(build(&config(), inputs).unwrap())
    }

    #[test]
    fn the_pool_rebuilds_the_hash_the_gateway_computed_for_every_kind_of_work() {
        let key = [0x21u8; 16];
        let assignment = AbwAssignment { slot: 2, key_hash: xor_key_hash(&key) };
        for (abw, abw_key) in [(None, None), (Some(assignment), Some(key))] {
            let job = build_job(abw);
            for prefix in [NotifyPrefix::Plain, NotifyPrefix::Quickdiff, NotifyPrefix::EmptyWork] {
                let [gateway, pool] = raw_pow_hashes(&job, prefix, abw_key);
                assert_eq!(gateway, pool, "{prefix:?}, ABW {}", abw.is_some());
            }
        }
    }
}
