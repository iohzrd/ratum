//! Crediting each share once, across every connection and however its sections are resent.

use super::*;
use crate::accounting::{AcceptedShareHashes, MAX_ACCEPTED_HASHES, claim};
use std::sync::Mutex;

fn fresh_hashes() -> Mutex<AcceptedShareHashes> {
    Mutex::new(AcceptedShareHashes::new(MAX_ACCEPTED_HASHES))
}

/// `verify` followed by `claim`, as a connection runs them, with the refusal reduced to its
/// reason.
fn claimed(
    v: &mut Verifier,
    hashes: &Mutex<AcceptedShareHashes>,
    s: &PowSubmit,
) -> Result<RebuiltShare, RejectReason> {
    v.verify(s, None, NOW).and_then(|rebuilt| claim(hashes, rebuilt, NOW)).map_err(|r| r.reason)
}

#[test]
fn a_replayed_share_is_refused_however_the_sections_are_resent() {
    let (mut v, s) = setup();
    let hashes = fresh_hashes();
    assert!(claimed(&mut v, &hashes, &s).is_ok());

    assert_eq!(claimed(&mut v, &hashes, &s), Err(RejectReason::DuplicateWork));
    let mut bare = s.clone();
    bare.job = None;
    bare.coinbase = None;
    assert_eq!(claimed(&mut v, &hashes, &bare), Err(RejectReason::DuplicateWork));
    let mut other = s.clone();
    let mut job = other.job.clone().unwrap();
    job.height += 1;
    other.job = Some(job);
    let _ = claimed(&mut v, &hashes, &other);
    assert_eq!(claimed(&mut v, &hashes, &s), Err(RejectReason::DuplicateWork));
    let mut same_work_other_job = s.clone();
    same_work_other_job.job_id = 5;
    assert_eq!(claimed(&mut v, &hashes, &same_work_other_job), Err(RejectReason::DuplicateWork));
}

#[test]
fn a_share_is_credited_once_across_connections() {
    let (mut first, s) = setup();
    let hashes = fresh_hashes();
    let second_policy = policy();
    let mut second = Verifier::new(&second_policy);
    record(&mut second, &split(), &[], NOW);

    assert!(claimed(&mut first, &hashes, &s).is_ok());
    assert_eq!(claimed(&mut second, &hashes, &s), Err(RejectReason::DuplicateWork));

    let mut alone = verifier();
    record(&mut alone, &split(), &[], NOW);
    assert!(claimed(&mut alone, &fresh_hashes(), &s).is_ok());
}

#[test]
fn accepted_share_hashes_remove_the_oldest_first() {
    let mut hashes = AcceptedShareHashes::new(2);
    assert!(hashes.insert([1; 32], NOW));
    assert!(hashes.insert([2; 32], NOW));
    assert!(!hashes.insert([1; 32], NOW));
    assert_eq!(hashes.len(), 2);
    assert!(hashes.insert([3; 32], NOW));
    assert_eq!(hashes.len(), 2);
    assert!(hashes.insert([1; 32], NOW));
    assert!(!hashes.insert([3; 32], NOW));
    let mut hashes = AcceptedShareHashes::new(0);
    assert!(hashes.insert([9; 32], NOW));
    assert!(!hashes.insert([9; 32], NOW));
}

#[test]
fn a_removed_hash_can_be_accepted_again() {
    let mut hashes = AcceptedShareHashes::new(4);
    assert!(hashes.insert([1; 32], NOW));
    assert!(hashes.insert([2; 32], NOW));
    assert!(!hashes.insert([1; 32], NOW));
    assert!(hashes.remove(&[1; 32]), "the hash was present");
    assert!(!hashes.remove(&[1; 32]), "and is gone now");
    assert_eq!(hashes.len(), 1);
    assert!(hashes.insert([1; 32], NOW), "a removed hash is accepted again when it is resent");
    assert!(!hashes.insert([2; 32], NOW), "the one that stayed is still a duplicate");
}

#[test]
fn a_rejected_share_is_not_recorded_as_seen() {
    let (mut v, mut s) = setup();
    let hashes = fresh_hashes();
    s.target_byte = 40;
    assert_eq!(claimed(&mut v, &hashes, &s), Err(RejectReason::HighHash));
    assert_eq!(claimed(&mut v, &hashes, &s), Err(RejectReason::HighHash));
    s.target_byte = 0;
    assert!(claimed(&mut v, &hashes, &s).is_ok());
}

/// `ACCEPTED_HASH_RETENTION_SECS` rests on the time check: a share whose header time is as far
/// ahead as that check allows, accepted at `NOW`, fails it on every resend once
/// `2 × NTIME_WINDOW_SECS` have passed, so forgetting its hash then credits nothing twice.
#[test]
fn no_resend_passes_the_time_check_once_its_hash_is_forgotten() {
    use crate::accounting::ACCEPTED_HASH_RETENTION_SECS;
    let (mut v, mut s) = setup();
    s.blake2b.time_on_wire = (NOW + NTIME_WINDOW_SECS) as u32;
    assert!(v.rebuild_checked_ignoring_target(&s, None, NOW).is_ok(), "accepted at NOW");
    for later in [NOW + 2 * NTIME_WINDOW_SECS + 1, NOW + ACCEPTED_HASH_RETENTION_SECS + 1] {
        assert_eq!(
            v.rebuild_checked_ignoring_target(&s, None, later),
            Err(RejectReason::BadNtime),
            "resent at NOW + {}",
            later - NOW
        );
    }
}
