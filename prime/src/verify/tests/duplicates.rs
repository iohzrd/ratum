//! Crediting each share once, across every connection and however its sections are resent.

use super::*;
use crate::accounting::{AcceptedShareHashes, claim};
use std::sync::Mutex;

fn fresh_hashes() -> Mutex<AcceptedShareHashes> {
    Mutex::new(AcceptedShareHashes::new(crate::ledger::MAX_SHARES))
}

/// `verify` followed by `claim`, as a connection runs them, with the refusal reduced to its
/// reason.
fn claimed(
    v: &mut Verifier,
    hashes: &Mutex<AcceptedShareHashes>,
    s: &PowSubmit,
) -> Result<RebuiltShare, RejectReason> {
    v.verify(s, None, NOW).and_then(|rebuilt| claim(hashes, rebuilt)).map_err(|r| r.reason)
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
    assert!(hashes.insert([1; 32]));
    assert!(hashes.insert([2; 32]));
    assert!(!hashes.insert([1; 32]));
    assert_eq!(hashes.len(), 2);
    assert!(hashes.insert([3; 32]));
    assert_eq!(hashes.len(), 2);
    assert!(hashes.insert([1; 32]));
    assert!(!hashes.insert([3; 32]));
    let mut hashes = AcceptedShareHashes::new(0);
    assert!(hashes.insert([9; 32]));
    assert!(!hashes.insert([9; 32]));
}

#[test]
fn a_removed_hash_can_be_accepted_again() {
    let mut hashes = AcceptedShareHashes::new(4);
    assert!(hashes.insert([1; 32]));
    assert!(hashes.insert([2; 32]));
    assert!(!hashes.insert([1; 32]));
    assert!(hashes.remove(&[1; 32]), "the hash was present");
    assert!(!hashes.remove(&[1; 32]), "and is gone now");
    assert_eq!(hashes.len(), 1);
    assert!(hashes.insert([1; 32]), "a removed hash is accepted again when it is resent");
    assert!(!hashes.insert([2; 32]), "the one that stayed is still a duplicate");
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
