//! The pool side of anti-block-withholding for one version 3 connection.
//!
//! The pool chooses a 16-byte XOR key per assignment slot, sends the gateway only its
//! commitment (0xA8), and installs the key into the connection's verifier so every rebuilt
//! header carries it. The gateway commits its headers to the hash and cannot distinguish a
//! block from a share, so the pool classifies and relays blocks, sends an 0xA5 receipt for
//! each, and reveals the key (0xA9) once no share on the slot can still arrive; the gateway
//! then audits the proofs it retained. This type holds the slot keys and builds the
//! payloads; the connection sends them and mirrors the keys into its verifier.
//!
//! The reveal's timing is the constraint the rest follows. The C gateway audits every proof
//! it retained on a slot the moment it processes the slot's reveal, and a proof that is a
//! block by its own `nbits` without an 0xA5 receipt sets its permanent CRITICAL failure and
//! closes the connection. A share the gateway sent before it processed the reveal, and the
//! pool read after it sent the reveal, cannot get its receipt in time. So a retired slot is
//! revealed only once it has been retired for `reveal_after`, longer than the gateway keeps
//! submitting shares on the slot's jobs: its stale-share rule accepts a share until
//! `share_stale_seconds + work_update_seconds` (160 s by default, 270 s at most) after the
//! job was made, and the slot's last job is made before the gateway processes the
//! rotation's notice (on a tip rotation, the jobs its node's new tip prompted moments
//! earlier). The default delay covers the largest window. The connection also holds a due
//! reveal until every share it received before it is answered
//! (`Connection::send_due_reveals`), so a receipt never follows the reveal it belongs before.

use ratum::datum::abw::{self, AssignmentNotice, Candidate, Reveal, raw_hash_le, subcmd};
use ratum_prime::verify::AbwKeys;
use std::time::{Duration, Instant};

/// The slot keys, indexed by wire slot 0..15. `None` is an unseeded (or revealed) slot.
pub(crate) type SlotKeys = [Option<[u8; 16]>; abw::ASSIGNMENT_SLOTS as usize];

/// Rotate after this many shares on the active slot. The C gateway retains one proof per
/// submitted share until the slot's reveal, in a cache of 65536 entries
/// (`DATUM_ABW_PENDING_CACHE`) shared by every unrevealed slot, and a full cache refuses the
/// share. The unrevealed slots are the active one and those retired within `reveal_after`,
/// so at the default delay the cache holds the proofs of a gateway sending up to about 160
/// shares per second in steady state: 16384 on the active slot plus 300 s of shares on
/// retired ones (a resumed session restamps its retired slots, so their proofs are held up
/// to twice as long).
pub(crate) const ROTATE_AFTER_SHARES: u64 = 16384;
/// Rotate once the active slot is this old. The C gateway's template cache
/// (`DATUM_ABW_TEMPLATE_CACHE`, 256 entries) holds one entry per template a retained proof
/// was built on, freed at the reveal, and a template is fetched every
/// `bitcoind_work_update_seconds` (5 at the least) and on each tip and notification: the
/// unrevealed slots span at most 600 s plus `reveal_after` of fetches, 180 periodic ones at
/// the default delay and 240 at the longest.
pub(crate) const ROTATE_AFTER: Duration = Duration::from_secs(600);
/// The default `--abw-reveal-after`: how long after its retirement a slot's key is revealed.
/// Above the C gateway's largest stale window (270 s), so a gateway at any legal
/// `share_stale_seconds` and `work_update_seconds` has stopped submitting on the slot.
pub(crate) const DEFAULT_REVEAL_AFTER: Duration = Duration::from_secs(300);

/// A slot the pool retired and has not revealed since.
#[derive(Clone, Copy, Debug)]
struct Retired {
    slot: u8,
    /// When the slot was retired, or when the session was resumed, whichever is later.
    at: Instant,
    /// The key was already sent in a reveal the gateway may not have received (the
    /// connection closed after it). It is in `revealed`, not `keys`, and the reveal is sent
    /// again `reveal_after` after the resume, once the gateway's replayed shares are
    /// answered.
    sent: bool,
}

/// One 0xA9 reveal to send.
pub(crate) struct Revealed {
    pub(crate) slot: u8,
    /// The reveal was sent before, on a connection that closed after it; see `Retired::sent`.
    pub(crate) again: bool,
    pub(crate) payload: Vec<u8>,
}

pub(crate) struct AbwManager {
    /// The seeded slots: the active one and the retired ones awaiting their reveal.
    keys: SlotKeys,
    /// The revealed slots' keys, kept until the slot is seeded again: the verifier rebuilds
    /// a share on such a slot for its exact reference and receipt without crediting it, and
    /// a resumed session sends the reveal again.
    revealed: SlotKeys,
    active: u8,
    /// The retired slots in retirement order.
    retired: Vec<Retired>,
    /// Shares received since the active slot was activated.
    shares: u64,
    activated_at: Instant,
    reveal_after: Duration,
}

impl AbwManager {
    /// Seed slot 0 as the active assignment.
    pub(crate) fn start(now: Instant, reveal_after: Duration) -> Self {
        let mut m = AbwManager {
            keys: [None; abw::ASSIGNMENT_SLOTS as usize],
            revealed: [None; abw::ASSIGNMENT_SLOTS as usize],
            active: 0,
            retired: Vec::new(),
            shares: 0,
            activated_at: now,
            reveal_after,
        };
        m.seed(0);
        m
    }

    /// The seeded and the revealed slots' keys, to mirror into the verifier.
    pub(crate) fn keys(&self) -> AbwKeys {
        AbwKeys { seeded: self.keys, revealed: self.revealed }
    }

    /// Store a random key in `slot` and make it the active assignment.
    fn seed(&mut self, slot: u8) {
        self.keys[slot as usize] = Some(abw::random_key());
        self.revealed[slot as usize] = None;
        self.active = slot;
    }

    fn notice(&self, slot: u8, active: bool) -> Vec<u8> {
        let key = self.keys[slot as usize].expect("a notice names a seeded slot");
        AssignmentNotice { active, slot, key_hash: abw::xor_key_hash(&key) }.encode()
    }

    /// The 0xA8 notices for every seeded slot, the active one last. A new session is sent
    /// them once; a resumed session is sent them again, since the C gateway clears its active
    /// slot on reconnect and accepts a repeated notice whose hash matches the one it holds.
    pub(crate) fn notices(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(self.retired.len() + 1);
        for r in self.retired.iter().filter(|r| !r.sent) {
            out.push(self.notice(r.slot, false));
        }
        out.push(self.notice(self.active, true));
        out
    }

    /// Continue the session on a resumed connection. Every retired slot counts as retired
    /// now, so the gateway's replayed shares are answered before any reveal, and every
    /// revealed slot's reveal is sent again after the delay, since the gateway may not have
    /// received it (the C gateway refuses to seed a slot again while it holds it unrevealed).
    pub(crate) fn resumed(&mut self, now: Instant) {
        for r in &mut self.retired {
            r.at = now;
        }
        for slot in 0..abw::ASSIGNMENT_SLOTS {
            if self.revealed[slot as usize].is_some()
                && !self.retired.iter().any(|r| r.slot == slot)
            {
                self.retired.push(Retired { slot, at: now, sent: true });
            }
        }
        self.activated_at = now;
    }

    /// The reveal of `r`. On its first reveal the key leaves the seeded slots for the
    /// revealed ones.
    fn reveal(&mut self, r: Retired) -> Revealed {
        let xor_key = if r.sent {
            self.revealed[r.slot as usize].expect("a sent reveal's key is kept")
        } else {
            let key = self.keys[r.slot as usize].take().expect("a retired slot is seeded");
            self.revealed[r.slot as usize] = Some(key);
            key
        };
        Revealed { slot: r.slot, again: r.sent, payload: Reveal { slot: r.slot, xor_key }.encode() }
    }

    /// Whether `reveals_due` would reveal a slot now.
    pub(crate) fn reveal_due(&self, now: Instant) -> bool {
        self.retired.iter().any(|r| now.duration_since(r.at) >= self.reveal_after)
    }

    /// The 0xA9 reveals of the slots retired for `reveal_after` or longer; they leave the
    /// retired slots.
    pub(crate) fn reveals_due(&mut self, now: Instant) -> Vec<Revealed> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.retired.len() {
            if now.duration_since(self.retired[i].at) >= self.reveal_after {
                let r = self.retired.remove(i);
                out.push(self.reveal(r));
            } else {
                i += 1;
            }
        }
        out
    }

    /// Seed and activate the next slot and retire the active one. Returns the reveal of the
    /// next slot, when it still awaits one, then the notice: the C gateway refuses to seed a
    /// slot again while it holds it unrevealed. The rotation reaches a slot again only after
    /// 15 others, so that reveal comes early only under a share rate the gateway's own caches
    /// do not sustain.
    pub(crate) fn rotate(&mut self, now: Instant) -> (Vec<Revealed>, Vec<u8>) {
        let old = self.active;
        let next = (old + 1) % abw::ASSIGNMENT_SLOTS;
        let mut reveals = Vec::new();
        if let Some(pos) = self.retired.iter().position(|r| r.slot == next) {
            let r = self.retired.remove(pos);
            reveals.push(self.reveal(r));
        }
        self.retired.push(Retired { slot: old, at: now, sent: false });
        self.seed(next);
        self.shares = 0;
        self.activated_at = now;
        (reveals, self.notice(next, true))
    }

    pub(crate) fn note_share(&mut self) {
        self.shares = self.shares.saturating_add(1);
    }

    /// Why a rotation is due, if one is: the share count or the age of the active slot.
    pub(crate) fn rotation_due(&self, now: Instant) -> Option<&'static str> {
        if self.shares >= ROTATE_AFTER_SHARES {
            Some("share count")
        } else if now.duration_since(self.activated_at) >= ROTATE_AFTER {
            Some("slot age")
        } else {
            None
        }
    }

    /// Whether a new tip rotates the assignment: only once the active slot is a quarter of
    /// `reveal_after` old, so a run of tips in quick succession (two blocks seconds apart,
    /// a testnet burst) retires at most four slots per `reveal_after` and the rotation does
    /// not reach a slot again before its reveal. A tip that does not rotate costs nothing:
    /// the gateway's jobs on the slot are stale on the new tip either way.
    pub(crate) fn tip_rotation_allowed(&self, now: Instant) -> bool {
        now.duration_since(self.activated_at) >= self.reveal_after / 4
    }

    /// The 0xA5 receipt for a block the pool handled, so the gateway's reveal audit counts
    /// it. `raw_hash2` is the unmasked hash in the BLAKE2b output order; the gateway retains
    /// proofs in the reversed order.
    pub(crate) fn receipt(slot: u8, raw_hash2: [u8; 32]) -> Vec<u8> {
        Candidate { slot, raw_pow_hash: raw_hash_le(&raw_hash2) }.encode(subcmd::CANDIDATE_RECEIPT)
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> u8 {
        self.active
    }

    #[cfg(test)]
    pub(crate) fn retired_slots(&self) -> Vec<u8> {
        self.retired.iter().map(|r| r.slot).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratum::datum::abw::AssignmentNotice as Notice;

    const AFTER: Duration = Duration::from_secs(180);

    fn decoded_notices(m: &AbwManager) -> Vec<(u8, bool)> {
        m.notices()
            .iter()
            .map(|n| {
                let n = Notice::decode(n).unwrap();
                (n.slot, n.active)
            })
            .collect()
    }

    fn decoded_reveals(reveals: &[Revealed]) -> Vec<(u8, [u8; 16])> {
        reveals
            .iter()
            .map(|r| {
                let decoded = Reveal::decode(&r.payload).unwrap();
                assert_eq!(decoded.slot, r.slot);
                (decoded.slot, decoded.xor_key)
            })
            .collect()
    }

    #[test]
    fn start_seeds_an_active_slot_zero() {
        let m = AbwManager::start(Instant::now(), AFTER);
        assert_eq!(decoded_notices(&m), [(0, true)]);
        assert_eq!(m.active(), 0);
        let key = m.keys().seeded[0].expect("slot 0 seeded");
        let notice = Notice::decode(&m.notices()[0]).unwrap();
        assert_eq!(notice.key_hash, abw::xor_key_hash(&key));
        assert!(m.keys().seeded[1..].iter().all(Option::is_none));
        assert!(m.keys().revealed.iter().all(Option::is_none));
        assert!(m.retired_slots().is_empty());
    }

    #[test]
    fn a_rotation_retires_the_active_slot_and_its_reveal_follows_after_the_delay() {
        let now = Instant::now();
        let mut m = AbwManager::start(now, AFTER);
        let key0 = m.keys().seeded[0].unwrap();

        let (reveals, notice) = m.rotate(now);
        assert!(reveals.is_empty(), "slot 1 awaits no reveal");
        let n = Notice::decode(&notice).unwrap();
        assert!(n.active);
        assert_eq!(n.slot, 1);
        assert_eq!(m.active(), 1);
        assert_eq!(m.keys().seeded[0], Some(key0), "the retired slot stays seeded");
        assert_eq!(decoded_notices(&m), [(0, false), (1, true)]);
        assert_eq!(m.retired_slots(), [0]);
        assert!(m.reveals_due(now).is_empty());
        assert!(!m.reveal_due(now + AFTER - Duration::from_secs(1)));
        assert!(m.reveals_due(now + AFTER - Duration::from_secs(1)).is_empty(), "not yet due");
        assert!(m.reveal_due(now + AFTER));

        let reveals = m.reveals_due(now + AFTER);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)]);
        assert!(abw::key_matches_hash(&key0, &abw::xor_key_hash(&key0)));
        assert!(m.keys().seeded[0].is_none(), "a revealed slot is no longer seeded");
        assert_eq!(m.keys().revealed[0], Some(key0), "its key is kept for refused shares");
        assert!(m.retired_slots().is_empty());
        assert_eq!(decoded_notices(&m), [(1, true)]);
        assert!(m.reveals_due(now + AFTER * 2).is_empty(), "revealed once");
    }

    #[test]
    fn two_rotations_within_the_delay_leave_two_slots_retired_until_each_is_due() {
        let now = Instant::now();
        let mut m = AbwManager::start(now, AFTER);
        m.rotate(now);
        let later = now + Duration::from_secs(100);
        m.rotate(later);
        assert_eq!(m.retired_slots(), [0, 1]);
        assert_eq!(m.keys().seeded.iter().filter(|k| k.is_some()).count(), 3);
        assert_eq!(decoded_notices(&m), [(0, false), (1, false), (2, true)]);

        let reveals = m.reveals_due(now + AFTER);
        assert_eq!(reveals.iter().map(|r| r.slot).collect::<Vec<_>>(), [0], "slot 1 is younger");
        assert_eq!(m.retired_slots(), [1]);
        let reveals = m.reveals_due(later + AFTER);
        assert_eq!(reveals.iter().map(|r| r.slot).collect::<Vec<_>>(), [1]);
        assert!(m.retired_slots().is_empty());
    }

    #[test]
    fn a_slot_seeded_again_before_its_reveal_is_revealed_first() {
        let now = Instant::now();
        let mut m = AbwManager::start(now, AFTER);
        let key0 = m.keys().seeded[0].unwrap();
        for _ in 0..15 {
            m.rotate(now);
        }
        assert_eq!(m.active(), 15);
        assert_eq!(m.retired_slots(), (0..15).collect::<Vec<u8>>());
        // The 16th rotation seeds slot 0 again: its old key is revealed first.
        let (reveals, notice) = m.rotate(now);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)]);
        assert!(!reveals[0].again);
        assert_eq!(Notice::decode(&notice).unwrap().slot, 0);
        assert_eq!(m.active(), 0);
        assert_ne!(m.keys().seeded[0], Some(key0), "seeded anew");
        assert!(m.keys().revealed[0].is_none(), "the old key is dropped with the new seed");
        assert_eq!(m.retired_slots(), (1..=15).collect::<Vec<u8>>());
    }

    #[test]
    fn a_resume_answers_replays_before_any_reveal_and_sends_the_reveals_again() {
        let now = Instant::now();
        let mut m = AbwManager::start(now, AFTER);
        let key0 = m.keys().seeded[0].unwrap();
        m.rotate(now);
        let key1 = m.keys().seeded[1].unwrap();
        let t1 = now + AFTER;
        assert_eq!(m.reveals_due(t1).len(), 1, "slot 0 revealed; the gateway may miss it");
        m.rotate(t1);
        assert_eq!(m.active(), 2);
        // Resumed 170 s later: slot 1 would have been due in 10 s.
        let t2 = t1 + Duration::from_secs(170);
        m.resumed(t2);
        assert_eq!(m.retired_slots(), [1, 0]);
        assert!(m.reveals_due(t2 + Duration::from_secs(10)).is_empty(), "retired anew");
        assert_eq!(decoded_notices(&m), [(1, false), (2, true)], "seeded slots only");
        assert_eq!(m.keys().seeded[1], Some(key1));
        assert_eq!(m.keys().revealed[0], Some(key0));
        assert!(m.keys().seeded[0].is_none());

        let reveals = m.reveals_due(t2 + AFTER);
        assert_eq!(decoded_reveals(&reveals), [(1, key1), (0, key0)]);
        assert_eq!(reveals.iter().map(|r| r.again).collect::<Vec<_>>(), [false, true]);
        assert_eq!(m.keys().revealed[0], Some(key0), "kept until the slot is seeded again");
        assert_eq!(m.keys().revealed[1], Some(key1));
        assert!(m.retired_slots().is_empty());
        // The age rotation counts from the resume.
        assert_eq!(m.rotation_due(t2 + ROTATE_AFTER - Duration::from_secs(1)), None);
        assert_eq!(m.rotation_due(t2 + ROTATE_AFTER), Some("slot age"));
    }

    #[test]
    fn a_rotation_is_due_by_share_count_or_slot_age() {
        let now = Instant::now();
        let mut m = AbwManager::start(now, AFTER);
        assert_eq!(m.rotation_due(now), None);
        for _ in 0..ROTATE_AFTER_SHARES - 1 {
            m.note_share();
        }
        assert_eq!(m.rotation_due(now), None);
        m.note_share();
        assert_eq!(m.rotation_due(now), Some("share count"));
        m.rotate(now);
        assert_eq!(m.rotation_due(now), None, "a rotation resets the count");
        assert_eq!(m.rotation_due(now + ROTATE_AFTER), Some("slot age"));
        m.rotate(now + ROTATE_AFTER);
        assert_eq!(m.rotation_due(now + ROTATE_AFTER), None);
    }

    #[test]
    fn a_tip_rotates_the_assignment_only_once_the_active_slot_is_old_enough() {
        let now = Instant::now();
        let mut m = AbwManager::start(now, AFTER);
        assert!(!m.tip_rotation_allowed(now));
        assert!(!m.tip_rotation_allowed(now + AFTER / 4 - Duration::from_secs(1)));
        assert!(m.tip_rotation_allowed(now + AFTER / 4));
        m.rotate(now + AFTER / 4);
        assert!(!m.tip_rotation_allowed(now + AFTER / 4), "a rotation resets the age");
        assert!(m.tip_rotation_allowed(now + AFTER / 2));
    }

    #[test]
    fn a_receipt_names_the_slot_and_the_reversed_hash() {
        let hash2: [u8; 32] = std::array::from_fn(|i| i as u8);
        let c =
            Candidate::decode(&AbwManager::receipt(3, hash2), subcmd::CANDIDATE_RECEIPT).unwrap();
        assert_eq!(c.slot, 3);
        assert_eq!(c.raw_pow_hash, raw_hash_le(&hash2));
        assert_eq!(c.raw_pow_hash[0], 31);
    }
}
