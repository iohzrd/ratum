use ratum::datum::abw::{self, AssignmentNotice, Candidate, Reveal, SlotKeys, raw_hash_le, subcmd};
use ratum_prime::verify::AbwKeys;
use std::time::{Duration, Instant};

pub(crate) const ROTATE_AFTER_SHARES: u64 = 16384;
pub(crate) const ROTATE_AFTER: Duration = Duration::from_secs(600);
pub(crate) const DEFAULT_REVEAL_AFTER: Duration = Duration::from_secs(300);
pub(crate) const REVEAL_AFTER_SECS_RANGE: std::ops::RangeInclusive<u64> = 1..=600;
const MAX_TIP_ROTATIONS_PER_REVEAL: u32 = 4;

#[derive(Clone, Copy, Debug)]
struct Retired {
    slot: u8,
    at: Instant,
    sent: bool,
}

pub(crate) struct Revealed {
    pub(crate) slot: u8,
    pub(crate) again: bool,
    pub(crate) payload: Vec<u8>,
}

pub(crate) struct AbwManager {
    keys: SlotKeys,
    revealed: SlotKeys,
    active: u8,
    retired: Vec<Retired>,
    shares: u64,
    activated_at: Instant,
    reveal_after: Duration,
}

impl AbwManager {
    pub(crate) fn start(now: Instant, reveal_after: Duration) -> Self {
        let mut m = Self {
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

    pub(crate) fn keys(&self) -> AbwKeys {
        AbwKeys { seeded: self.keys, revealed: self.revealed }
    }

    fn seed(&mut self, slot: u8) {
        self.keys[slot as usize] = Some(abw::random_key());
        self.revealed[slot as usize] = None;
        self.active = slot;
    }

    fn notice(&self, slot: u8, active: bool) -> Vec<u8> {
        let key = self.keys[slot as usize].expect("a notice names a seeded slot");
        AssignmentNotice { active, slot, key_hash: abw::xor_key_hash(&key) }.encode()
    }

    pub(crate) fn notices(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(self.retired.len() + 1);
        for r in self.retired.iter().filter(|r| !r.sent) {
            out.push(self.notice(r.slot, false));
        }
        out.push(self.notice(self.active, true));
        out
    }

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

    pub(crate) fn next_due(&self) -> Instant {
        let rotation = self.activated_at + ROTATE_AFTER;
        self.retired
            .iter()
            .map(|r| r.at + self.reveal_after)
            .min()
            .map_or(rotation, |reveal| rotation.min(reveal))
    }

    pub(crate) fn reveal_due(&self, now: Instant) -> bool {
        self.retired.iter().any(|r| now.duration_since(r.at) >= self.reveal_after)
    }

    pub(crate) fn reveals_due(&mut self, now: Instant) -> Vec<Revealed> {
        let reveal_after = self.reveal_after;
        let due: Vec<Retired> =
            self.retired.extract_if(.., |r| now.duration_since(r.at) >= reveal_after).collect();
        due.into_iter().map(|r| self.reveal(r)).collect()
    }

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

    pub(crate) fn rotation_due(&self, now: Instant) -> Option<&'static str> {
        if self.shares >= ROTATE_AFTER_SHARES {
            Some("share count")
        } else if now.duration_since(self.activated_at) >= ROTATE_AFTER {
            Some("slot age")
        } else {
            None
        }
    }

    pub(crate) fn tip_rotation_allowed(&self, now: Instant) -> bool {
        now.duration_since(self.activated_at) >= self.reveal_after / MAX_TIP_ROTATIONS_PER_REVEAL
    }

    pub(crate) fn receipt(slot: u8, raw_hash2: [u8; 32]) -> Vec<u8> {
        Candidate { slot, raw_pow_hash: raw_hash_le(&raw_hash2) }.encode(subcmd::CANDIDATE_RECEIPT)
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
        assert_eq!(m.active, 0);
        let key = m.keys().seeded[0].expect("slot 0 seeded");
        let notice = Notice::decode(&m.notices()[0]).unwrap();
        assert_eq!(notice.key_hash, abw::xor_key_hash(&key));
        assert!(m.keys().seeded[1..].iter().all(Option::is_none));
        assert!(m.keys().revealed.iter().all(Option::is_none));
        assert!(m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>().is_empty());
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
        assert_eq!(m.active, 1);
        assert_eq!(m.keys().seeded[0], Some(key0), "the retired slot stays seeded");
        assert_eq!(decoded_notices(&m), [(0, false), (1, true)]);
        assert_eq!(m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(), [0]);
        assert!(m.reveals_due(now).is_empty());
        assert!(!m.reveal_due(now + AFTER - Duration::from_secs(1)));
        assert!(m.reveals_due(now + AFTER - Duration::from_secs(1)).is_empty(), "not yet due");
        assert!(m.reveal_due(now + AFTER));

        let reveals = m.reveals_due(now + AFTER);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)]);
        assert!(abw::key_matches_hash(&key0, &abw::xor_key_hash(&key0)));
        assert!(m.keys().seeded[0].is_none(), "a revealed slot is no longer seeded");
        assert_eq!(m.keys().revealed[0], Some(key0), "its key is kept for refused shares");
        assert!(m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>().is_empty());
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
        assert_eq!(m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(), [0, 1]);
        assert_eq!(m.keys().seeded.iter().filter(|k| k.is_some()).count(), 3);
        assert_eq!(decoded_notices(&m), [(0, false), (1, false), (2, true)]);

        let reveals = m.reveals_due(now + AFTER);
        assert_eq!(reveals.iter().map(|r| r.slot).collect::<Vec<_>>(), [0], "slot 1 is younger");
        assert_eq!(m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(), [1]);
        let reveals = m.reveals_due(later + AFTER);
        assert_eq!(reveals.iter().map(|r| r.slot).collect::<Vec<_>>(), [1]);
        assert!(m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>().is_empty());
    }

    #[test]
    fn a_slot_seeded_again_before_its_reveal_is_revealed_first() {
        let now = Instant::now();
        let mut m = AbwManager::start(now, AFTER);
        let key0 = m.keys().seeded[0].unwrap();
        for _ in 0..15 {
            m.rotate(now);
        }
        assert_eq!(m.active, 15);
        assert_eq!(
            m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(),
            (0..15).collect::<Vec<u8>>()
        );
        let (reveals, notice) = m.rotate(now);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)]);
        assert!(!reveals[0].again);
        assert_eq!(Notice::decode(&notice).unwrap().slot, 0);
        assert_eq!(m.active, 0);
        assert_ne!(m.keys().seeded[0], Some(key0), "seeded anew");
        assert!(m.keys().revealed[0].is_none(), "the old key is dropped with the new seed");
        assert_eq!(
            m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(),
            (1..=15).collect::<Vec<u8>>()
        );
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
        assert_eq!(m.active, 2);
        let t2 = t1 + Duration::from_secs(170);
        m.resumed(t2);
        assert_eq!(m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(), [1, 0]);
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
        assert!(m.retired.iter().map(|r| r.slot).collect::<Vec<u8>>().is_empty());
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
