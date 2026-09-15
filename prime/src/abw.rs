use crate::verify::AbwKeys;
use ratum::datum::messages::abw::{
    self, AssignmentNotice, Reveal, ShareRef, SlotKeys, raw_pow_hash_le, subcmd,
};
use ratum::header::xor_key_hash;
use std::time::{Duration, Instant};

pub const ROTATE_AFTER_SHARES: u64 = 16384;
pub const ROTATE_AFTER: Duration = Duration::from_secs(600);
pub const DEFAULT_REVEAL_AFTER: Duration = Duration::from_secs(300);
pub const REVEAL_AFTER_SECS_RANGE: std::ops::RangeInclusive<u64> = 1..=600;
const MAX_TIP_ROTATIONS_PER_REVEAL: u32 = 4;

#[derive(Clone, Copy, Debug)]
struct Retired {
    slot: u8,
    reveal_at: Instant,
    reveal_sent: bool,
    retired_on_open_connection: bool,
}

pub struct PendingReveal {
    pub slot: u8,
    pub resend: bool,
    pub payload: Vec<u8>,
}

pub struct Rotation {
    pub reveals: Vec<PendingReveal>,
    pub notice: Vec<u8>,
}

pub struct AbwSlotState {
    seeded: SlotKeys,
    revealed: SlotKeys,
    active: u8,
    retired: Vec<Retired>,
    shares_since_activation: u64,
    activated_at: Instant,
    reveal_after: Duration,
}

impl AbwSlotState {
    pub fn start(now: Instant, reveal_after: Duration) -> Self {
        let mut abw = Self {
            seeded: [None; abw::ASSIGNMENT_SLOTS as usize],
            revealed: [None; abw::ASSIGNMENT_SLOTS as usize],
            active: 0,
            retired: Vec::new(),
            shares_since_activation: 0,
            activated_at: now,
            reveal_after,
        };
        abw.seed(0);
        abw
    }

    pub fn keys(&self) -> AbwKeys {
        AbwKeys { seeded: self.seeded, revealed: self.revealed }
    }

    fn seed(&mut self, slot: u8) {
        self.seeded[slot as usize] = Some(abw::random_key());
        self.revealed[slot as usize] = None;
        self.active = slot;
    }

    fn notice(&self, slot: u8, active: bool) -> Vec<u8> {
        let key = self.seeded[slot as usize].expect("a notice names a seeded slot");
        AssignmentNotice { active, slot, key_hash: xor_key_hash(&key) }.encode()
    }

    pub fn notices(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(self.retired.len() + 1);
        for r in self.retired.iter().filter(|r| !r.reveal_sent) {
            out.push(self.notice(r.slot, false));
        }
        out.push(self.notice(self.active, true));
        out
    }

    pub fn resume(&mut self, closed_at: Instant) {
        for r in &mut self.retired {
            if r.retired_on_open_connection {
                r.reveal_at = closed_at + self.reveal_after;
                r.retired_on_open_connection = false;
            }
        }
        for slot in 0..abw::ASSIGNMENT_SLOTS {
            if self.revealed[slot as usize].is_some()
                && !self.retired.iter().any(|r| r.slot == slot)
            {
                self.retired.push(Retired {
                    slot,
                    reveal_at: closed_at,
                    reveal_sent: true,
                    retired_on_open_connection: false,
                });
            }
        }
    }

    fn reveal(&mut self, r: Retired) -> PendingReveal {
        let xor_key = if r.reveal_sent {
            self.revealed[r.slot as usize].expect("a sent reveal's key is kept")
        } else {
            let key = self.seeded[r.slot as usize].take().expect("a retired slot is seeded");
            self.revealed[r.slot as usize] = Some(key);
            key
        };
        PendingReveal {
            slot: r.slot,
            resend: r.reveal_sent,
            payload: Reveal { slot: r.slot, xor_key }.encode(),
        }
    }

    pub fn next_due(&self) -> Instant {
        let rotation = self.activated_at + ROTATE_AFTER;
        self.retired.iter().map(|r| r.reveal_at).min().map_or(rotation, |r| rotation.min(r))
    }

    pub fn reveal_due(&self, now: Instant) -> bool {
        self.retired.iter().any(|r| now >= r.reveal_at)
    }

    pub fn reveals_due(&mut self, now: Instant) -> Vec<PendingReveal> {
        let due: Vec<Retired> = self.retired.extract_if(.., |r| now >= r.reveal_at).collect();
        due.into_iter().map(|r| self.reveal(r)).collect()
    }

    pub fn rotate(&mut self, now: Instant) -> Rotation {
        let old = self.active;
        let next = (old + 1) % abw::ASSIGNMENT_SLOTS;
        let mut reveals = Vec::new();
        if let Some(pos) = self.retired.iter().position(|r| r.slot == next) {
            let r = self.retired.remove(pos);
            reveals.push(self.reveal(r));
        }
        self.retired.push(Retired {
            slot: old,
            reveal_at: now + self.reveal_after,
            reveal_sent: false,
            retired_on_open_connection: true,
        });
        self.seed(next);
        self.shares_since_activation = 0;
        self.activated_at = now;
        Rotation { reveals, notice: self.notice(next, true) }
    }

    pub fn note_share(&mut self) {
        self.shares_since_activation = self.shares_since_activation.saturating_add(1);
    }

    pub fn rotation_due(&self, now: Instant) -> Option<&'static str> {
        if self.shares_since_activation >= ROTATE_AFTER_SHARES {
            Some("share count")
        } else if now.duration_since(self.activated_at) >= ROTATE_AFTER {
            Some("slot age")
        } else {
            None
        }
    }

    pub fn tip_rotation_allowed(&self, now: Instant) -> bool {
        now.duration_since(self.activated_at) >= self.reveal_after / MAX_TIP_ROTATIONS_PER_REVEAL
    }

    pub fn receipt(slot: u8, raw_pow_hash: [u8; 32]) -> Vec<u8> {
        ShareRef { slot, raw_pow_hash_le: raw_pow_hash_le(&raw_pow_hash) }
            .encode_candidate(subcmd::CANDIDATE_RECEIPT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratum::datum::messages::abw::AssignmentNotice as Notice;

    const AFTER: Duration = Duration::from_secs(180);

    fn decoded_notices(abw: &AbwSlotState) -> Vec<(u8, bool)> {
        abw.notices()
            .iter()
            .map(|n| {
                let n = Notice::decode(n).unwrap();
                (n.slot, n.active)
            })
            .collect()
    }

    fn decoded_reveals(reveals: &[PendingReveal]) -> Vec<(u8, [u8; 16])> {
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
        let abw = AbwSlotState::start(Instant::now(), AFTER);
        assert_eq!(decoded_notices(&abw), [(0, true)]);
        assert_eq!(abw.active, 0);
        let key = abw.keys().seeded[0].expect("slot 0 seeded");
        let notice = Notice::decode(&abw.notices()[0]).unwrap();
        assert_eq!(notice.key_hash, xor_key_hash(&key));
        assert!(abw.keys().seeded[1..].iter().all(Option::is_none));
        assert!(abw.keys().revealed.iter().all(Option::is_none));
        assert!(abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>().is_empty());
    }

    #[test]
    fn a_rotation_retires_the_active_slot_and_its_reveal_follows_after_the_delay() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        let key0 = abw.keys().seeded[0].unwrap();

        let Rotation { reveals, notice } = abw.rotate(now);
        assert!(reveals.is_empty(), "slot 1 awaits no reveal");
        let n = Notice::decode(&notice).unwrap();
        assert!(n.active);
        assert_eq!(n.slot, 1);
        assert_eq!(abw.active, 1);
        assert_eq!(abw.keys().seeded[0], Some(key0), "the retired slot stays seeded");
        assert_eq!(decoded_notices(&abw), [(0, false), (1, true)]);
        assert_eq!(abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(), [0]);
        assert!(abw.reveals_due(now).is_empty());
        assert!(!abw.reveal_due(now + AFTER - Duration::from_secs(1)));
        assert!(abw.reveals_due(now + AFTER - Duration::from_secs(1)).is_empty(), "not yet due");
        assert!(abw.reveal_due(now + AFTER));

        let reveals = abw.reveals_due(now + AFTER);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)]);
        assert!(abw::key_matches_hash(&key0, &xor_key_hash(&key0)));
        assert!(abw.keys().seeded[0].is_none(), "a revealed slot is no longer seeded");
        assert_eq!(abw.keys().revealed[0], Some(key0), "its key is kept for refused shares");
        assert!(abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>().is_empty());
        assert_eq!(decoded_notices(&abw), [(1, true)]);
        assert!(abw.reveals_due(now + AFTER * 2).is_empty(), "revealed once");
    }

    #[test]
    fn two_rotations_within_the_delay_leave_two_slots_retired_until_each_is_due() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        abw.rotate(now);
        let later = now + Duration::from_secs(100);
        abw.rotate(later);
        assert_eq!(abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(), [0, 1]);
        assert_eq!(abw.keys().seeded.iter().filter(|k| k.is_some()).count(), 3);
        assert_eq!(decoded_notices(&abw), [(0, false), (1, false), (2, true)]);

        let reveals = abw.reveals_due(now + AFTER);
        assert_eq!(reveals.iter().map(|r| r.slot).collect::<Vec<_>>(), [0], "slot 1 is younger");
        assert_eq!(abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(), [1]);
        let reveals = abw.reveals_due(later + AFTER);
        assert_eq!(reveals.iter().map(|r| r.slot).collect::<Vec<_>>(), [1]);
        assert!(abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>().is_empty());
    }

    #[test]
    fn a_slot_seeded_again_before_its_reveal_is_revealed_first() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        let key0 = abw.keys().seeded[0].unwrap();
        for _ in 0..15 {
            abw.rotate(now);
        }
        assert_eq!(abw.active, 15);
        assert_eq!(
            abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(),
            (0..15).collect::<Vec<u8>>()
        );
        let Rotation { reveals, notice } = abw.rotate(now);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)]);
        assert!(!reveals[0].resend);
        assert_eq!(Notice::decode(&notice).unwrap().slot, 0);
        assert_eq!(abw.active, 0);
        assert_ne!(abw.keys().seeded[0], Some(key0), "seeded anew");
        assert!(abw.keys().revealed[0].is_none(), "the old key is dropped with the new seed");
        assert_eq!(
            abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(),
            (1..=15).collect::<Vec<u8>>()
        );
    }

    #[test]
    fn a_resume_keeps_each_reveal_time_and_resends_what_the_gateway_may_have_missed() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        let key0 = abw.keys().seeded[0].unwrap();
        abw.rotate(now);
        let key1 = abw.keys().seeded[1].unwrap();
        let t1 = now + AFTER;
        assert_eq!(abw.reveals_due(t1).len(), 1, "slot 0 revealed; the gateway may miss it");
        abw.rotate(t1);
        assert_eq!(abw.active, 2);
        let closed_at = t1 + Duration::from_secs(170);
        abw.resume(closed_at);
        assert_eq!(abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>(), [1, 0]);
        assert_eq!(decoded_notices(&abw), [(1, false), (2, true)], "seeded slots only");
        assert_eq!(abw.keys().seeded[1], Some(key1));
        assert_eq!(abw.keys().revealed[0], Some(key0));
        assert!(abw.keys().seeded[0].is_none());

        let reveals = abw.reveals_due(closed_at);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)], "a sent reveal is resent at once");
        assert!(reveals[0].resend);
        assert!(!abw.reveal_due(closed_at + AFTER - Duration::from_secs(1)));

        let reveals = abw.reveals_due(closed_at + AFTER);
        assert_eq!(decoded_reveals(&reveals), [(1, key1)], "slot 1 waits from the close");
        assert!(!reveals[0].resend);
        assert_eq!(abw.keys().revealed[0], Some(key0), "kept until the slot is seeded again");
        assert_eq!(abw.keys().revealed[1], Some(key1));
        assert!(abw.retired.iter().map(|r| r.slot).collect::<Vec<u8>>().is_empty());
        assert_eq!(abw.rotation_due(t1 + ROTATE_AFTER - Duration::from_secs(1)), None);
        assert_eq!(
            abw.rotation_due(t1 + ROTATE_AFTER),
            Some("slot age"),
            "a resume does not restart the slot age"
        );
    }

    #[test]
    fn resuming_again_and_again_does_not_postpone_a_reveal() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        abw.rotate(now);
        let first_close = now + Duration::from_secs(30);
        let mut closed_at = first_close;
        for _ in 0..10 {
            abw.resume(closed_at);
            closed_at += Duration::from_secs(60);
        }
        assert!(!abw.reveal_due(first_close + AFTER - Duration::from_secs(1)));
        assert!(abw.reveal_due(first_close + AFTER), "the delay runs from the first close");
        let reveals = abw.reveals_due(first_close + AFTER);
        assert_eq!(reveals.iter().map(|r| r.slot).collect::<Vec<u8>>(), [0]);
    }

    #[test]
    fn a_rotation_is_due_by_share_count_or_slot_age() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        assert_eq!(abw.rotation_due(now), None);
        for _ in 0..ROTATE_AFTER_SHARES - 1 {
            abw.note_share();
        }
        assert_eq!(abw.rotation_due(now), None);
        abw.note_share();
        assert_eq!(abw.rotation_due(now), Some("share count"));
        abw.rotate(now);
        assert_eq!(abw.rotation_due(now), None, "a rotation resets the count");
        assert_eq!(abw.rotation_due(now + ROTATE_AFTER), Some("slot age"));
        abw.rotate(now + ROTATE_AFTER);
        assert_eq!(abw.rotation_due(now + ROTATE_AFTER), None);
    }

    #[test]
    fn a_tip_rotates_the_assignment_only_once_the_active_slot_is_old_enough() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        assert!(!abw.tip_rotation_allowed(now));
        assert!(!abw.tip_rotation_allowed(now + AFTER / 4 - Duration::from_secs(1)));
        assert!(abw.tip_rotation_allowed(now + AFTER / 4));
        abw.rotate(now + AFTER / 4);
        assert!(!abw.tip_rotation_allowed(now + AFTER / 4), "a rotation resets the age");
        assert!(abw.tip_rotation_allowed(now + AFTER / 2));
    }

    #[test]
    fn a_receipt_names_the_slot_and_the_reversed_hash() {
        let raw_pow_hash: [u8; 32] = std::array::from_fn(|i| i as u8);
        let c = ShareRef::decode_candidate(
            &AbwSlotState::receipt(3, raw_pow_hash),
            subcmd::CANDIDATE_RECEIPT,
        )
        .unwrap();
        assert_eq!(c.slot, 3);
        assert_eq!(c.raw_pow_hash_le, raw_pow_hash_le(&raw_pow_hash));
        assert_eq!(c.raw_pow_hash_le[0], 31);
    }
}
