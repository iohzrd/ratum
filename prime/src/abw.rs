use ratum::datum::abw::{self, AssignmentNotice, Candidate, Reveal, raw_hash_le, subcmd};
use ratum_prime::verify::AbwKeys;
use std::time::{Duration, Instant};

pub(crate) type SlotKeys = [Option<[u8; 16]>; abw::ASSIGNMENT_SLOTS as usize];

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
