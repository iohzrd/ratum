//! The anti-block-withholding slots of one session. The pool mines every gateway under a secret XOR
//! key it commits to by hash, rotates to a new slot on a tip, a share count or an age, and
//! discloses a retired slot's key after a delay. A gateway holding work cannot tell a block from a
//! share, and can check afterwards that every block it found was acknowledged.

use ratum::datum::messages::abw::{self, AssignmentNotice, Reveal};
use ratum::header::{XorKey, xor_key_hash};
use std::time::{Duration, Instant};

pub const ROTATE_AFTER_SHARES: u64 = 16384;
pub const ROTATE_AFTER: Duration = Duration::from_secs(600);
pub const DEFAULT_REVEAL_AFTER: Duration = Duration::from_secs(300);
pub const REVEAL_AFTER_SECS_RANGE: std::ops::RangeInclusive<u64> = 1..=600;
const MAX_TIP_ROTATIONS_PER_REVEAL: u32 = 4;
/// How long after a connection opens its rotations and reveals wait, so the shares a resumed
/// gateway replays are answered first.
pub const REPLAY_GRACE: Duration = Duration::from_secs(10);

const SLOTS: usize = abw::ASSIGNMENT_SLOTS as usize;

/// Whether a slot's key is still the pool's secret or has been disclosed to the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKeyStatus {
    Secret,
    Revealed,
}

/// One assignment slot through its life: seeded with a secret key (the active slot, or one
/// a resumed session still holds), retired with the reveal of its key pending, and revealed
/// with the key kept so refused shares on it are still rebuilt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Empty,
    Seeded {
        key: XorKey,
    },
    Retired {
        key: XorKey,
        reveal_at: Instant,
        /// Retired while the gateway was connected, so a resume restarts the reveal delay
        /// from the close instead of the rotation.
        retired_on_open_connection: bool,
    },
    Revealed {
        key: XorKey,
        /// Set on a resume: the reveal sent on the closed connection is sent again at once.
        resend_at: Option<Instant>,
    },
}

impl Slot {
    fn secret_key(&self) -> Option<XorKey> {
        match self {
            Self::Seeded { key } | Self::Retired { key, .. } => Some(*key),
            Self::Empty | Self::Revealed { .. } => None,
        }
    }

    fn due_at(&self) -> Option<Instant> {
        match self {
            Self::Retired { reveal_at, .. } => Some(*reveal_at),
            Self::Revealed { resend_at, .. } => *resend_at,
            Self::Empty | Self::Seeded { .. } => None,
        }
    }
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
    slots: [Slot; SLOTS],
    active: u8,
    shares_since_activation: u64,
    activated_at: Instant,
    reveal_after: Duration,
    /// Rotations and reveals are not due before this instant (see `connect`).
    held_until: Instant,
    /// A new tip asked for a rotation that the hold has not yet let through.
    tip_rotation_pending: bool,
    /// The slots whose key a relayed block's header published.
    published: [bool; SLOTS],
}

impl AbwSlotState {
    pub fn start(now: Instant, reveal_after: Duration) -> Self {
        let mut abw = Self {
            slots: [Slot::Empty; SLOTS],
            active: 0,
            shares_since_activation: 0,
            activated_at: now,
            reveal_after,
            held_until: now,
            tip_rotation_pending: false,
            published: [false; SLOTS],
        };
        abw.seed(0);
        abw
    }

    /// A state holding the given keys: `seeded` slots as secret, `revealed` slots as
    /// disclosed, slot 0 active.
    #[cfg(test)]
    pub fn with_keys(seeded: [Option<XorKey>; SLOTS], revealed: [Option<XorKey>; SLOTS]) -> Self {
        let mut abw = Self::start(Instant::now(), DEFAULT_REVEAL_AFTER);
        for (slot, (seeded, revealed)) in abw.slots.iter_mut().zip(seeded.iter().zip(&revealed)) {
            *slot = match (seeded, revealed) {
                (Some(key), _) => Slot::Seeded { key: *key },
                (None, Some(key)) => Slot::Revealed { key: *key, resend_at: None },
                (None, None) => Slot::Empty,
            };
        }
        abw
    }

    /// The key a share on `slot` is verified with, and whether it is still secret; none
    /// for a slot that was never seeded or that is out of range. A published key is revealed.
    pub fn key_for(&self, slot: u8) -> Option<(XorKey, SlotKeyStatus)> {
        let entry = self.slots.get(usize::from(slot))?;
        let published = self.published[usize::from(slot)];
        match entry {
            Slot::Seeded { key } | Slot::Retired { key, .. } if !published => {
                Some((*key, SlotKeyStatus::Secret))
            }
            Slot::Seeded { key } | Slot::Retired { key, .. } | Slot::Revealed { key, .. } => {
                Some((*key, SlotKeyStatus::Revealed))
            }
            Slot::Empty => None,
        }
    }

    /// Marks `slot`'s key public (a relayed block's header carries it); an active slot rotates at
    /// once. Returns whether it was active; none if its key was not secret.
    pub fn note_published(&mut self, slot: u8) -> Option<bool> {
        let at = usize::from(slot);
        self.slots.get(at)?.secret_key()?;
        if std::mem::replace(&mut self.published[at], true) {
            return None;
        }
        Some(slot == self.active)
    }

    fn active_published(&self) -> bool {
        self.published[usize::from(self.active)]
    }

    fn seed(&mut self, slot: u8) {
        self.slots[usize::from(slot)] = Slot::Seeded { key: ratum::rand::bytes() };
        self.published[usize::from(slot)] = false;
        self.active = slot;
    }

    fn notice(&self, slot: u8, active: bool) -> Option<Vec<u8>> {
        let key = self.slots[usize::from(slot)].secret_key()?;
        Some(AssignmentNotice { active, slot, key_hash: xor_key_hash(&key) }.encode())
    }

    /// The notices a connection opens with: every retired slot whose reveal is still
    /// pending, then the active slot.
    pub fn notices(&self) -> Vec<Vec<u8>> {
        let retired = (0..abw::ASSIGNMENT_SLOTS)
            .filter(|&slot| matches!(self.slots[usize::from(slot)], Slot::Retired { .. }))
            .filter_map(|slot| self.notice(slot, false));
        retired.chain(self.notice(self.active, true)).collect()
    }

    /// Holds rotations and reveals for `REPLAY_GRACE` from `opened_at`, the time the
    /// connection now carrying the session was accepted.
    pub fn connect(&mut self, opened_at: Instant) {
        self.held_until = opened_at + REPLAY_GRACE;
    }

    fn held(&self, now: Instant) -> bool {
        now < self.held_until
    }

    pub fn resume(&mut self, closed_at: Instant) {
        for slot in &mut self.slots {
            match slot {
                Slot::Retired { reveal_at, retired_on_open_connection: on_open @ true, .. } => {
                    *reveal_at = closed_at + self.reveal_after;
                    *on_open = false;
                }
                Slot::Revealed { resend_at: resend_at @ None, .. } => *resend_at = Some(closed_at),
                _ => {}
            }
        }
    }

    /// Sends the slot's key: the reveal of a retired slot, or the reveal of a revealed slot
    /// again where a resume asked for it.
    fn reveal(&mut self, slot: u8) -> Option<PendingReveal> {
        let entry = &mut self.slots[usize::from(slot)];
        let (key, resend) = match *entry {
            Slot::Retired { key, .. } => {
                *entry = Slot::Revealed { key, resend_at: None };
                (key, false)
            }
            Slot::Revealed { key, resend_at: Some(_) } => {
                *entry = Slot::Revealed { key, resend_at: None };
                (key, true)
            }
            Slot::Empty | Slot::Seeded { .. } | Slot::Revealed { resend_at: None, .. } => {
                return None;
            }
        };
        Some(PendingReveal { slot, resend, payload: Reveal { slot, xor_key: key }.encode() })
    }

    /// The slot a rotation activates next.
    fn next_slot(&self) -> u8 {
        (self.active + 1) % abw::ASSIGNMENT_SLOTS
    }

    /// When the slot a rotation activates next is still retired, the instant its key is
    /// revealed: the rotation waits for it, since seeding the slot again before then would
    /// disclose its key before the delay the gateway relies on.
    fn next_slot_reveal_at(&self) -> Option<Instant> {
        match self.slots[usize::from(self.next_slot())] {
            Slot::Retired { reveal_at, .. } => Some(reveal_at),
            _ => None,
        }
    }

    /// The earliest instant a rotation or a reveal can be due, never before the hold ends.
    pub fn next_due(&self) -> Instant {
        let rotation = if self.tip_rotation_pending || self.active_published() {
            self.held_until
        } else {
            self.activated_at + ROTATE_AFTER
        };
        let rotation = self.next_slot_reveal_at().map_or(rotation, |at| rotation.max(at));
        let due =
            self.slots.iter().filter_map(Slot::due_at).min().map_or(rotation, |r| rotation.min(r));
        due.max(self.held_until)
    }

    pub fn reveal_due(&self, now: Instant) -> bool {
        !self.held(now) && self.slots.iter().filter_map(Slot::due_at).any(|at| now >= at)
    }

    pub fn reveals_due(&mut self, now: Instant) -> Vec<PendingReveal> {
        if self.held(now) {
            return Vec::new();
        }
        let due: Vec<u8> = (0..abw::ASSIGNMENT_SLOTS)
            .filter(|&slot| self.slots[usize::from(slot)].due_at().is_some_and(|at| now >= at))
            .collect();
        due.into_iter().filter_map(|slot| self.reveal(slot)).collect()
    }

    /// Retires the active slot and activates the next. `rotation_due` asks for no rotation
    /// while the next slot's reveal is pending; a rotation made then reveals it first.
    pub fn rotate(&mut self, now: Instant) -> Rotation {
        let old = self.active;
        let next = self.next_slot();
        let reveals: Vec<PendingReveal> = self.reveal(next).into_iter().collect();
        if let Slot::Seeded { key } = self.slots[usize::from(old)] {
            self.slots[usize::from(old)] = Slot::Retired {
                key,
                reveal_at: now + self.reveal_after,
                retired_on_open_connection: true,
            };
        }
        self.seed(next);
        self.shares_since_activation = 0;
        self.activated_at = now;
        self.tip_rotation_pending = false;
        let notice = self.notice(next, true).expect("the slot was seeded above");
        Rotation { reveals, notice }
    }

    pub fn note_share(&mut self) {
        self.shares_since_activation = self.shares_since_activation.saturating_add(1);
    }

    /// Why a rotation is due, if one is: never during the hold, and never while the next
    /// slot's reveal is pending (the rotation then waits for the reveal).
    pub fn rotation_due(&self, now: Instant) -> Option<&'static str> {
        if self.held(now) || self.next_slot_reveal_at().is_some() {
            None
        } else if self.active_published() {
            Some("a relayed block published its key")
        } else if self.tip_rotation_pending {
            Some("new tip")
        } else if self.shares_since_activation >= ROTATE_AFTER_SHARES {
            Some("share count")
        } else if now.duration_since(self.activated_at) >= ROTATE_AFTER {
            Some("slot age")
        } else {
            None
        }
    }

    /// Records a new tip: a rotation becomes due, once the hold ends, when the active slot is
    /// at least a quarter of the reveal delay old. Returns whether it was.
    pub fn note_tip(&mut self, now: Instant) -> bool {
        let old_enough = now.duration_since(self.activated_at)
            >= self.reveal_after / MAX_TIP_ROTATIONS_PER_REVEAL;
        self.tip_rotation_pending |= old_enough;
        old_enough
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

    fn retired_slots(abw: &AbwSlotState) -> Vec<u8> {
        (0..abw::ASSIGNMENT_SLOTS)
            .filter(|&slot| matches!(abw.slots[usize::from(slot)], Slot::Retired { .. }))
            .collect()
    }

    fn secret_key(abw: &AbwSlotState, slot: u8) -> Option<XorKey> {
        match abw.key_for(slot) {
            Some((key, SlotKeyStatus::Secret)) => Some(key),
            _ => None,
        }
    }

    fn revealed_key(abw: &AbwSlotState, slot: u8) -> Option<XorKey> {
        match abw.key_for(slot) {
            Some((key, SlotKeyStatus::Revealed)) => Some(key),
            _ => None,
        }
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
        let key = secret_key(&abw, 0).expect("slot 0 seeded");
        let notice = Notice::decode(&abw.notices()[0]).unwrap();
        assert_eq!(notice.key_hash, xor_key_hash(&key));
        assert!(abw.slots[1..].iter().all(|s| *s == Slot::Empty));
        assert!(retired_slots(&abw).is_empty());
    }

    #[test]
    fn a_rotation_retires_the_active_slot_and_its_reveal_follows_after_the_delay() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        let key0 = secret_key(&abw, 0).unwrap();

        let Rotation { reveals, notice } = abw.rotate(now);
        assert!(reveals.is_empty(), "slot 1 awaits no reveal");
        let n = Notice::decode(&notice).unwrap();
        assert!(n.active);
        assert_eq!(n.slot, 1);
        assert_eq!(abw.active, 1);
        assert_eq!(secret_key(&abw, 0), Some(key0), "the retired slot's key stays secret");
        assert_eq!(decoded_notices(&abw), [(0, false), (1, true)]);
        assert_eq!(retired_slots(&abw), [0]);
        assert!(abw.reveals_due(now).is_empty());
        assert!(!abw.reveal_due(now + AFTER - Duration::from_secs(1)));
        assert!(abw.reveals_due(now + AFTER - Duration::from_secs(1)).is_empty(), "not yet due");
        assert!(abw.reveal_due(now + AFTER));

        let reveals = abw.reveals_due(now + AFTER);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)]);
        assert_eq!(revealed_key(&abw, 0), Some(key0), "its key is kept for refused shares");
        assert!(retired_slots(&abw).is_empty());
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
        assert_eq!(retired_slots(&abw), [0, 1]);
        assert_eq!(abw.slots.iter().filter(|s| s.secret_key().is_some()).count(), 3);
        assert_eq!(decoded_notices(&abw), [(0, false), (1, false), (2, true)]);

        let reveals = abw.reveals_due(now + AFTER);
        assert_eq!(reveals.iter().map(|r| r.slot).collect::<Vec<_>>(), [0], "slot 1 is younger");
        assert_eq!(retired_slots(&abw), [1]);
        let reveals = abw.reveals_due(later + AFTER);
        assert_eq!(reveals.iter().map(|r| r.slot).collect::<Vec<_>>(), [1]);
        assert!(retired_slots(&abw).is_empty());
    }

    #[test]
    fn a_slot_seeded_again_before_its_reveal_is_revealed_first() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        let key0 = secret_key(&abw, 0).unwrap();
        for _ in 0..15 {
            abw.rotate(now);
        }
        assert_eq!(abw.active, 15);
        assert_eq!(retired_slots(&abw), (0..15).collect::<Vec<u8>>());
        let Rotation { reveals, notice } = abw.rotate(now);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)]);
        assert!(!reveals[0].resend);
        assert_eq!(Notice::decode(&notice).unwrap().slot, 0);
        assert_eq!(abw.active, 0);
        let reseeded = secret_key(&abw, 0).expect("seeded anew, the old key dropped");
        assert_ne!(reseeded, key0);
        assert_eq!(retired_slots(&abw), (1..=15).collect::<Vec<u8>>());
    }

    #[test]
    fn a_rotation_onto_a_slot_awaiting_its_reveal_waits_for_the_reveal() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        for _ in 0..15 {
            abw.rotate(now);
        }
        for _ in 0..ROTATE_AFTER_SHARES {
            abw.note_share();
        }
        assert_eq!(abw.rotation_due(now), None, "slot 0 is retired and its reveal is pending");
        assert_eq!(abw.next_due(), now + AFTER, "the loop wakes when slot 0's reveal is due");
        let reveals = abw.reveals_due(now + AFTER);
        assert!(reveals.iter().any(|r| r.slot == 0));
        assert_eq!(abw.rotation_due(now + AFTER), Some("share count"));
        let Rotation { reveals, .. } = abw.rotate(now + AFTER);
        assert!(reveals.is_empty(), "nothing is revealed early");
        assert_eq!(abw.active, 0);
    }

    #[test]
    fn a_resume_keeps_each_reveal_time_and_resends_what_the_gateway_may_have_missed() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        let key0 = secret_key(&abw, 0).unwrap();
        abw.rotate(now);
        let key1 = secret_key(&abw, 1).unwrap();
        let t1 = now + AFTER;
        assert_eq!(abw.reveals_due(t1).len(), 1, "slot 0 revealed; the gateway may miss it");
        abw.rotate(t1);
        assert_eq!(abw.active, 2);
        let closed_at = t1 + Duration::from_secs(170);
        abw.resume(closed_at);
        assert_eq!(retired_slots(&abw), [1]);
        assert_eq!(decoded_notices(&abw), [(1, false), (2, true)], "seeded slots only");
        assert_eq!(secret_key(&abw, 1), Some(key1));
        assert_eq!(revealed_key(&abw, 0), Some(key0));
        assert!(abw.reveal_due(closed_at), "the reveal sent on the closed connection is due again");

        let reveals = abw.reveals_due(closed_at);
        assert_eq!(decoded_reveals(&reveals), [(0, key0)], "a sent reveal is resent at once");
        assert!(reveals[0].resend);
        assert!(!abw.reveal_due(closed_at + AFTER - Duration::from_secs(1)));

        let reveals = abw.reveals_due(closed_at + AFTER);
        assert_eq!(decoded_reveals(&reveals), [(1, key1)], "slot 1 waits from the close");
        assert!(!reveals[0].resend);
        assert_eq!(revealed_key(&abw, 0), Some(key0), "kept until the slot is seeded again");
        assert_eq!(revealed_key(&abw, 1), Some(key1));
        assert!(retired_slots(&abw).is_empty());
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
        assert!(!abw.note_tip(now));
        assert!(!abw.note_tip(now + AFTER / 4 - Duration::from_secs(1)));
        assert_eq!(abw.rotation_due(now + AFTER / 4), None, "a tip too early asks for nothing");
        assert!(abw.note_tip(now + AFTER / 4));
        assert_eq!(abw.rotation_due(now + AFTER / 4), Some("new tip"));
        abw.rotate(now + AFTER / 4);
        assert_eq!(abw.rotation_due(now + AFTER / 4), None, "the rotation clears the request");
        assert!(!abw.note_tip(now + AFTER / 4), "a rotation resets the age");
        assert!(abw.note_tip(now + AFTER / 2));
    }

    #[test]
    fn a_relayed_block_publishes_its_slots_key_and_rotates_off_the_active_slot_at_once() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        abw.rotate(now);
        let key0 = secret_key(&abw, 0).unwrap();
        assert_eq!(abw.note_published(0), Some(false), "slot 0 is retired, not active");
        assert_eq!(revealed_key(&abw, 0), Some(key0), "its shares are refused as revealed");
        assert_eq!(retired_slots(&abw), [0], "its reveal still waits for its time");
        assert!(abw.reveals_due(now).is_empty());
        assert_eq!(abw.rotation_due(now), None, "the active slot's key is still secret");

        let key1 = secret_key(&abw, 1).unwrap();
        assert_eq!(abw.note_published(1), Some(true));
        assert_eq!(abw.note_published(1), None, "published once");
        assert_eq!(revealed_key(&abw, 1), Some(key1));
        assert_eq!(abw.next_due(), now, "the rotation is due now, whatever the slot's age");
        assert_eq!(abw.rotation_due(now), Some("a relayed block published its key"));
        abw.rotate(now);
        assert_eq!(abw.active, 2);
        assert!(secret_key(&abw, 2).is_some(), "the new slot's key is secret");
        assert_eq!(abw.rotation_due(now), None);
        assert_eq!(abw.note_published(OUT_OF_RANGE_SLOT), None);

        for _ in 0..15 {
            abw.rotate(now);
        }
        assert_eq!(abw.active, 1);
        assert!(secret_key(&abw, 1).is_some(), "a slot seeded again has a new, secret key");
    }

    const OUT_OF_RANGE_SLOT: u8 = abw::ASSIGNMENT_SLOTS;

    #[test]
    fn a_connection_holds_rotations_and_reveals_and_a_tip_during_the_hold_waits_for_it() {
        let now = Instant::now();
        let mut abw = AbwSlotState::start(now, AFTER);
        abw.rotate(now);
        let opened_at = now + AFTER;
        abw.connect(opened_at);
        let during = opened_at + REPLAY_GRACE - Duration::from_secs(1);
        let after = opened_at + REPLAY_GRACE;

        assert!(!abw.reveal_due(during), "slot 0's reveal is due but held");
        assert!(abw.reveals_due(during).is_empty());
        assert!(abw.note_tip(during));
        assert_eq!(abw.rotation_due(during), None, "the tip's rotation is held");
        assert_eq!(abw.next_due(), after, "and falls due when the hold ends");

        assert_eq!(abw.rotation_due(after), Some("new tip"), "the tip's rotation is not lost");
        assert!(abw.reveal_due(after));
        assert_eq!(abw.reveals_due(after).iter().map(|r| r.slot).collect::<Vec<u8>>(), [0]);
        abw.rotate(after);
        assert_eq!(abw.rotation_due(after), None);
        assert_eq!(abw.next_due(), after + AFTER, "slot 1's reveal, from its retirement");
    }
}
