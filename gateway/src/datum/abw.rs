//! The anti-block-withholding commitments this gateway holds: one key hash per slot and which slot
//! is active. The gateway holds no key until the pool reveals it, so it hashes a header with the
//! committed hash in place of one.

use ratum::datum::messages::abw::ASSIGNMENT_SLOTS;
use ratum::header::{XorKey, xor_key_hash};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbwAssignment {
    pub slot: u8,
    pub key_hash: [u8; 32],
}

#[derive(Default)]
pub struct AbwAssignments {
    key_hashes: [Option<[u8; 32]>; ASSIGNMENT_SLOTS as usize],
    active: Option<u8>,
}

impl AbwAssignments {
    pub fn assignment(&self) -> Option<AbwAssignment> {
        let slot = self.active?;
        Some(AbwAssignment { slot, key_hash: self.key_hashes[slot as usize]? })
    }

    pub fn holds(&self, a: AbwAssignment) -> bool {
        self.key_hashes[a.slot as usize] == Some(a.key_hash)
    }

    pub fn install(&mut self, slot: u8, key_hash: [u8; 32], active: bool) {
        self.key_hashes[slot as usize] = Some(key_hash);
        if active {
            self.active = Some(slot);
        }
    }

    /// Makes `slot` active. False, and no change, when the slot holds no key hash (never
    /// installed, or revealed).
    pub fn activate(&mut self, slot: u8) -> bool {
        if self.key_hashes[slot as usize].is_none() {
            return false;
        }
        self.active = Some(slot);
        true
    }

    pub fn reveal(&mut self, slot: u8, xor_key: &XorKey) -> bool {
        if let Some(hash) = self.key_hashes[slot as usize]
            && xor_key_hash(xor_key) != hash
        {
            return false;
        }
        self.key_hashes[slot as usize] = None;
        if self.active == Some(slot) {
            self.active = None;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The C gateway's `datum_protocol_abw_activation_state_test` sequence.
    #[test]
    fn an_activation_moves_the_active_slot_to_an_installed_one() {
        let key = |b: u8| [b; 16];
        let mut a = AbwAssignments::default();
        assert!(!a.activate(0), "not installed");
        a.install(0, xor_key_hash(&key(1)), false);
        assert_eq!(a.assignment(), None, "an inactive notice installs without activating");
        assert!(a.activate(0));
        assert_eq!(a.assignment().map(|x| x.slot), Some(0));

        a.install(1, xor_key_hash(&key(2)), false);
        assert_eq!(a.assignment().map(|x| x.slot), Some(0));
        assert!(a.activate(1));
        assert_eq!(
            a.assignment(),
            Some(AbwAssignment { slot: 1, key_hash: xor_key_hash(&key(2)) })
        );

        assert!(a.reveal(0, &key(1)));
        assert!(!a.activate(0), "revealed");
        assert_eq!(a.assignment().map(|x| x.slot), Some(1));
        assert!(a.reveal(1, &key(2)));
        assert_eq!(a.assignment(), None);
    }
}
