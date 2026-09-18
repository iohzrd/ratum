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
