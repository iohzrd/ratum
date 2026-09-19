//! The anti-block-withholding side of a connection: the tip notifications it sends, the rotations
//! it performs, and the key reveals it sends as they fall due.

use super::Connection;
use crate::abw::{AbwSlotState, PendingReveal, Rotation};
use crate::verify::RebuiltShare;
use log::{debug, warn};
use ratum::datum::messages::BLOCKNOTIFY_MESSAGE;
use ratum::datum::messages::abw::{CandidateRef, subcmd};
use ratum::datum::messages::share::PowSubmit;
use std::io;
use std::time::{Duration, Instant};

impl Connection<'_> {
    pub(super) fn abw(&self) -> Option<&AbwSlotState> {
        self.v3.as_ref().map(|v| &v.abw)
    }

    /// The anti-block-withholding slot a share's receipt and reference name: the slot it
    /// carries, on a version 3 session only.
    pub(super) fn abw_slot_of(&self, s: &PowSubmit) -> Option<u8> {
        s.abw_slot.filter(|_| self.v3.is_some())
    }

    pub(super) fn notify_tip_change(&mut self) -> io::Result<()> {
        let (tip, template) = self.server.node_state.tip_and_template();
        let current = tip.map(|t| t.hash);
        if current != self.verifier.tip() {
            let tip_replaced = self.verifier.tip().is_some();
            self.verifier.set_tip(current, ratum::unix_now());
            self.verifier.set_template(template);
            // The shares held for a parent the node had not reported: verified again now
            // that it reports this tip, and held on while their parent is another block.
            self.release_held(super::shares::HeldShare::awaits_parent)?;
            if current.is_some() {
                if tip_replaced {
                    self.rotate_on_tip()?;
                }
                self.send_mining(&BLOCKNOTIFY_MESSAGE, false)?;
                debug!("[{}]   <- blocknotify (new tip)", self.peer);
            }
        } else if self.verifier.set_template(template) {
            debug!("[{}]   next target set for the current tip", self.peer);
        }
        Ok(())
    }

    /// Rotates the assignment for the new tip before the blocknotify is sent, or leaves the
    /// rotation pending while the connection's hold lasts.
    fn rotate_on_tip(&mut self) -> io::Result<()> {
        let now = Instant::now();
        let Some(v3) = &mut self.v3 else { return Ok(()) };
        if !v3.abw.note_tip(now) {
            debug!("[{}]   the active ABW slot is too young to rotate on the new tip", self.peer);
            return Ok(());
        }
        match v3.abw.rotation_due(now) {
            Some(why) if self.may_rotate_or_reveal()? => self.rotate_abw(why),
            _ => Ok(()),
        }
    }

    /// Whether a rotation or a reveal may be sent now: every share received has been
    /// answered, so none is held for its job's transactions and the socket holds no unread
    /// frame. A reveal then follows the answers to every share mined on the slot it discloses.
    pub(super) fn may_rotate_or_reveal(&mut self) -> io::Result<bool> {
        Ok(self.held.is_empty() && self.socket_drained()?)
    }

    fn send_reveals(&mut self, reveals: &[PendingReveal], rotating: bool) -> io::Result<()> {
        for r in reveals {
            self.send_mining(&r.payload, false)?;
            match (rotating, r.resend) {
                (_, true) => {
                    debug!("[{}]   <- sent the reveal of ABW slot {} again", self.peer, r.slot);
                }
                (false, false) => {
                    debug!("[{}]   <- revealed the retired ABW slot {}", self.peer, r.slot);
                }
                (true, false) => warn!(
                    "[{}]   <- revealed ABW slot {} early: the rotation reached it again \
                     before its reveal was due",
                    self.peer, r.slot
                ),
            }
        }
        Ok(())
    }

    pub(super) fn rotate_abw(&mut self, why: &str) -> io::Result<()> {
        let Some(v3) = &mut self.v3 else { return Ok(()) };
        let Rotation { reveals, notice } = v3.abw.rotate(Instant::now());
        self.send_reveals(&reveals, true)?;
        self.send_mining(&notice, false)?;
        debug!("[{}]   <- rotated the ABW assignment ({why})", self.peer);
        Ok(())
    }

    pub(super) fn send_due_reveals(&mut self) -> io::Result<()> {
        let now = Instant::now();
        if !self.abw().is_some_and(|abw| abw.reveal_due(now)) || !self.may_rotate_or_reveal()? {
            return Ok(());
        }
        let Some(v3) = &mut self.v3 else { return Ok(()) };
        let reveals = v3.abw.reveals_due(now);
        self.send_reveals(&reveals, false)
    }

    fn socket_drained(&mut self) -> io::Result<bool> {
        self.socket.wait(Some(Duration::ZERO))?;
        Ok(!self.socket.readable())
    }

    pub(super) fn send_abw_receipt(
        &mut self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
    ) -> io::Result<()> {
        let Some(slot) = self.abw_slot_of(s) else { return Ok(()) };
        let receipt = CandidateRef::new(slot, &rebuilt.raw_pow_hash)
            .encode_candidate(subcmd::CANDIDATE_RECEIPT);
        self.send_mining(&receipt, false)?;
        debug!("[{}]   <- ABW receipt for the block on slot {slot}", self.peer);
        Ok(())
    }
}
