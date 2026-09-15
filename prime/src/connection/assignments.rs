use super::Connection;
use crate::abw::{AbwSlotState, PendingReveal, Rotation};
use crate::verify::RebuiltShare;
use log::{debug, warn};
use ratum::datum::messages::blocknotify;
use ratum::datum::messages::share::PowSubmit;
use std::io;
use std::time::{Duration, Instant};

pub(super) const REPLAY_GRACE: Duration = Duration::from_secs(10);

impl Connection<'_> {
    pub(super) fn abw(&self) -> Option<&AbwSlotState> {
        self.v3.as_ref().map(|v| &v.abw)
    }

    pub(super) fn with_abw<R>(&mut self, f: impl FnOnce(&mut AbwSlotState) -> R) -> Option<R> {
        let abw = &mut self.v3.as_mut()?.abw;
        let r = f(abw);
        let keys = abw.keys();
        self.verifier.set_abw_keys(Some(keys));
        Some(r)
    }

    pub(super) fn notify_tip_change(&mut self) -> io::Result<()> {
        let current = self.server.node_view.tip().map(|t| t.hash);
        let next_bits = self.server.node_view.next_bits();
        if current != self.known_tip {
            let tip_replaced = self.known_tip.is_some();
            self.known_tip = current;
            self.verifier.set_tip(current, ratum::unix_now());
            self.verifier.set_next_target(next_bits);
            self.known_next_bits = next_bits;
            if current.is_some() {
                if tip_replaced {
                    self.rotate_on_tip()?;
                }
                self.send_mining(&blocknotify(), false)?;
                debug!("[{}]   <- blocknotify (new tip)", self.peer);
            }
        } else if next_bits != self.known_next_bits {
            self.verifier.set_next_target(next_bits);
            self.known_next_bits = next_bits;
            debug!("[{}]   next target set for the current tip", self.peer);
        }
        Ok(())
    }

    fn rotate_on_tip(&mut self) -> io::Result<()> {
        match self.abw() {
            Some(abw) if abw.tip_rotation_allowed(Instant::now()) => self.rotate_abw("new tip"),
            Some(_) => {
                debug!(
                    "[{}]   the active ABW slot is too young to rotate on the new tip",
                    self.peer
                );
                Ok(())
            }
            None => Ok(()),
        }
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
        if self.opened_at.elapsed() < REPLAY_GRACE {
            return Ok(());
        }
        let Some(Rotation { reveals, notice }) = self.with_abw(|abw| abw.rotate(Instant::now()))
        else {
            return Ok(());
        };
        self.send_reveals(&reveals, true)?;
        self.send_mining(&notice, false)?;
        debug!("[{}]   <- rotated the ABW assignment ({why})", self.peer);
        Ok(())
    }

    pub(super) fn send_due_reveals(&mut self) -> io::Result<()> {
        let now = Instant::now();
        if self.opened_at.elapsed() < REPLAY_GRACE
            || !self.abw().is_some_and(|abw| abw.reveal_due(now))
            || !self.socket_drained()?
        {
            return Ok(());
        }
        let reveals = self.with_abw(|abw| abw.reveals_due(now)).unwrap_or_default();
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
        let Some(slot) = s.abw_slot.filter(|_| self.v3.is_some()) else { return Ok(()) };
        self.send_mining(&AbwSlotState::receipt(slot, rebuilt.raw_pow_hash), false)?;
        debug!("[{}]   <- ABW receipt for the block on slot {slot}", self.peer);
        Ok(())
    }
}
