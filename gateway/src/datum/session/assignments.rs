//! The anti-block-withholding messages from the pool: a slot assignment and its key hash, and
//! the reveal of a key, which is checked against the hash committed to.

use super::Session;
use log::{debug, error};
use ratum::datum::messages::abw::{AssignmentNotice, Reveal};

impl Session<'_> {
    pub(super) fn on_abw_notice(&self, plain: &[u8]) {
        let Some(notice) = decoded("assignment notice", AssignmentNotice::decode(plain)) else {
            return;
        };
        self.gateway.pool.session().abw.install(notice.slot, notice.key_hash, notice.active);
        debug!("ABW assignment for slot {} (active {})", notice.slot, notice.active);
        if notice.active {
            self.gateway.template_waker.rebuild();
        }
    }

    pub(super) fn on_abw_reveal(&self, plain: &[u8]) {
        let Some(reveal) = decoded("reveal", Reveal::decode(plain)) else { return };
        if !self.gateway.pool.session().abw.reveal(reveal.slot, &reveal.xor_key) {
            error!("ABW reveal for slot {} does not match its commitment; ignored", reveal.slot);
            return;
        }
        debug!("ABW slot {} revealed", reveal.slot);
    }
}

fn decoded<T>(what: &str, decoded: Result<T, ratum::datum::messages::Error>) -> Option<T> {
    decoded.inspect_err(|e| error!("malformed ABW {what}: {e}")).ok()
}
