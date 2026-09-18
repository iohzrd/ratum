//! What interrupts the template thread's wait: a block notification, from the node, the pool,
//! SIGUSR1 or /NOTIFY, a request to rebuild the current work as a new block, and a request to
//! build a job on the current tip at once. A wait reports which of them arrived.

use ratum::lock;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

#[derive(Default)]
pub struct TemplateWaker {
    pending: Mutex<PendingWakes>,
    signal: Condvar,
}

#[derive(Default)]
struct PendingWakes {
    block: Option<PendingBlock>,
    rebuild_requested: bool,
    refresh_requested: bool,
}

#[derive(Clone, Debug)]
enum PendingBlock {
    AnyBlock,
    Hash(String),
}

impl PendingBlock {
    fn hash(self) -> Option<String> {
        match self {
            Self::AnyBlock => None,
            Self::Hash(h) => Some(h),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wake {
    /// A block notification: the tip it names, none when any pending notification named no
    /// tip, and whether a rebuild was requested with it.
    Block {
        hash: Option<String>,
        rebuild: bool,
    },
    /// Rebuild the work as a new block: every job served is marked stale and the tip is
    /// served again as empty work.
    Rebuild,
    /// Build a job on the current tip now, as the next work update would: the jobs already
    /// served stay valid.
    Refresh,
    Timeout,
}

impl TemplateWaker {
    pub fn raise(&self) {
        self.raise_block(None);
    }

    pub fn raise_for(&self, hash_hex: &str) {
        self.raise_block(Some(hash_hex.to_string()));
    }

    fn raise_block(&self, hash: Option<String>) {
        let mut p = lock(&self.pending);
        let pending_is_unnamed = matches!(p.block, Some(PendingBlock::AnyBlock));
        p.block = Some(match hash {
            Some(h) if !pending_is_unnamed => PendingBlock::Hash(h),
            _ => PendingBlock::AnyBlock,
        });
        self.signal.notify_all();
    }

    pub fn rebuild(&self) {
        lock(&self.pending).rebuild_requested = true;
        self.signal.notify_all();
    }

    /// Requests a job on the current tip without a rebuild: the template thread fetches a
    /// template at once and builds from it as it would at the end of its update interval.
    pub fn refresh(&self) {
        lock(&self.pending).refresh_requested = true;
        self.signal.notify_all();
    }

    /// Waits up to `d` for a wake. A refresh requested together with a block notification
    /// or a rebuild is reported as that wake, since the template thread fetches a template
    /// after every wake.
    pub fn wait(&self, d: Duration) -> Wake {
        let g = lock(&self.pending);
        let (mut g, _) = self
            .signal
            .wait_timeout_while(g, d, |p| {
                p.block.is_none() && !p.rebuild_requested && !p.refresh_requested
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rebuild = std::mem::take(&mut g.rebuild_requested);
        let refresh = std::mem::take(&mut g.refresh_requested);
        match g.block.take() {
            Some(pending) => Wake::Block { hash: pending.hash(), rebuild },
            None if rebuild => Wake::Rebuild,
            None if refresh => Wake::Refresh,
            None => Wake::Timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_carry_their_tip_and_an_unknown_tip_outranks_a_known_one() {
        let n = TemplateWaker::default();
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Timeout);
        n.raise_for("aa");
        assert_eq!(
            n.wait(Duration::from_millis(1)),
            Wake::Block { hash: Some("aa".into()), rebuild: false }
        );
        n.raise_for("aa");
        n.raise();
        n.raise_for("bb");
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Block { hash: None, rebuild: false });
        n.rebuild();
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Rebuild);
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Timeout);
    }

    #[test]
    fn a_rebuild_requested_with_a_block_notification_is_carried_by_it() {
        let n = TemplateWaker::default();
        n.rebuild();
        n.raise();
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Block { hash: None, rebuild: true });
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Timeout, "delivered once");
    }

    #[test]
    fn a_refresh_is_its_own_wake_and_never_a_rebuild() {
        let n = TemplateWaker::default();
        n.refresh();
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Refresh);
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Timeout, "delivered once");
        n.refresh();
        n.raise();
        assert_eq!(
            n.wait(Duration::from_millis(1)),
            Wake::Block { hash: None, rebuild: false },
            "a refresh with a block notification requests no rebuild"
        );
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Timeout);
    }
}
