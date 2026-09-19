//! The version 3 sessions kept between connections, by the gateway's signing key. A gateway
//! presenting the token of its saved session continues that session's assignments and the splits it
//! was sent, so the shares it replays after a reconnect still verify.

use crate::abw::AbwSlotState;
use crate::bounded::BoundedMap;
use crate::verify::DictatedSplits;
use ratum::datum::handshake::{ResumeToken, new_resume_token};
use std::time::{Duration, Instant};

pub const SESSION_KEEP: Duration = Duration::from_secs(3600);
pub const MAX_SAVED_SESSIONS: usize = 4096;

/// A version 3 session as saved between connections: its open part, the splits the
/// verifier recorded, when it was saved and when its connection was accepted.
pub struct SavedSession {
    pub v3: V3Session,
    pub splits: DictatedSplits,
    pub saved_at: Instant,
    pub connection_opened_at: Instant,
}

impl SavedSession {
    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.saved_at) > SESSION_KEEP
    }
}

/// The version 3 sessions saved for resume, by the gateway's signing key, and what a new
/// session starts with: the pool's prime id in its token and the reveal delay of its slots.
pub struct SessionStore {
    saved: BoundedMap<[u8; 32], SavedSession>,
    prime_id: u64,
    reveal_after: Duration,
}

impl SessionStore {
    pub fn new(prime_id: u64, reveal_after: Duration) -> Self {
        Self { saved: BoundedMap::new(MAX_SAVED_SESSIONS), prime_id, reveal_after }
    }

    pub fn save(&mut self, key: [u8; 32], session: SavedSession) {
        let saved_at = session.saved_at;
        self.saved.retain(|_, s| !s.expired(saved_at));
        if self
            .saved
            .get(&key)
            .is_some_and(|kept| kept.connection_opened_at > session.connection_opened_at)
        {
            return;
        }
        self.saved.insert(key, session);
    }

    #[cfg(test)]
    pub fn take(&mut self, key: &[u8; 32]) -> Option<SavedSession> {
        self.saved.remove(key)
    }

    /// The session and splits for a hello, and whether they resumed a saved session. The
    /// hello carries no challenge from the pool, so a copy of an earlier hello can be sent
    /// again by anyone who observed it. A hello that presents no token, or another token,
    /// leaves the saved session in place. One that presents its token receives a copy of the
    /// session under a new token, and the saved session stays until `claim` removes it, once
    /// the connection has sent a frame the session key decrypts, which a copy of a hello
    /// cannot: the gateway that sent the hello can still resume the session after it.
    pub fn resume_or_start(
        &mut self,
        client_sign_pk: [u8; 32],
        presented: Option<&ResumeToken>,
        now: Instant,
    ) -> (V3Session, DictatedSplits, bool) {
        let saved = presented.and_then(|presented| {
            self.saved
                .get(&client_sign_pk)
                .filter(|saved| !saved.expired(now) && saved.v3.token == *presented)
        });
        if let Some(saved) = saved {
            let mut abw = saved.v3.abw.clone();
            abw.resume(saved.saved_at);
            let v3 = V3Session { token: new_resume_token(self.prime_id), abw };
            return (v3, saved.splits.clone(), true);
        }
        let v3 = V3Session {
            token: new_resume_token(self.prime_id),
            abw: AbwSlotState::start(now, self.reveal_after),
        };
        (v3, DictatedSplits::default(), false)
    }

    /// Removes the saved session `presented` resumed, now that the connection holding its
    /// copy has proved it holds the session keys; false when no saved session carries the
    /// token, as when another connection claimed it first or its gateway saved a newer one.
    pub fn claim(&mut self, client_sign_pk: [u8; 32], presented: &ResumeToken) -> bool {
        let claimed = self.saved.get(&client_sign_pk).is_some_and(|s| s.v3.token == *presented);
        if claimed {
            self.saved.remove(&client_sign_pk);
        }
        claimed
    }
}

/// What a version 3 connection holds while it is open: its resume token and its
/// anti-block-withholding slots.
pub struct V3Session {
    pub token: ResumeToken,
    pub abw: AbwSlotState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abw::DEFAULT_REVEAL_AFTER;
    use crate::ledger::split::Payout;
    use crate::payout::DictatedOutput;
    use ratum::bitcoin::transaction::TxOut;

    fn store() -> SessionStore {
        SessionStore::new(1, DEFAULT_REVEAL_AFTER)
    }

    #[test]
    fn a_saved_session_is_copied_by_its_token_and_removed_once_claimed() {
        let mut store = store();
        let key = [7u8; 32];
        let now = Instant::now();
        let token = new_resume_token(1);
        let abw = AbwSlotState::start(now, DEFAULT_REVEAL_AFTER);
        let hash0 = ratum::header::xor_key_hash(&abw.key_for(0).unwrap().0);
        let split = TxOut { value: 5, script_pubkey: vec![0x51] };
        let mut splits = DictatedSplits::default();
        splits.record(
            7,
            split.value,
            [0x5a; 32],
            vec![DictatedOutput {
                payout: Payout { identity: "carol".to_string(), sats: split.value },
                script_pubkey: split.script_pubkey.clone(),
            }],
            0,
        );
        let v3 = V3Session { token, abw };
        store.save(key, SavedSession { v3, splits, saved_at: now, connection_opened_at: now });

        let (v3, splits, resumed) = store.resume_or_start(key, Some(&token), now);
        assert!(resumed);
        assert_ne!(v3.token, token, "the copy carries a new token");
        assert_eq!(v3.token[..8], 1u64.to_le_bytes());
        assert_eq!(ratum::header::xor_key_hash(&v3.abw.key_for(0).unwrap().0), hash0);
        assert_eq!(
            splits.get(7).map(|d| d.outputs[0].output()).as_ref(),
            Some(&split),
            "the session's splits continue"
        );
        assert_eq!(splits.next_id(), 8, "the next split takes id 8");
        assert_eq!(store.saved.len(), 1, "the entry stays until the connection is proved");

        let (again, _, resumed) = store.resume_or_start(key, Some(&token), now);
        assert!(resumed, "a copy of the hello sent again receives another copy");
        assert_ne!(again.token, v3.token, "under a token of its own");

        assert!(!store.claim(key, &v3.token), "the new token names no saved session");
        assert!(store.claim(key, &token));
        assert_eq!(store.saved.len(), 0, "the entry is removed once");
        assert!(!store.claim(key, &token));

        let (v3, splits, resumed) = store.resume_or_start(key, Some(&token), now);
        assert!(!resumed, "a claimed session is not resumed again");
        assert_ne!(v3.token, token);
        assert_eq!(splits, DictatedSplits::default());
        assert_eq!(splits.next_id(), 1);
    }

    #[test]
    fn a_resume_with_another_token_or_past_session_keep_starts_a_new_session() {
        let mut store = store();
        let key = [8u8; 32];
        let now = Instant::now();
        let token = new_resume_token(1);
        let save = |store: &mut SessionStore, saved_at: Instant| {
            let abw = AbwSlotState::start(now, DEFAULT_REVEAL_AFTER);
            store.save(key, saved(token, abw, saved_at, now));
        };

        save(&mut store, now);
        let other = new_resume_token(1);
        let (v3, _, resumed) = store.resume_or_start(key, Some(&other), now);
        assert!(!resumed);
        assert_ne!(v3.token, token);
        assert_eq!(store.saved.len(), 1, "a mismatch leaves the entry for the right token");

        let late = now + SESSION_KEEP + Duration::from_secs(1);
        assert!(!store.resume_or_start(key, Some(&token), late).2, "expired");

        assert!(!store.resume_or_start(key, None, now).2, "no token presented");
        assert_eq!(store.saved.len(), 1, "and neither does a hello without one");
        assert!(!store.resume_or_start([9u8; 32], Some(&token), now).2, "another gateway's key");
        assert!(store.resume_or_start(key, Some(&token), now).2, "the right token resumes it");
        assert_eq!(store.saved.len(), 1, "and leaves the entry until it is claimed");
        assert!(store.claim(key, &token));
        assert_eq!(store.saved.len(), 0);
    }

    fn saved(
        token: ResumeToken,
        abw: AbwSlotState,
        saved_at: Instant,
        connection_opened_at: Instant,
    ) -> SavedSession {
        let v3 = V3Session { token, abw };
        SavedSession { v3, splits: DictatedSplits::default(), saved_at, connection_opened_at }
    }

    #[test]
    fn the_session_store_evicts_the_oldest_past_its_capacity() {
        let mut store = store();
        let now = Instant::now();
        let token = new_resume_token(1);
        for i in 0..=MAX_SAVED_SESSIONS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let abw = AbwSlotState::start(now, DEFAULT_REVEAL_AFTER);
            store.save(key, saved(token, abw, now, now));
        }
        assert_eq!(store.saved.len(), MAX_SAVED_SESSIONS);
        assert!(store.take(&[0u8; 32]).is_none(), "the first entry was evicted");
        let mut last = [0u8; 32];
        last[..8].copy_from_slice(&(MAX_SAVED_SESSIONS as u64).to_le_bytes());
        assert!(store.take(&last).is_some());
        assert_eq!(store.saved.len(), MAX_SAVED_SESSIONS - 1);
        let mut second = [0u8; 32];
        second[..8].copy_from_slice(&1u64.to_le_bytes());
        let abw = AbwSlotState::start(now, DEFAULT_REVEAL_AFTER);
        store.save(second, saved(token, abw, now, now));
        assert_eq!(store.saved.len(), MAX_SAVED_SESSIONS - 1);
        assert_eq!(store.saved.order().back(), Some(&second));
    }

    #[test]
    fn a_save_removes_the_sessions_no_hello_can_resume() {
        let mut store = store();
        let t0 = Instant::now();
        let token = new_resume_token(1);
        let abw = AbwSlotState::start(t0, DEFAULT_REVEAL_AFTER);
        store.save([1u8; 32], saved(token, abw, t0, t0));
        let later = t0 + SESSION_KEEP + Duration::from_secs(1);
        let abw = AbwSlotState::start(later, DEFAULT_REVEAL_AFTER);
        store.save([2u8; 32], saved(token, abw, later, later));
        assert_eq!(store.saved.len(), 1, "the expired entry is gone");
        assert!(store.take(&[1u8; 32]).is_none());
        assert!(store.take(&[2u8; 32]).is_some());
        assert!(store.saved.order().is_empty(), "the eviction order follows the map");
    }

    #[test]
    fn a_connection_accepted_earlier_does_not_overwrite_a_later_ones_saved_session() {
        let mut store = store();
        let key = [3u8; 32];
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(60);
        let later = new_resume_token(1);
        let earlier = new_resume_token(1);
        let session = |token, connection_opened_at| {
            let abw = AbwSlotState::start(t0, DEFAULT_REVEAL_AFTER);
            saved(token, abw, t1 + Duration::from_secs(1), connection_opened_at)
        };
        store.save(key, session(later, t1));
        store.save(key, session(earlier, t0));
        assert_eq!(store.take(&key).unwrap().v3.token, later, "the later connection's entry stays");
        store.save(key, session(earlier, t0));
        store.save(key, session(later, t1));
        assert_eq!(store.take(&key).unwrap().v3.token, later);
        assert_eq!(store.saved.len(), 0);
    }
}
