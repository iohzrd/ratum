use crate::abw::AbwSlotState;
use crate::bounded::BoundedMap;
use crate::server::Server;
use crate::verify::Splits;
use ratum::datum::handshake::{ResumeToken, new_resume_token};
use ratum::lock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const SESSION_KEEP: Duration = Duration::from_secs(3600);
pub const MAX_SAVED_SESSIONS: usize = 4096;

pub struct SavedSession {
    pub state: SessionState,
    pub saved_at: Instant,
    pub connection_opened_at: Instant,
}

impl SavedSession {
    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.saved_at) > SESSION_KEEP
    }
}

pub struct SessionStore(BoundedMap<[u8; 32], SavedSession>);

impl Default for SessionStore {
    fn default() -> Self {
        Self(BoundedMap::new(MAX_SAVED_SESSIONS))
    }
}

impl SessionStore {
    pub fn save(&mut self, key: [u8; 32], session: SavedSession) {
        let saved_at = session.saved_at;
        self.0.retain(|_, s| !s.expired(saved_at));
        if self
            .0
            .get(&key)
            .is_some_and(|kept| kept.connection_opened_at > session.connection_opened_at)
        {
            return;
        }
        self.0.insert(key, session);
    }

    pub fn take(&mut self, key: &[u8; 32]) -> Option<SavedSession> {
        self.0.remove(key)
    }
}

pub struct SessionState {
    pub token: ResumeToken,
    pub abw: AbwSlotState,
    pub splits: Splits,
    pub last_coinbaser_id: u8,
}

pub struct StartedSession {
    pub state: SessionState,
    pub resumed: bool,
}

impl Server {
    pub fn resume_or_start(
        &self,
        client_sign_pk: [u8; 32],
        presented: Option<&ResumeToken>,
        now: Instant,
    ) -> StartedSession {
        let saved = lock(&self.sessions).take(&client_sign_pk);
        if let (Some(presented), Some(saved)) = (presented, saved)
            && !saved.expired(now)
            && saved.state.token == *presented
        {
            let closed_at = saved.saved_at;
            let mut state = saved.state;
            state.abw.resume(closed_at);
            return StartedSession { state, resumed: true };
        }
        let state = SessionState {
            token: new_resume_token(self.share_policy.prime_id),
            abw: AbwSlotState::start(now, self.abw_reveal_after),
            splits: HashMap::new(),
            last_coinbaser_id: 0,
        };
        StartedSession { state, resumed: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::server_with;
    use crate::payout::DictatedOutput;
    use ratum::bitcoin::transaction::TxOut;

    #[test]
    fn a_saved_session_is_resumed_once_by_its_token() {
        let server = server_with(&[], &[], 0);
        let key = [7u8; 32];
        let now = Instant::now();
        let token = new_resume_token(1);
        let abw = AbwSlotState::start(now, crate::abw::DEFAULT_REVEAL_AFTER);
        let hash0 = ratum::header::xor_key_hash(&abw.keys().seeded[0].unwrap());
        let split = TxOut { value: 5, script_pubkey: vec![0x51] };
        let mut splits = HashMap::new();
        splits.insert(
            7u8,
            crate::verify::DictatedSplit {
                outputs: vec![DictatedOutput {
                    identity: "carol".to_string(),
                    output: split.clone(),
                }],
                sent_at: 0,
            },
        );
        let state = SessionState { token, abw, splits, last_coinbaser_id: 7 };
        lock(&server.sessions)
            .save(key, SavedSession { state, saved_at: now, connection_opened_at: now });

        let StartedSession { state, resumed } = server.resume_or_start(key, Some(&token), now);
        assert!(resumed);
        assert_eq!(state.token, token);
        assert_eq!(ratum::header::xor_key_hash(&state.abw.keys().seeded[0].unwrap()), hash0);
        assert_eq!(
            state.splits.get(&7).map(|d| &d.outputs[0].output),
            Some(&split),
            "the session's splits continue"
        );
        assert_eq!(state.last_coinbaser_id, 7, "the next split takes id 8");
        assert_eq!(lock(&server.sessions).0.len(), 0, "the entry is consumed");

        let StartedSession { state, resumed } = server.resume_or_start(key, Some(&token), now);
        assert!(!resumed, "a consumed session is not resumed again");
        assert_ne!(state.token, token);
        assert_eq!(state.token[..8], 1u64.to_le_bytes());
        assert!(state.splits.is_empty());
        assert_eq!(state.last_coinbaser_id, 0);
    }

    #[test]
    fn a_resume_with_another_token_or_past_session_keep_starts_a_new_session() {
        let server = server_with(&[], &[], 0);
        let key = [8u8; 32];
        let now = Instant::now();
        let token = new_resume_token(1);
        let save = |server: &Server, saved_at: Instant| {
            let abw = AbwSlotState::start(now, crate::abw::DEFAULT_REVEAL_AFTER);
            lock(&server.sessions).save(key, saved(token, abw, saved_at, now));
        };

        save(&server, now);
        let other = new_resume_token(1);
        let StartedSession { state, resumed } = server.resume_or_start(key, Some(&other), now);
        assert!(!resumed);
        assert_ne!(state.token, token);
        assert_eq!(lock(&server.sessions).0.len(), 0, "a mismatch consumes the entry too");

        save(&server, now);
        let late = now + SESSION_KEEP + Duration::from_secs(1);
        assert!(!server.resume_or_start(key, Some(&token), late).resumed, "expired");

        save(&server, now);
        assert!(!server.resume_or_start(key, None, now).resumed, "no token presented");
        assert_eq!(lock(&server.sessions).0.len(), 0);

        assert!(
            !server.resume_or_start([9u8; 32], Some(&token), now).resumed,
            "another gateway's key"
        );
    }

    fn saved(
        token: ResumeToken,
        abw: AbwSlotState,
        saved_at: Instant,
        connection_opened_at: Instant,
    ) -> SavedSession {
        let state = SessionState { token, abw, splits: HashMap::new(), last_coinbaser_id: 0 };
        SavedSession { state, saved_at, connection_opened_at }
    }

    #[test]
    fn the_session_store_evicts_the_oldest_past_its_capacity() {
        let mut store = SessionStore::default();
        let now = Instant::now();
        let token = new_resume_token(1);
        for i in 0..=MAX_SAVED_SESSIONS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let abw = AbwSlotState::start(now, crate::abw::DEFAULT_REVEAL_AFTER);
            store.save(key, saved(token, abw, now, now));
        }
        assert_eq!(store.0.len(), MAX_SAVED_SESSIONS);
        assert!(store.take(&[0u8; 32]).is_none(), "the first entry was evicted");
        let mut last = [0u8; 32];
        last[..8].copy_from_slice(&(MAX_SAVED_SESSIONS as u64).to_le_bytes());
        assert!(store.take(&last).is_some());
        assert_eq!(store.0.len(), MAX_SAVED_SESSIONS - 1);
        let mut second = [0u8; 32];
        second[..8].copy_from_slice(&1u64.to_le_bytes());
        let abw = AbwSlotState::start(now, crate::abw::DEFAULT_REVEAL_AFTER);
        store.save(second, saved(token, abw, now, now));
        assert_eq!(store.0.len(), MAX_SAVED_SESSIONS - 1);
        assert_eq!(store.0.order().back(), Some(&second));
    }

    #[test]
    fn a_save_removes_the_sessions_no_hello_can_resume() {
        let mut store = SessionStore::default();
        let t0 = Instant::now();
        let token = new_resume_token(1);
        let abw = AbwSlotState::start(t0, crate::abw::DEFAULT_REVEAL_AFTER);
        store.save([1u8; 32], saved(token, abw, t0, t0));
        let later = t0 + SESSION_KEEP + Duration::from_secs(1);
        let abw = AbwSlotState::start(later, crate::abw::DEFAULT_REVEAL_AFTER);
        store.save([2u8; 32], saved(token, abw, later, later));
        assert_eq!(store.0.len(), 1, "the expired entry is gone");
        assert!(store.take(&[1u8; 32]).is_none());
        assert!(store.take(&[2u8; 32]).is_some());
        assert!(store.0.order().is_empty(), "the eviction order follows the map");
    }

    #[test]
    fn a_connection_accepted_earlier_does_not_overwrite_a_later_ones_saved_session() {
        let mut store = SessionStore::default();
        let key = [3u8; 32];
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(60);
        let later = new_resume_token(1);
        let earlier = new_resume_token(1);
        let session = |token, connection_opened_at| {
            let abw = AbwSlotState::start(t0, crate::abw::DEFAULT_REVEAL_AFTER);
            saved(token, abw, t1 + Duration::from_secs(1), connection_opened_at)
        };
        store.save(key, session(later, t1));
        store.save(key, session(earlier, t0));
        assert_eq!(
            store.take(&key).unwrap().state.token,
            later,
            "the later connection's entry stays"
        );
        store.save(key, session(earlier, t0));
        store.save(key, session(later, t1));
        assert_eq!(store.take(&key).unwrap().state.token, later);
        assert_eq!(store.0.len(), 0);
    }
}
