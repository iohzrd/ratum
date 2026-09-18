//! A value held under a lock whose writer is told whether it changed, which is what lets a
//! condition that stands be reported once rather than once per poll.

use crate::lock;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct Latest<T>(Mutex<T>);

impl<T: Clone + PartialEq> Latest<T> {
    pub fn get(&self) -> T {
        lock(&self.0).clone()
    }

    /// Records `value` and returns whether it differs from the value held.
    pub fn set(&self, value: T) -> bool {
        let mut held = lock(&self.0);
        if *held == value {
            return false;
        }
        *held = value;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_reports_only_a_change() {
        let held: Latest<Option<String>> = Latest::default();
        assert_eq!(held.get(), None);
        assert!(!held.set(None), "the value it already holds");
        assert!(held.set(Some("no template".into())));
        assert!(!held.set(Some("no template".into())), "the same reason, standing");
        assert_eq!(held.get(), Some("no template".to_string()));
        assert!(held.set(None), "the reason cleared");
    }
}
