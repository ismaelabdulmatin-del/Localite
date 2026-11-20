//! Scoped in-memory store with controllable clock.
//!
//! Scopes isolate namespaces/tenants; `Clock` has `now()` (auth wall-clock)
//! and `service_now()` (semantic time) so signature-skew tests can freeze
//! auth without freezing TTLs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default)]
pub struct Clock {
    frozen_service: Option<u64>,
    frozen_wall: Option<u64>,
}

impl Clock {
    pub fn live() -> Self {
        Self { frozen_service: None, frozen_wall: None }
    }
    pub fn frozen_at(epoch_secs: u64) -> Self {
        Self { frozen_service: Some(epoch_secs), frozen_wall: Some(epoch_secs) }
    }
    fn epoch_now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
    /// Wall clock for SigV4 skew checks.
    pub fn now(&self) -> u64 {
        self.frozen_wall.unwrap_or_else(Self::epoch_now)
    }
    /// Semantic clock for TTLs/expiry.
    pub fn service_now(&self) -> u64 {
        self.frozen_service.unwrap_or_else(Self::epoch_now)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Store {
    inner: Arc<Mutex<HashMap<String, HashMap<String, Vec<u8>>>>>,
    pub clock: Clock,
}

impl Store {
    pub fn new(clock: Clock) -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())), clock }
    }
    pub fn put(&self, scope: &str, key: &str, value: Vec<u8>) {
        self.inner.lock().unwrap()
            .entry(scope.to_string()).or_default()
            .insert(key.to_string(), value);
    }
    pub fn get(&self, scope: &str, key: &str) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().get(scope)?.get(key).cloned()
    }
    pub fn delete(&self, scope: &str, key: &str) -> bool {
        self.inner.lock().unwrap().get_mut(scope).map(|m| m.remove(key).is_some()).unwrap_or(false)
    }
    pub fn list(&self, scope: &str, prefix: &str) -> Vec<String> {
        let g = self.inner.lock().unwrap();
        g.get(scope).map(|m| {
            let mut ks: Vec<String> = m.keys().filter(|k| k.starts_with(prefix)).cloned().collect();
            ks.sort();
            ks
        }).unwrap_or_default()
    }
}

#[cfg(test)]
pub mod store {
    pub mod tests {
        use super::super::*;

        #[test]
        fn scoped_roundtrip() {
            let s = Store::new(Clock::frozen_at(1_700_000_000));
            s.put("tenant-a", "k", b"v".to_vec());
            assert_eq!(s.get("tenant-a", "k").unwrap(), b"v");
            // Scopes isolate.
            assert_eq!(s.get("tenant-b", "k"), None);
            assert_eq!(s.clock.service_now(), 1_700_000_000);
            assert_eq!(s.clock.now(), 1_700_000_000);
            assert!(s.delete("tenant-a", "k"));
            assert_eq!(s.get("tenant-a", "k"), None);
        }
    }
}
