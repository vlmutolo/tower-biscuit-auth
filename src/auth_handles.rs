use std::{
    hash::Hash,
    time::{SystemTime, UNIX_EPOCH},
};

use biscuit_auth::Biscuit;
use dashmap::DashMap;

use crate::SharedAuth;

pub struct AuthHandles<K> {
    auth_map: DashMap<K, SharedAuth>,
    revocation_list: RevocationList,
}

impl<K> AuthHandles<K> {
    pub fn auth_map(&self) -> &DashMap<K, SharedAuth> {
        &self.auth_map
    }

    pub fn check(&self, biscuit: &Biscuit) -> bool {
        let at_least_one_revoked = biscuit
            .revocation_identifiers()
            .into_iter()
            .any(|id| self.revocation_list.map.contains_key(&id));

        !at_least_one_revoked
    }

    /// Clean up expired entries in the revocation.
    ///
    /// This does a full scan over the list of existing revocation IDs,
    /// so it should be used sparingly if there are a large number of
    /// authorizers or revocation IDs.
    pub fn drain_expired(&self) {
        self.revocation_list.drain_expired();
    }
}

impl<K: Hash + Eq> AuthHandles<K> {
    pub fn new() -> Self {
        Self {
            auth_map: DashMap::new(),
            revocation_list: RevocationList::new(),
        }
    }
}

impl<K: Hash + Eq> Default for AuthHandles<K> {
    fn default() -> Self {
        Self::new()
    }
}

type RevocationId = Vec<u8>;
type Expiry = u64;

struct RevocationList {
    map: DashMap<RevocationId, Expiry>,
}

impl RevocationList {
    fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }

    fn drain_expired(&self) {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("no reason to have a time less than Unix epoch\u{2026} right?")
            .as_secs();

        self.map
            .retain(|_id, expiry_unix_s| *expiry_unix_s > cutoff);
    }
}
