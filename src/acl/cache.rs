use lru::LruCache;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use super::rule::Protocol;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MatchResultCacheKey {
    pub host: String,
    pub proto: Protocol,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct MatchResult<O: Clone> {
    pub outbound: Option<O>,
    pub hijack_address: Option<IpAddr>,
}

pub struct MatchCache<O: Clone> {
    cache: Mutex<LruCache<MatchResultCacheKey, MatchResult<O>>>,
}

impl<O: Clone> MatchCache<O> {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

    pub fn get(&self, key: &MatchResultCacheKey) -> Option<MatchResult<O>> {
        let mut lock = self.cache.lock().unwrap();
        lock.get(key).cloned()
    }

    pub fn put(&self, key: MatchResultCacheKey, result: MatchResult<O>) {
        let mut lock = self.cache.lock().unwrap();
        lock.put(key, result);
    }
}
