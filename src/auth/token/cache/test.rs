use super::{CacheClient, HttpCache, HttpCacheError, Resource};
use async_trait::async_trait;
use bytes::Bytes;
use error_stack::Report;
use http::Uri;
use serde_json::to_string;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

struct CacheClientMock {
    pub calls: Arc<Mutex<usize>>,
    response: Resource,
}

impl CacheClientMock {
    pub fn new(response: Resource) -> Self {
        Self {
            calls: Arc::new(Mutex::new(0)),
            response,
        }
    }
}

#[async_trait]
impl CacheClient for CacheClientMock {
    type Error = HttpCacheError;

    async fn fetch(&self, _uri: &Uri) -> Result<Resource, Report<Self::Error>> {
        *self.calls.lock().await += 1;

        Ok(self.response.clone())
    }
}

#[tokio::test]
async fn test_http_cache() {
    let json = Bytes::copy_from_slice(to_string(&123).unwrap().as_bytes());
    let response = Resource {
        data: json,
        max_age: Duration::from_secs(999),
    };
    let client = CacheClientMock::new(response);
    let calls = client.calls.clone();

    let http_cache = HttpCache::new(client, "http://localhost".parse().unwrap())
        .await
        .unwrap();

    let _: i32 = http_cache.get().await.unwrap();
    let _: i32 = http_cache.get().await.unwrap();
    let cached: i32 = http_cache.get().await.unwrap();

    assert_eq!(cached, 123);
    assert_eq!(*calls.lock().await, 1);
}
