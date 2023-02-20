#[cfg(test)]
mod test;

pub mod error;

use crate::client::HyperClient;
use async_trait::async_trait;
use bytes::Bytes;
use error::{HttpCacheError, HyperClientError};
use error_stack::{IntoReport, Report, ResultExt};
use headers::{CacheControl, HeaderMapExt};
use http::Uri;
use hyper::{self, body::to_bytes};
use serde::de::DeserializeOwned;
use serde_json::from_slice;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
struct Cache<ContentT> {
    expires_at: SystemTime,
    content: ContentT,
}

impl<ContentT> Cache<ContentT> {
    pub fn new(max_age: Duration, content: ContentT) -> Self {
        Self {
            expires_at: SystemTime::now() + max_age,
            content,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at <= SystemTime::now()
    }

    pub fn update(&mut self, max_age: Duration, content: ContentT) {
        self.expires_at = SystemTime::now() + max_age;
        self.content = content;
    }
}

#[derive(Clone, Debug)]
pub struct Resource {
    pub data: Bytes,
    pub max_age: Duration,
}

#[async_trait]
pub trait CacheClient: Sized + Send + Sync
where
    Self::Error: std::error::Error + Send + Sync + 'static,
{
    type Error;

    /// Simple async interface to fetch data and its TTL for an URI
    async fn fetch(&self, uri: &Uri) -> Result<Resource, Report<Self::Error>>;
}

#[async_trait]
impl CacheClient for HyperClient {
    type Error = HyperClientError;

    async fn fetch(&self, uri: &Uri) -> Result<Resource, Report<Self::Error>> {
        let response = self
            .get(uri.clone())
            .await
            .into_report()
            .change_context(HyperClientError::FailedToFetch)?;

        let status = response.status();

        if !status.is_success() {
            return Err(Report::new(HyperClientError::BadHttpResponse(status)));
        }

        let cache_header: Option<CacheControl> = response.headers().typed_get();
        let body = to_bytes(response)
            .await
            .into_report()
            .change_context(HyperClientError::FailedToFetch)?;

        if let Some(cache_header) = cache_header {
            let ttl = cache_header
                .s_max_age()
                .unwrap_or_else(|| cache_header.max_age().unwrap_or_default());

            return Ok(Resource {
                data: body,
                max_age: ttl,
            });
        }

        Ok(Resource {
            data: body,
            max_age: Duration::default(),
        })
    }
}

pub struct HttpCache<CacheClientT, ContentT> {
    client: CacheClientT,
    path: Uri,
    cache: Arc<RwLock<Cache<ContentT>>>,
    refresh: Mutex<()>,
}

impl<CacheClientT, ContentT> HttpCache<CacheClientT, ContentT>
where
    CacheClientT: CacheClient,
    ContentT: DeserializeOwned + Clone + Send + Sync,
{
    pub async fn new(client: CacheClientT, path: Uri) -> Result<Self, Report<HttpCacheError>> {
        let resource = client.fetch(&path).await.change_context(HttpCacheError)?;

        let initial_cache: Cache<ContentT> = Cache::new(
            resource.max_age,
            from_slice(&resource.data)
                .into_report()
                .change_context(HttpCacheError)?,
        );

        Ok(Self {
            client,
            path,
            cache: Arc::new(RwLock::new(initial_cache)),
            refresh: Mutex::new(()),
        })
    }

    pub async fn get(&self) -> Result<ContentT, Report<HttpCacheError>> {
        let cache = self.cache.read().await.clone();
        if cache.is_expired() {
            // to make sure only a single connection is being established to refresh the resource
            let _refresh_guard = self.refresh.lock().await;

            // check if the cache has been refreshed by another co-routine
            let cache = self.cache.read().await.clone();
            if !cache.is_expired() {
                return Ok(cache.content);
            }

            // refresh resource
            let resource = self
                .client
                .fetch(&self.path)
                .await
                .change_context(HttpCacheError)?;

            let content: ContentT = from_slice(&resource.data)
                .into_report()
                .change_context(HttpCacheError)?;

            self.cache
                .write()
                .await
                .update(resource.max_age, content.clone());

            return Ok(content);
        }

        Ok(cache.content)
    }
}
