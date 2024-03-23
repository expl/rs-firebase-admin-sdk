use reqwest::StatusCode;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
#[error("Failed while caching resource")]
pub struct CacheError;

#[derive(Error, Debug, Clone)]
pub enum ClientError {
    #[error("Failed to fetch HTTP resource")]
    FailedToFetch,
    #[error("Unexpected HTTP status code {0}")]
    BadHttpResponse(StatusCode),
    #[error("Failed to deserialize resource")]
    FailedToDeserialize,
}
