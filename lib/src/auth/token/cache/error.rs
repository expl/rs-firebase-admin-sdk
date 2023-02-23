use hyper::StatusCode;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
#[error("Failed to while caching HTTP resource")]
pub struct HttpCacheError;

#[derive(Error, Debug, Clone)]
pub enum HyperClientError {
    #[error("Failed to fetch HTTP resource")]
    FailedToFetch,
    #[error("Unexpected HTTP status code {0}")]
    BadHttpResponse(StatusCode),
    #[error("Failed to deserialize resource")]
    FailedToDeserialize,
}
