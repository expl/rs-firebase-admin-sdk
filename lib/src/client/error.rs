use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
pub struct FireBaseAPIErrorDetail {
    pub message: String,
    pub reason: String,
    pub domain: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FireBaseAPIError {
    pub code: u16,
    pub message: String,
    pub errors: Vec<FireBaseAPIErrorDetail>,
}

/// [Firebase Auth error response body](https://firebase.google.com/docs/reference/rest/auth#section-error-format)
#[derive(Clone, Debug, Deserialize)]
pub struct FireBaseAPIErrorResponse {
    pub error: FireBaseAPIError,
}

#[derive(Error, Debug, Clone)]
pub enum ApiClientError {
    #[error("Failed to send API request")]
    FailedToSendRequest,
    #[error("Failed to serialize API request")]
    FailedToSerializeRequest,
    #[error("Failed to receive API response")]
    FailedToReceiveResponse,
    #[error("Failed to deserialize API response")]
    FailedToDeserializeResponse,
    #[error("Server responded with an error {0:?}")]
    ServerError(FireBaseAPIError),
}
