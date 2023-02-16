use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CredentialsError {
    #[error("Failed while parsing service credential JSON")]
    FailedParsingServiceCredentials,
    #[error("Received invalid access token")]
    InvalidAccessToken,
    #[error("Something unexpected happened")]
    Internal,
}
