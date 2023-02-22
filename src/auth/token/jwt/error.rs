use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum JWTError {
    #[error("Failed to parse token")]
    FailedToParse,
    #[error("Failed to encode token")]
    FailedToEncode,
    #[error("Token is missing header")]
    MissingHeader,
    #[error("Token is missing payload")]
    MissingPayload,
    #[error("Token is missing signature")]
    MissingSignature,
}
