use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum TokenVerificationError {
    #[error("Invalid key for token's signature")]
    InvalidSignatureKey,
    #[error("Invalid token's signature")]
    InvalidSignature,
    #[error("Invalid token's signature algorithm")]
    InvalidSignatureAlgorithm,
    #[error("Token is expired")]
    Expired,
    #[error("Token was issued in the future")]
    IssuedInFuture,
    #[error("Token has invalid audience")]
    InvalidAudience,
    #[error("Token has invalid issuer")]
    InvalidIssuer,
    #[error("Token has empty subject")]
    MissingSubject,
}
