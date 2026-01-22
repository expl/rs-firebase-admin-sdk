use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use core::future::Future;
use error_stack::{Report, ResultExt};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use jsonwebtoken_jwks_cache::{CachedJWKS, TimeoutSpec};
use serde_json::{Value, from_slice};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

const GOOGLE_JWKS_URI: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const GOOGLE_PKEYS_URI: &str =
    "https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys";
const GOOGLE_ID_TOKEN_ISSUER_PREFIX: &str = "https://securetoken.google.com/";
const GOOGLE_COOKIE_ISSUER_PREFIX: &str = "https://session.firebase.google.com/";

#[derive(Error, Debug, Clone)]
pub enum TokenVerificationError {
    #[error("Token's key is missing")]
    MissingKey,
    #[error("Invalid token")]
    Invalid,
    #[error("Unexpected error")]
    Internal,
}

pub trait TokenValidator {
    /// Validate JWT returning all claims on success
    fn validate(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<HashMap<String, Value>, Report<TokenVerificationError>>> + Send + Sync;
}

pub struct LiveValidator {
    project_id: String,
    issuer: String,
    jwks: CachedJWKS,
}

impl LiveValidator {
    pub fn new_jwt_validator(project_id: String) -> Result<Self, reqwest::Error> {
        Ok(Self {
            issuer: format!("{GOOGLE_ID_TOKEN_ISSUER_PREFIX}{project_id}"),
            project_id,
            jwks: CachedJWKS::new(
                // should always succeed
                GOOGLE_JWKS_URI.parse().unwrap(),
                Duration::from_secs(60),
                TimeoutSpec::default(),
            )?,
        })
    }

    pub fn new_cookie_validator(project_id: String) -> Result<Self, reqwest::Error> {
        Ok(Self {
            issuer: format!("{GOOGLE_COOKIE_ISSUER_PREFIX}{project_id}"),
            project_id,
            jwks: CachedJWKS::new_rsa_pkeys(
                // should always succeed
                GOOGLE_PKEYS_URI.parse().unwrap(),
                Duration::from_secs(60),
                TimeoutSpec::default(),
            )?,
        })
    }
}

impl TokenValidator for LiveValidator {
    async fn validate(
        &self,
        token: &str,
    ) -> Result<HashMap<String, Value>, Report<TokenVerificationError>> {
        let jwks = self
            .jwks
            .get()
            .await
            .change_context(TokenVerificationError::Internal)?;
        let jwt_header = decode_header(token).change_context(TokenVerificationError::Invalid)?;

        let jwk: DecodingKey = jwks
            .find(&jwt_header.kid.ok_or(TokenVerificationError::MissingKey)?)
            .ok_or(TokenVerificationError::MissingKey)?
            .try_into()
            .change_context(TokenVerificationError::Internal)?;

        let mut validator = Validation::new(jwt_header.alg);
        validator.set_audience(&[&self.project_id]);
        validator.set_issuer(&[&self.issuer]);

        decode::<HashMap<String, Value>>(token, &jwk, &validator)
            .change_context(TokenVerificationError::Invalid)
            .map(|t| t.claims)
    }
}

#[derive(Default)]
pub struct EmulatorValidator;

impl TokenValidator for EmulatorValidator {
    async fn validate(
        &self,
        token: &str,
    ) -> Result<HashMap<String, Value>, Report<TokenVerificationError>> {
        let header = token
            .split(".")
            .nth(1)
            .ok_or(TokenVerificationError::Invalid)?;

        let header = URL_SAFE_NO_PAD
            .decode(header)
            .change_context(TokenVerificationError::Invalid)?;

        from_slice(&header).change_context(TokenVerificationError::Invalid)
    }
}
