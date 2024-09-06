#[cfg(test)]
mod test;

pub mod cache;
pub mod crypto;
pub mod error;
pub mod jwt;

use cache::KeyCache;
use crypto::JwtRsaPubKey;
use error::TokenVerificationError;
use error_stack::{Report, ResultExt};
use jwt::{JWTAlgorithm, JWToken};
use std::future::Future;
use time::{Duration, OffsetDateTime};

const GOOGLE_ID_TOKEN_ISSUER_PREFIX: &str = "https://securetoken.google.com/";
const GOOGLE_COOKIE_ISSUER_PREFIX: &str = "https://session.firebase.google.com/";

#[cfg(feature = "tokens")]
pub(crate) const GOOGLE_PUB_KEY_URI: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
#[cfg(feature = "tokens")]
pub(crate) const GOOGLE_COOKIE_PUB_KEY_URI: &str =
    "https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys";

pub trait TokenVerifier: Sized + Sync + Send {
    fn verify_token(
        &self,
        id_token: &str,
    ) -> impl Future<Output = Result<JWToken, Report<TokenVerificationError>>> + Send;
}

pub struct EmulatedTokenVerifier {
    _project_id: String,
    _issuer: String,
}

impl EmulatedTokenVerifier {
    pub fn new(project_id: String) -> Self {
        Self {
            _project_id: project_id.clone(),
            _issuer: project_id,
        }
    }
}

impl TokenVerifier for EmulatedTokenVerifier {
    async fn verify_token(
        &self,
        id_token: &str,
    ) -> Result<JWToken, Report<TokenVerificationError>> {
        let token = JWToken::from_encoded(id_token)
            .change_context(TokenVerificationError::FailedParsing)?;

        // TODO: implement claim checks for emulator

        Ok(token)
    }
}

pub struct LiveTokenVerifier<CacheT: KeyCache> {
    project_id: String,
    issuer: String,
    key_cache: CacheT,
}

impl<CacheT: KeyCache + Send + Sync> TokenVerifier for LiveTokenVerifier<CacheT> {
    async fn verify_token(
        &self,
        id_token: &str,
    ) -> Result<JWToken, Report<TokenVerificationError>> {
        let token = JWToken::from_encoded(id_token)
            .change_context(TokenVerificationError::FailedParsing)?;

        self.verify(&token).await?;

        Ok(token)
    }
}

impl<CacheT: KeyCache + Send + Sync> LiveTokenVerifier<CacheT> {
    /// Create new ID token verifier
    pub fn new_id_verifier(
        project_id: String,
        key_cache: CacheT,
    ) -> Result<Self, Report<TokenVerificationError>> {
        Ok(Self {
            issuer: String::new() + GOOGLE_ID_TOKEN_ISSUER_PREFIX + &project_id,
            project_id,
            key_cache,
        })
    }

    /// Create new cookie token verifier
    pub fn new_cookie_verifier(
        project_id: String,
        key_cache: CacheT,
    ) -> Result<Self, Report<TokenVerificationError>> {
        Ok(Self {
            issuer: String::new() + GOOGLE_COOKIE_ISSUER_PREFIX + &project_id,
            project_id,
            key_cache,
        })
    }

    async fn verify_signature(
        &self,
        token: &JWToken,
    ) -> Result<(), Report<TokenVerificationError>> {
        let keys = self
            .key_cache
            .get_keys()
            .await
            .change_context(TokenVerificationError::FailedGettingKeys)?;

        let key_id = token
            .header
            .kid
            .as_ref()
            .ok_or(TokenVerificationError::FailedGettingKeys)?;

        let key = keys
            .get(key_id)
            .ok_or(Report::new(TokenVerificationError::InvalidSignatureKey))?;

        let is_valid = key
            .verify(token.payload.as_bytes(), &token.signature)
            .change_context(TokenVerificationError::InvalidSignature)?;

        if !is_valid {
            return Err(Report::new(TokenVerificationError::InvalidSignature));
        }

        Ok(())
    }

    fn verify_header(&self, token: &JWToken) -> Result<(), Report<TokenVerificationError>> {
        match token.header.alg {
            JWTAlgorithm::RS256 => Ok(()),
            _ => Err(Report::new(
                TokenVerificationError::InvalidSignatureAlgorithm,
            )),
        }
    }

    fn verify_claims(&self, token: &JWToken) -> Result<(), Report<TokenVerificationError>> {
        let now = OffsetDateTime::now_utc();

        if token.critical_claims.exp <= now {
            return Err(Report::new(TokenVerificationError::Expired));
        }

        // Firebase sometimes has wonky iat, pad with 10secs
        if token.critical_claims.iat > now + Duration::seconds(10) {
            return Err(Report::new(TokenVerificationError::IssuedInFuture));
        }

        if token.critical_claims.auth_time > now {
            return Err(Report::new(TokenVerificationError::IssuedInFuture));
        }

        if token.critical_claims.aud != self.project_id {
            return Err(Report::new(TokenVerificationError::InvalidAudience));
        }

        if token.critical_claims.iss != self.issuer {
            return Err(Report::new(TokenVerificationError::InvalidIssuer));
        }

        if token.critical_claims.sub.is_empty() {
            return Err(Report::new(TokenVerificationError::MissingSubject));
        }

        Ok(())
    }

    /// verify JWToken's attributes and signature
    pub async fn verify(&self, token: &JWToken) -> Result<(), Report<TokenVerificationError>> {
        self.verify_header(token)?;
        self.verify_claims(token)?;
        self.verify_signature(token).await
    }
}
