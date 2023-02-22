#[cfg(test)]
mod test;

pub mod cache;
pub mod crypto;
pub mod error;
pub mod jwt;

use cache::{error::HttpCacheError, CacheClient, HttpCache};
use crypto::JwtRsaPubKey;
use error::TokenVerificationError;
use error_stack::{Report, ResultExt};
use http::Uri;
use jwt::{JWTAlgorithm, JWToken};
use std::collections::BTreeMap;
use time::OffsetDateTime;

const GOOGLE_PUB_KEY_URI: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

pub struct TokenVerifier<ClientT> {
    project_id: String,
    issuer: String,
    key_cache: HttpCache<ClientT, BTreeMap<String, JwtRsaPubKey>>,
}

impl<ClientT: CacheClient> TokenVerifier<ClientT> {
    pub async fn new(project_id: String, client: ClientT) -> Result<Self, Report<HttpCacheError>> {
        Ok(Self {
            issuer: String::new() + "https://securetoken.google.com/" + &project_id,
            project_id,
            key_cache: HttpCache::new(client, Uri::from_static(GOOGLE_PUB_KEY_URI)).await?,
        })
    }

    async fn verify_signature(
        &self,
        token: &JWToken,
    ) -> Result<(), Report<TokenVerificationError>> {
        let keys = self.key_cache.get().await.unwrap();

        let key = keys
            .get(&token.header.kid)
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

        if token.critical_claims.iat > now {
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

    pub async fn verify(&self, token: &JWToken) -> Result<(), Report<TokenVerificationError>> {
        self.verify_header(token)?;
        self.verify_claims(token)?;
        self.verify_signature(token).await
    }
}
