#[cfg(test)]
mod test;

pub mod error;
pub mod util;

use base64::{self, Engine};
use error::JWTError;
use error_stack::{Report, ResultExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_slice, to_string};
use std::collections::BTreeMap;
use time::{OffsetDateTime, serde::timestamp};

#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
pub enum JWTAlgorithm {
    #[serde(rename = "none")]
    NONE,
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TokenHeader {
    pub alg: JWTAlgorithm,
    pub kid: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TokenClaims {
    #[serde(with = "timestamp")]
    pub exp: OffsetDateTime,
    #[serde(with = "timestamp")]
    pub iat: OffsetDateTime,
    pub aud: String,
    pub iss: String,
    pub sub: String,
    #[serde(with = "timestamp")]
    pub auth_time: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct JWToken {
    pub header: TokenHeader,
    pub critical_claims: TokenClaims,
    pub all_claims: BTreeMap<String, Value>,
    pub payload: String,
    pub signature: Vec<u8>,
}

impl JWToken {
    pub fn from_encoded(encoded: &str) -> Result<Self, Report<JWTError>> {
        let mut parts = encoded.split('.');

        let header_slice = parts.next().ok_or(Report::new(JWTError::MissingHeader))?;

        let header: TokenHeader = from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(header_slice)
                .change_context(JWTError::FailedToParse)?,
        )
        .change_context(JWTError::FailedToParse)?;

        let claims_slice = parts.next().ok_or(Report::new(JWTError::MissingHeader))?;
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims_slice)
            .change_context(JWTError::FailedToParse)?;

        let critical_claims: TokenClaims =
            from_slice(&claims).change_context(JWTError::FailedToParse)?;
        let all_claims: BTreeMap<String, Value> =
            from_slice(&claims).change_context(JWTError::FailedToParse)?;

        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                parts
                    .next()
                    .ok_or(Report::new(JWTError::MissingSignature))?,
            )
            .change_context(JWTError::FailedToParse)?;

        Ok(Self {
            header,
            critical_claims,
            all_claims,
            payload: String::new() + header_slice + "." + claims_slice,
            signature,
        })
    }
}

pub trait JwtSigner {
    fn sign_jwt(&mut self, header: &str, payload: &str) -> Result<String, Report<JWTError>>;
}

/// Utility method for generating JWTs
pub fn encode_jwt<HeaderT: Serialize, PayloadT: Serialize, SignerT: JwtSigner>(
    header: &HeaderT,
    payload: &PayloadT,
    mut signer: SignerT,
) -> Result<String, Report<JWTError>> {
    let encoded_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(to_string(header).change_context(JWTError::FailedToEncode)?);

    let encoded_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(to_string(payload).change_context(JWTError::FailedToEncode)?);

    let encoded_signature = signer.sign_jwt(&encoded_header, &encoded_payload)?;

    Ok(encoded_header + "." + &encoded_payload + "." + &encoded_signature)
}
