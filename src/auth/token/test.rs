use super::jwt::{util::generate_test_token, JWTAlgorithm, JWToken, TokenClaims, TokenHeader};
use super::{TokenVerifier, TokenVerificationError};
use super::{cache::Resource, CacheClient};
use super::crypto::generate_test_cert;
use async_trait::async_trait;
use error_stack::Report;
use http::Uri;
use serde_json::to_string;
use std::collections::BTreeMap;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

#[derive(Error, Debug, Clone)]
#[error("CertCacheClientMockError")]
pub struct CertCacheClientMockError;

/// Mock for public x.509 certificate cache
struct CertCacheClientMock {
    keys: Vec<u8>,
}

impl CertCacheClientMock {
    pub fn mock(keys: Vec<u8>) -> Self {
        Self { keys }
    }
}

#[async_trait]
impl CacheClient for CertCacheClientMock {
    type Error = CertCacheClientMockError;

    async fn fetch(&self, _: &Uri) -> Result<Resource, Report<Self::Error>> {
        Ok(Resource {
            data: self.keys.clone().into(),
            max_age: std::time::Duration::from_secs(60),
        })
    }
}

/// Mock and test correct token verification
#[tokio::test]
async fn test_verify_correct_token() {
    let issued_at = OffsetDateTime::now_utc()
        .replace_microsecond(0)
        .unwrap()
        .replace_millisecond(0)
        .unwrap();
    let valid_until = issued_at + Duration::days(1);
    let project_id = String::from("test_project");

    let (encoded_token, cert) = generate_test_token(
        TokenHeader {
            alg: JWTAlgorithm::RS256,
            kid: "123".into(),
            typ: "JWT".into(),
        },
        TokenClaims {
            exp: valid_until,
            iat: issued_at,
            aud: project_id.clone(),
            iss: format!("https://securetoken.google.com/{project_id}"),
            sub: "user123".into(),
            auth_time: issued_at,
        },
    );

    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
    let key_map: BTreeMap<String, String> =
        vec![(String::from("123"), cert_pem)].into_iter().collect();
    let key_map_json: Vec<u8> = to_string(&key_map).unwrap().as_bytes().to_vec();

    let decoded_token = JWToken::from_encoded(&encoded_token).unwrap();

    let verifier = TokenVerifier::new(
        project_id,
        CertCacheClientMock::mock(key_map_json),
    )
    .await
    .unwrap();

    verifier.verify(&decoded_token).await.unwrap();
}

/// Mock and test token with incorrect signature verification
#[tokio::test]
async fn test_verify_incorrect_token_signature_key() {
    let issued_at = OffsetDateTime::now_utc()
        .replace_microsecond(0)
        .unwrap()
        .replace_millisecond(0)
        .unwrap();
    let valid_until = issued_at + Duration::days(1);
    let project_id = String::from("test_project");

    let (encoded_token, _) = generate_test_token(
        TokenHeader {
            alg: JWTAlgorithm::RS256,
            kid: "123".into(),
            typ: "JWT".into(),
        },
        TokenClaims {
            exp: valid_until,
            iat: issued_at,
            aud: project_id.clone(),
            iss: format!("https://securetoken.google.com/{project_id}"),
            sub: "user123".into(),
            auth_time: issued_at,
        },
    );

    // Put different certificate than the one used to sign token into the cache
    let (cert, _) = generate_test_cert().unwrap();

    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
    let key_map: BTreeMap<String, String> =
        vec![(String::from("123"), cert_pem)].into_iter().collect();
    let key_map_json: Vec<u8> = to_string(&key_map).unwrap().as_bytes().to_vec();

    let decoded_token = JWToken::from_encoded(&encoded_token).unwrap();

    let verifier = TokenVerifier::new(
        project_id,
        CertCacheClientMock::mock(key_map_json),
    )
    .await
    .unwrap();

    let result = verifier.verify(&decoded_token).await;

    if let Err(err) = result {
        match err.current_context() {
            TokenVerificationError::InvalidSignature => {},
            _ => panic!("Expected invalid signature error but got {err}")
        }
    } else {
        panic!("Should not be a valid token because of incorrect certificate for signature used");
    }
}

/// Mock and test token with incorrect expiration verification
#[tokio::test]
async fn test_verify_token_expiration() {
    let issued_at = OffsetDateTime::now_utc()
        .replace_microsecond(0)
        .unwrap()
        .replace_millisecond(0)
        .unwrap();
    let valid_until = issued_at - Duration::days(1);
    let project_id = String::from("test_project");

    let (encoded_token, cert) = generate_test_token(
        TokenHeader {
            alg: JWTAlgorithm::RS256,
            kid: "123".into(),
            typ: "JWT".into(),
        },
        TokenClaims {
            exp: valid_until,
            iat: issued_at,
            aud: project_id.clone(),
            iss: format!("https://securetoken.google.com/{project_id}"),
            sub: "user123".into(),
            auth_time: issued_at,
        },
    );

    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
    let key_map: BTreeMap<String, String> =
        vec![(String::from("123"), cert_pem)].into_iter().collect();
    let key_map_json: Vec<u8> = to_string(&key_map).unwrap().as_bytes().to_vec();

    let decoded_token = JWToken::from_encoded(&encoded_token).unwrap();

    let verifier = TokenVerifier::new(
        project_id.clone(),
        CertCacheClientMock::mock(key_map_json),
    )
    .await
    .unwrap();

    let result = verifier.verify(&decoded_token).await;

    if let Err(err) = result {
        match err.current_context() {
            TokenVerificationError::Expired => {},
            _ => panic!("Expected expired token error but got {err}")
        }
    } else {
        panic!("Should not be a valid token because the token is expired");
    }

    // test with issuing date in the future
    let issued_at = issued_at + Duration::days(1);
    let valid_until = issued_at + Duration::days(1);

    let (encoded_token, cert) = generate_test_token(
        TokenHeader {
            alg: JWTAlgorithm::RS256,
            kid: "123".into(),
            typ: "JWT".into(),
        },
        TokenClaims {
            exp: valid_until,
            iat: issued_at,
            aud: project_id.clone(),
            iss: format!("https://securetoken.google.com/{project_id}"),
            sub: "user123".into(),
            auth_time: issued_at,
        },
    );

    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
    let key_map: BTreeMap<String, String> =
        vec![(String::from("123"), cert_pem)].into_iter().collect();
    let key_map_json: Vec<u8> = to_string(&key_map).unwrap().as_bytes().to_vec();

    let decoded_token = JWToken::from_encoded(&encoded_token).unwrap();

    let verifier = TokenVerifier::new(
        project_id,
        CertCacheClientMock::mock(key_map_json),
    )
    .await
    .unwrap();

    let result = verifier.verify(&decoded_token).await;

    if let Err(err) = result {
        match err.current_context() {
            TokenVerificationError::IssuedInFuture => {},
            _ => panic!("Expected token issued in the future error but got {err}")
        }
    } else {
        panic!("Should not be a valid token because the token was issued in the future");
    }
}

/// Mock and test token with incorrect claims verification
#[tokio::test]
async fn test_verify_token_claims() {
    let issued_at = OffsetDateTime::now_utc()
        .replace_microsecond(0)
        .unwrap()
        .replace_millisecond(0)
        .unwrap();
    let valid_until = issued_at + Duration::days(1);
    let project_id = String::from("test_project");

    let (encoded_token, cert) = generate_test_token(
        TokenHeader {
            alg: JWTAlgorithm::RS256,
            kid: "123".into(),
            typ: "JWT".into(),
        },
        TokenClaims {
            exp: valid_until,
            iat: issued_at,
            aud: "another_project".into(),
            iss: format!("https://securetoken.google.com/{project_id}"),
            sub: "user123".into(),
            auth_time: issued_at,
        },
    );

    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
    let key_map: BTreeMap<String, String> =
        vec![(String::from("123"), cert_pem)].into_iter().collect();
    let key_map_json: Vec<u8> = to_string(&key_map).unwrap().as_bytes().to_vec();

    let decoded_token = JWToken::from_encoded(&encoded_token).unwrap();

    let verifier = TokenVerifier::new(
        project_id.clone(),
        CertCacheClientMock::mock(key_map_json),
    )
    .await
    .unwrap();

    let result = verifier.verify(&decoded_token).await;

    if let Err(err) = result {
        match err.current_context() {
            TokenVerificationError::InvalidAudience => {},
            _ => panic!("Expected invalid audience error but got {err}")
        }
    } else {
        panic!("Should not be a valid token because the audience is invalid");
    }

    // test with wrong issuer claim
    let (encoded_token, cert) = generate_test_token(
        TokenHeader {
            alg: JWTAlgorithm::RS256,
            kid: "123".into(),
            typ: "JWT".into(),
        },
        TokenClaims {
            exp: valid_until,
            iat: issued_at,
            aud: project_id.clone(),
            iss: "https://securetoken.google.com/another_project".into(),
            sub: "user123".into(),
            auth_time: issued_at,
        },
    );

    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
    let key_map: BTreeMap<String, String> =
        vec![(String::from("123"), cert_pem)].into_iter().collect();
    let key_map_json: Vec<u8> = to_string(&key_map).unwrap().as_bytes().to_vec();

    let decoded_token = JWToken::from_encoded(&encoded_token).unwrap();

    let verifier = TokenVerifier::new(
        project_id,
        CertCacheClientMock::mock(key_map_json),
    )
    .await
    .unwrap();

    let result = verifier.verify(&decoded_token).await;

    if let Err(err) = result {
        match err.current_context() {
            TokenVerificationError::InvalidIssuer => {},
            _ => panic!("Expected invalid token issuer error but got {err}")
        }
    } else {
        panic!("Should not be a valid token because the token has invalid issuer");
    }
}