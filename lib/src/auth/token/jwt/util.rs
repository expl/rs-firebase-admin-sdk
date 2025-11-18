use super::{TokenClaims, TokenHeader, encode_jwt};
use crate::auth::token::crypto::generate_test_cert;
use openssl::{hash::MessageDigest, sign::Signer, x509::X509};

/// Utility method for generating signed RS256 JWTs to be used in tests
pub fn generate_test_token(header: TokenHeader, critical_claims: TokenClaims) -> (String, X509) {
    let (cert, key_pair) = generate_test_cert().unwrap();
    let signer = Signer::new(MessageDigest::sha256(), &key_pair).unwrap();

    (encode_jwt(&header, &critical_claims, signer).unwrap(), cert)
}
