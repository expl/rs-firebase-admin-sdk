use super::jwt::{error::JWTError, JwtSigner};
use base64::{self, Engine};
use error_stack::{Report, ResultExt};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    sign::{Signer, Verifier},
    x509::{X509Name, X509},
};
use serde::de::{self, Visitor};
use std::fmt;

impl<'a> JwtSigner for Signer<'a> {
    fn sign_jwt(&mut self, header: &str, payload: &str) -> Result<String, Report<JWTError>> {
        self.update(header.as_bytes())
            .change_context(JWTError::FailedToEncode)?;
        self.update(b".").change_context(JWTError::FailedToEncode)?;
        self.update(payload.as_bytes())
            .change_context(JWTError::FailedToEncode)?;

        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            self.sign_to_vec()
                .change_context(JWTError::FailedToEncode)?,
        );

        Ok(signature)
    }
}

#[derive(Debug, Clone)]
pub struct JwtRsaPubKey {
    key: PKey<Public>,
}

impl JwtRsaPubKey {
    pub fn new(key: PKey<Public>) -> Self {
        Self { key }
    }

    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Report<ErrorStack>> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.key)?;
        verifier.update(payload)?;

        verifier.verify(signature).map_err(error_stack::Report::new)
    }
}

struct JwtRsaPubKeyVisitor;

impl<'de> Visitor<'de> for JwtRsaPubKeyVisitor {
    type Value = JwtRsaPubKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string with public key in PEM format.")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let cert = X509::from_pem(value.as_bytes()).map_err(|e| E::custom(format!("{e:?}")))?;
        let key = cert.public_key().map_err(|e| E::custom(format!("{e:?}")))?;

        Ok(JwtRsaPubKey { key })
    }
}

impl<'de> de::Deserialize<'de> for JwtRsaPubKey {
    fn deserialize<D>(deserializer: D) -> Result<JwtRsaPubKey, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(JwtRsaPubKeyVisitor)
    }
}

/// Utility method for generating x.509 certificate for testing purposes
pub fn generate_test_cert() -> Result<(X509, PKey<Private>), Report<ErrorStack>> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;

    let mut name_builder = X509Name::builder()?;
    name_builder.append_entry_by_text("C", "JP")?;
    name_builder.append_entry_by_text("O", "Firebase")?;
    name_builder.append_entry_by_text("CN", "Firebase test")?;
    let cert_name = name_builder.build();

    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(1)?;
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    cert_builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    cert_builder.set_subject_name(&cert_name)?;
    cert_builder.set_issuer_name(&cert_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}
