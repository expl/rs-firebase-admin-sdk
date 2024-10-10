//! OAuth2 credential managers for GCP and Firebase Emulator

pub mod emulator;
pub mod error;
pub mod gcp;

#[cfg(test)]
mod test;

use error::CredentialsError;
use error_stack::{Report, ResultExt};
use headers::{authorization::Bearer, Authorization, HeaderMapExt};
use headers::{Header, HeaderName, HeaderValue};
use http::header::HeaderMap;
use std::future::Future;

static X_GOOG_USER_PROJECT: HeaderName = HeaderName::from_static("x-goog-user-project");

pub struct GoogleUserProject(String);

impl Header for GoogleUserProject {
    fn name() -> &'static HeaderName {
        &X_GOOG_USER_PROJECT
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values
            .next()
            .ok_or_else(headers::Error::invalid)?
            .as_bytes();

        match std::str::from_utf8(value) {
            Ok(v) => Ok(Self(v.into())),
            Err(_) => Err(headers::Error::invalid()),
        }
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let value = HeaderValue::from_str(&self.0).unwrap_or_else(|_| HeaderValue::from_static(""));

        values.extend(std::iter::once(value));
    }
}

pub trait Credentials: Send + Sync + 'static {
    /// Implementation for generation of OAuth2 access token
    fn get_access_token(
        &self,
        scopes: &[&str],
    ) -> impl Future<Output = Result<String, Report<CredentialsError>>> + Send;

    /// Implementation for getting GCP project id
    fn get_project_id(
        &self,
    ) -> impl Future<Output = Result<String, Report<CredentialsError>>> + Send;

    /// Set credentials for a API request, by default use bearer authorization for passing access token
    fn set_credentials(
        &self,
        headers: &mut HeaderMap,
        scopes: &[&str],
    ) -> impl Future<Output = Result<(), Report<CredentialsError>>> + Send {
        async move {
            let token = self.get_access_token(scopes).await?;

            headers.typed_insert(
                Authorization::<Bearer>::bearer(&token)
                    .change_context(CredentialsError::InvalidAccessToken)?,
            );

            headers.typed_insert(GoogleUserProject(self.get_project_id().await?));

            Ok(())
        }
    }
}
