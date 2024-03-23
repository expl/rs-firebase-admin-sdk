//! OAuth2 credential managers for GCP and Firebase Emulator

pub mod emulator;
pub mod error;
pub mod gcp;

use error::CredentialsError;
use error_stack::{Report, ResultExt};
use headers::{authorization::Bearer, Authorization, HeaderMapExt};
use http::header::HeaderMap;
use std::future::Future;

pub trait Credentials: Send + Sync + 'static {
    /// Implementation for generation of OAuth2 access token
    fn get_access_token(
        &self,
        scopes: &[&str],
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

            Ok(())
        }
    }
}
