pub mod emulator;
pub mod error;
pub mod gcp;

use async_trait::async_trait;
use error::CredentialsError;
use error_stack::{IntoReport, Report, ResultExt};
use headers::{authorization::Bearer, Authorization, HeaderMapExt};
use http::header::HeaderMap;

#[async_trait]
pub trait Credentials {
    /// Implementation for generation of OAuth2 access token
    async fn get_access_token(&self, scopes: &[&str]) -> Result<String, Report<CredentialsError>>;

    /// Set credentials for a API request, by default use bearer authorization for passing access token
    async fn set_credentials(
        &self,
        headers: &mut HeaderMap,
        scopes: &[&str],
    ) -> Result<(), Report<CredentialsError>> {
        let token = self.get_access_token(scopes).await?;

        headers.typed_insert(
            Authorization::<Bearer>::bearer(&token)
                .into_report()
                .change_context(CredentialsError::InvalidAccessToken)?,
        );

        Ok(())
    }
}
