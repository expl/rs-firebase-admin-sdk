use super::{Credentials, CredentialsError};
use async_trait::async_trait;
use error_stack::{IntoReport, Report, ResultExt};
pub use gcp_auth::AuthenticationManager as GcpCredentials;

#[async_trait]
impl Credentials for GcpCredentials {
    async fn get_access_token(&self, scopes: &[&str]) -> Result<String, Report<CredentialsError>> {
        let token = self
            .get_token(scopes)
            .await
            .into_report()
            .change_context(CredentialsError::Internal)?;

        Ok(token.as_str().into())
    }
}
