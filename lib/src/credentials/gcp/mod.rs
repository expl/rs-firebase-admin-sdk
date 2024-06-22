use super::{Credentials, CredentialsError};
use crate::GcpCredentials;
use error_stack::{Report, ResultExt};

impl Credentials for GcpCredentials {
    async fn get_access_token(&self, scopes: &[&str]) -> Result<String, Report<CredentialsError>> {
        let token = self
            .token(scopes)
            .await
            .change_context(CredentialsError::Internal)?;

        Ok(token.as_str().into())
    }
}
