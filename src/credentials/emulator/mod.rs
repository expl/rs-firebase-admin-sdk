use super::{Credentials, CredentialsError};
use async_trait::async_trait;
use error_stack::Report;

#[derive(Debug, Clone, Default)]
pub struct EmulatorCredentials;

#[async_trait]
impl Credentials for EmulatorCredentials {
    async fn get_access_token(&self, _scopes: &[&str]) -> Result<String, Report<CredentialsError>> {
        Ok("owner".into())
    }
}
