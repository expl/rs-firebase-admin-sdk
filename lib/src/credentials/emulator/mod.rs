use super::{Credentials, CredentialsError};
use error_stack::Report;

#[derive(Debug, Clone, Default)]
pub struct EmulatorCredentials;

impl Credentials for EmulatorCredentials {
    async fn get_access_token(&self, _scopes: &[&str]) -> Result<String, Report<CredentialsError>> {
        Ok("owner".into())
    }
}
