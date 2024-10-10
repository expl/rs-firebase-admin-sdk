use super::{Credentials, CredentialsError};
use error_stack::Report;

#[derive(Debug, Clone)]
pub struct EmulatorCredentials {
    project_id: String,
}

impl Default for EmulatorCredentials {
    fn default() -> Self {
        Self {
            project_id: std::env::var("PROJECT_ID").unwrap_or("demo-firebase-project".into()),
        }
    }
}

impl Credentials for EmulatorCredentials {
    async fn get_access_token(&self, _scopes: &[&str]) -> Result<String, Report<CredentialsError>> {
        Ok("owner".into())
    }

    async fn get_project_id(&self) -> Result<String, Report<CredentialsError>> {
        Ok(self.project_id.clone())
    }
}
