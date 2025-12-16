#[cfg(test)]
mod test;

use super::GoogleUserProject;
use google_cloud_auth::{
    credentials::{CacheableResource, CredentialsProvider, EntityTag},
    errors::CredentialsError,
};
use headers::{Authorization, HeaderMapExt};
use http::HeaderMap;

#[derive(Debug, Clone)]
pub struct EmulatorCredentials {
    pub(crate) project_id: String,
}

impl Default for EmulatorCredentials {
    fn default() -> Self {
        Self {
            project_id: std::env::var("GOOGLE_CLOUD_PROJECT").unwrap_or_else(|_| {
                std::env::var("PROJECT_ID").unwrap_or("demo-firebase-project".into())
            }),
        }
    }
}

impl CredentialsProvider for EmulatorCredentials {
    async fn headers(
        &self,
        _extensions: http::Extensions,
    ) -> Result<CacheableResource<HeaderMap>, CredentialsError> {
        let mut headers = HeaderMap::with_capacity(2);
        headers.typed_insert(Authorization::bearer("owner").expect("Should always be valid"));

        headers.typed_insert(GoogleUserProject(self.project_id.clone()));

        Ok(CacheableResource::New {
            entity_tag: EntityTag::new(),
            data: headers,
        })
    }

    async fn universe_domain(&self) -> Option<String> {
        unimplemented!("unimplemented")
    }
}
