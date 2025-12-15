//! OAuth2 credential managers for GCP and Firebase Emulator

pub mod emulator;

use headers::{Header, HeaderName, HeaderValue};
use google_cloud_auth::credentials::{CredentialsProvider, CacheableResource};
use http::{Extensions, HeaderMap};
use error_stack::{Report, ResultExt};
use headers::HeaderMapExt;

#[derive(thiserror::Error, Debug, Clone)]
#[error("Failed to extract GCP credentials")]
pub struct GCPCredentialsError;

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

pub(crate) async fn get_project_id(
    creds: &impl CredentialsProvider
) -> Result<String, Report<GCPCredentialsError>> {
    let headers = get_headers(creds).await?;

    let user_project: GoogleUserProject = headers.typed_get()
        .ok_or(Report::new(GCPCredentialsError))?;
    
    Ok(user_project.0)
}

pub(crate) async fn get_headers(
    creds: &impl CredentialsProvider
) -> Result<HeaderMap, Report<GCPCredentialsError>> {
    let headers = creds.headers(Extensions::new())
        .await
        .change_context(GCPCredentialsError)?;

    let headers = match headers {
        CacheableResource::New { entity_tag: _, data } => data,
        _ => unreachable!()
    };

    Ok(headers)
}