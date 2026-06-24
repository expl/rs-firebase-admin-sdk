pub mod api_uri;
pub mod auth;
pub mod client;
pub mod credentials;
#[cfg(feature = "tokens")]
pub mod jwt;
pub mod util;

use auth::FirebaseAuth;
use client::ReqwestApiClient;
use credentials::{GCPCredentialsError, emulator::EmulatorCredentials, get_project_id};
use error_stack::{Report, ResultExt};
use google_cloud_auth::credentials::Builder;
pub use google_cloud_auth::credentials::{Credentials, CredentialsProvider};
use std::sync::Arc;

const FIREBASE_AUTH_SCOPES: [&str; 2] = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
];

#[derive(Debug, Clone, thiserror::Error)]
#[error("Failed to create Firebase token validator")]
pub struct FirebaseAppValidatorError;

pub enum App {
    Live {
        credentials: Credentials,
        project_id: String,
    },
    Emulated {
        credentials: EmulatorCredentials,
        url: String,
    },
}

impl App {
    pub async fn live() -> Result<Self, Report<GCPCredentialsError>> {
        let credentials: Credentials = Builder::default()
            .with_scopes(FIREBASE_AUTH_SCOPES)
            .build_access_token_credentials()
            .change_context(GCPCredentialsError)?
            .into();

        let project_id = get_project_id(&credentials)
            .await
            .change_context(GCPCredentialsError)?;

        Ok(Self::Live {
            credentials,
            project_id,
        })
    }

    pub fn live_with_project_id(project_id: String) -> Result<Self, Report<GCPCredentialsError>> {
        let credentials: Credentials = Builder::default()
            .with_scopes(FIREBASE_AUTH_SCOPES)
            .build_access_token_credentials()
            .change_context(GCPCredentialsError)?
            .into();

        Ok(Self::Live {
            credentials,
            project_id,
        })
    }

    pub fn emulated(url: String) -> Self {
        Self::Emulated {
            credentials: EmulatorCredentials::default(),
            url,
        }
    }

    pub fn auth(&self) -> FirebaseAuth<ReqwestApiClient> {
        match self {
            Self::Live {
                credentials,
                project_id,
            } => {
                let client = ReqwestApiClient::new(reqwest::Client::new(), credentials.clone());

                FirebaseAuth::live(project_id, client)
            }
            Self::Emulated { credentials, url } => {
                let client =
                    ReqwestApiClient::new(reqwest::Client::new(), credentials.clone().into());

                FirebaseAuth::emulated(url.clone(), &credentials.project_id, client)
            }
        }
    }

    #[cfg(feature = "tokens")]
    pub fn token_validator(
        &self,
    ) -> Result<Arc<dyn jwt::TokenValidator>, Report<FirebaseAppValidatorError>> {
        match self {
            Self::Live {
                credentials: _,
                project_id,
            } => jwt::LiveValidator::new_jwt_validator(project_id.clone())
                .change_context(FirebaseAppValidatorError)
                .map(|s| Arc::new(s) as Arc<dyn jwt::TokenValidator>),
            Self::Emulated {
                credentials: _,
                url: _,
            } => Ok(Arc::new(jwt::EmulatorValidator) as Arc<dyn jwt::TokenValidator>),
        }
    }

    #[cfg(feature = "tokens")]
    pub fn cookie_validator(
        &self,
    ) -> Result<Arc<dyn jwt::TokenValidator>, Report<FirebaseAppValidatorError>> {
        match self {
            Self::Live {
                credentials: _,
                project_id,
            } => jwt::LiveValidator::new_cookie_validator(project_id.clone())
                .change_context(FirebaseAppValidatorError)
                .map(|s| Arc::new(s) as Arc<dyn jwt::TokenValidator>),
            Self::Emulated {
                credentials: _,
                url: _,
            } => Ok(Arc::new(jwt::EmulatorValidator) as Arc<dyn jwt::TokenValidator>),
        }
    }
}
