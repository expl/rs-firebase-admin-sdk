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
pub use google_cloud_auth::credentials::CredentialsProvider;
use google_cloud_auth::credentials::{AccessTokenCredentials, Builder};

const FIREBASE_AUTH_SCOPES: [&str; 2] = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
];

pub type LiveAuthAdmin = FirebaseAuth<ReqwestApiClient<AccessTokenCredentials>>;
/// Default Firebase Auth Emulator admin manager
pub type EmulatorAuthAdmin = FirebaseAuth<ReqwestApiClient<EmulatorCredentials>>;

/// Base privileged manager for Firebase
pub struct App<C> {
    credentials: C,
    project_id: String,
}

impl App<EmulatorCredentials> {
    /// Firebase app backend by emulator
    pub fn emulated() -> Self {
        let credentials = EmulatorCredentials::default();
        Self {
            project_id: credentials.project_id.clone(),
            credentials,
        }
    }

    /// Firebase authentication manager for emulator
    pub fn auth(&self, emulator_url: String) -> EmulatorAuthAdmin {
        let client = ReqwestApiClient::new(reqwest::Client::new(), self.credentials.clone());

        FirebaseAuth::emulated(emulator_url, &self.credentials.project_id, client)
    }

    /// OIDC token verifier for emulator
    #[cfg(feature = "tokens")]
    pub fn id_token_verifier(&self) -> impl jwt::TokenValidator {
        jwt::EmulatorValidator
    }
}

impl App<AccessTokenCredentials> {
    /// Create instance of Firebase app for live project
    pub async fn live() -> Result<Self, Report<GCPCredentialsError>> {
        let credentials = Builder::default()
            .with_scopes(FIREBASE_AUTH_SCOPES)
            .build_access_token_credentials()
            .change_context(GCPCredentialsError)?;

        let project_id = get_project_id(&credentials)
            .await
            .change_context(GCPCredentialsError)?;

        Ok(Self {
            credentials,
            project_id,
        })
    }

    /// Create Firebase authentication manager
    pub fn auth(&self) -> LiveAuthAdmin {
        let client = ReqwestApiClient::new(reqwest::Client::new(), self.credentials.clone());

        FirebaseAuth::live(&self.project_id, client)
    }

    /// Create OIDC token verifier
    #[cfg(feature = "tokens")]
    pub async fn id_token_verifier(
        &self,
    ) -> Result<impl jwt::TokenValidator, Report<credentials::GCPCredentialsError>> {
        let project_id = credentials::get_project_id(&self.credentials).await?;

        jwt::LiveValidator::new_jwt_validator(project_id)
            .change_context(credentials::GCPCredentialsError)
    }

    // /// Create cookie token verifier
    #[cfg(feature = "tokens")]
    pub async fn cookie_token_verifier(
        &self,
    ) -> Result<impl jwt::TokenValidator, Report<credentials::GCPCredentialsError>> {
        let project_id = credentials::get_project_id(&self.credentials).await?;

        jwt::LiveValidator::new_cookie_validator(project_id)
            .change_context(credentials::GCPCredentialsError)
    }
}
