pub mod api_uri;
pub mod auth;
pub mod client;
pub mod credentials;
pub mod util;

use auth::FirebaseAuth;

#[cfg(feature = "tokens")]
use auth::token::{
    cache::{HttpCache, PubKeys},
    error::TokenVerificationError,
    EmulatedTokenVerifier, LiveTokenVerifier, GOOGLE_COOKIE_PUB_KEY_URI, GOOGLE_PUB_KEY_URI,
};
use client::ReqwestApiClient;
use credentials::emulator::EmulatorCredentials;
pub use credentials::{error::CredentialsError, Credentials};
use error_stack::{Report, ResultExt};
pub use gcp_auth::provider as credentials_provider;
use gcp_auth::TokenProvider;
use std::sync::Arc;

/// Default Firebase Auth admin manager
pub type GcpCredentials = Arc<dyn TokenProvider>;
pub type LiveAuthAdmin = FirebaseAuth<ReqwestApiClient<GcpCredentials>>;
/// Default Firebase Auth Emulator admin manager
pub type EmulatorAuthAdmin = FirebaseAuth<ReqwestApiClient<EmulatorCredentials>>;

/// Base privileged manager for Firebase
pub struct App<CredentialsT> {
    credentials: CredentialsT,
    project_id: String,
}

impl App<EmulatorCredentials> {
    /// Firebase app backend by emulator
    pub fn emulated(project_id: String) -> Self {
        Self {
            credentials: EmulatorCredentials {},
            project_id,
        }
    }

    /// Firebase authentication manager for emulator
    pub fn auth(&self, emulator_url: String) -> EmulatorAuthAdmin {
        let client = ReqwestApiClient::new(reqwest::Client::new(), self.credentials.clone());

        FirebaseAuth::emulated(emulator_url, &self.project_id, client)
    }

    /// OIDC token verifier for emulator
    #[cfg(feature = "tokens")]
    pub fn id_token_verifier(&self) -> EmulatedTokenVerifier {
        EmulatedTokenVerifier::new(self.project_id.clone())
    }
}

impl App<GcpCredentials> {
    /// Create instance of Firebase app for live project
    pub async fn live(credentials: GcpCredentials) -> Result<Self, Report<CredentialsError>> {
        Self::live_shared(credentials).await
    }

    pub async fn live_shared(
        credentials: GcpCredentials,
    ) -> Result<Self, Report<CredentialsError>> {
        let project_id = credentials
            .project_id()
            .await
            .change_context(CredentialsError::Internal)?
            .to_string();

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
    ) -> Result<
        LiveTokenVerifier<HttpCache<reqwest::Client, PubKeys>>,
        Report<TokenVerificationError>,
    > {
        let cache_client = HttpCache::new(
            reqwest::Client::new(),
            GOOGLE_PUB_KEY_URI
                .parse()
                .map_err(error_stack::Report::new)
                .change_context(TokenVerificationError::FailedGettingKeys)?,
        )
        .await
        .change_context(TokenVerificationError::FailedGettingKeys)?;

        LiveTokenVerifier::new_id_verifier(self.project_id.clone(), cache_client)
    }

    /// Create cookie token verifier
    #[cfg(feature = "tokens")]
    pub async fn cookie_token_verifier(
        &self,
    ) -> Result<
        LiveTokenVerifier<HttpCache<reqwest::Client, PubKeys>>,
        Report<TokenVerificationError>,
    > {
        let cache_client = HttpCache::new(
            reqwest::Client::new(),
            GOOGLE_COOKIE_PUB_KEY_URI
                .parse()
                .map_err(error_stack::Report::new)
                .change_context(TokenVerificationError::FailedGettingKeys)?,
        )
        .await
        .change_context(TokenVerificationError::FailedGettingKeys)?;

        LiveTokenVerifier::new_cookie_verifier(self.project_id.clone(), cache_client)
    }
}
