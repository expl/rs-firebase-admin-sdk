pub mod api_uri;
pub mod auth;
pub mod client;
pub mod credentials;
pub mod util;

use auth::FirebaseAuth;

#[cfg(feature = "tokens")]
use auth::token::{
    GOOGLE_COOKIE_PUB_KEY_URI, GOOGLE_PUB_KEY_URI, LiveTokenVerifier,
    cache::{HttpCache, PubKeys},
    error::TokenVerificationError,
};
use client::ReqwestApiClient;
use credentials::{emulator::EmulatorCredentials, GCPCredentialsError, get_project_id};
use error_stack::{Report, ResultExt};
use google_cloud_auth::{credentials::{AccessTokenCredentials, Builder}};

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
    project_id: String
}

impl App<EmulatorCredentials> {
    /// Firebase app backend by emulator
    pub fn emulated() -> Self {
        let credentials = EmulatorCredentials::default();
        Self {
            project_id: credentials.project_id.clone(),
            credentials
        }
    }

    /// Firebase authentication manager for emulator
    pub fn auth(&self, emulator_url: String) -> EmulatorAuthAdmin {
        let client = ReqwestApiClient::new(reqwest::Client::new(), self.credentials.clone());

        FirebaseAuth::emulated(emulator_url, &self.credentials.project_id, client)
    }

    // /// OIDC token verifier for emulator
    // #[cfg(feature = "tokens")]
    // pub fn id_token_verifier(&self) -> EmulatedTokenVerifier {
    //     EmulatedTokenVerifier::new(self.project_id.clone())
    // }
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
        
        Ok(
            Self {
                credentials,
                project_id
            }
        )
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
