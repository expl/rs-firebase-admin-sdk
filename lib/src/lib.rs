pub mod api_uri;
pub mod auth;
pub mod client;
pub mod credentials;
pub mod util;

use auth::{
    token::{error::TokenVerificationError, EmulatedTokenVerifier, LiveTokenVerifier},
    FirebaseAuth,
};
use client::{build_https_client, HyperApiClient, HyperClient};
pub use credentials::gcp::GcpCredentials;
use credentials::emulator::EmulatorCredentials;
use error_stack::Report;
pub use gcp_auth::CustomServiceAccount;
use http::uri::Authority;
use std::sync::Arc;

/// Default Firebase Auth admin manager
pub type LiveAuthAdmin = FirebaseAuth<HyperApiClient<GcpCredentials>>;
/// Default Firebase Auth Emulator admin manager
pub type EmulatorAuthAdmin = FirebaseAuth<HyperApiClient<EmulatorCredentials>>;

/// Base privileged manager for Firebase
pub struct App<CredentialsT> {
    credentials: Arc<CredentialsT>,
    project_id: String,
}

impl App<EmulatorCredentials> {
    pub fn emulated(project_id: String) -> Self {
        Self {
            credentials: Arc::new(EmulatorCredentials {}),
            project_id,
        }
    }

    pub fn auth(&self, emulator_auth: Authority) -> EmulatorAuthAdmin {
        let client = HyperApiClient::new(self.credentials.clone());

        FirebaseAuth::emulated(emulator_auth, &self.project_id, client)
    }

    pub fn id_token_verifier(&self) -> EmulatedTokenVerifier {
        EmulatedTokenVerifier::new(self.project_id.clone())
    }
}

impl App<GcpCredentials> {
    pub fn live(project_id: String, service_account: CustomServiceAccount) -> Self {
        Self {
            credentials: Arc::new(service_account.into()),
            project_id,
        }
    }

    pub fn auth(&self) -> LiveAuthAdmin {
        let client = HyperApiClient::new(self.credentials.clone());

        FirebaseAuth::live(&self.project_id, client)
    }

    pub async fn id_token_verifier(
        &self,
    ) -> Result<LiveTokenVerifier<HyperClient>, Report<TokenVerificationError>> {
        LiveTokenVerifier::new(self.project_id.clone(), build_https_client()).await
    }
}
