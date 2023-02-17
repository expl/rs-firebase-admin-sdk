pub mod api_uri;
pub mod auth;
pub mod client;
pub mod credentials;
pub mod util;

use auth::FirebaseAuth;
use client::HyperApiClient;
use credentials::{emulator::EmulatorCredentials, gcp::GcpCredentials};
pub use gcp_auth::CustomServiceAccount;
use http::uri::Authority;
use std::sync::Arc;

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

    pub fn auth(
        &self,
        emulator_auth: Authority,
    ) -> FirebaseAuth<HyperApiClient<EmulatorCredentials>> {
        let client = HyperApiClient::new(self.credentials.clone());

        FirebaseAuth::emulated(emulator_auth, &self.project_id, client)
    }
}

impl App<GcpCredentials> {
    pub fn live(project_id: String, service_account: CustomServiceAccount) -> Self {
        Self {
            credentials: Arc::new(service_account.into()),
            project_id,
        }
    }

    pub fn auth(&self) -> FirebaseAuth<HyperApiClient<GcpCredentials>> {
        let client = HyperApiClient::new(self.credentials.clone());

        FirebaseAuth::live(&self.project_id, client)
    }
}
