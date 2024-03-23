//! API URI builder interface and API path definitions

/// Firebase Auth admin REST API endpoints
pub enum FirebaseAuthRestApi {
    CreateUser,
    GetUsers,
    ListUsers,
    DeleteUser,
    DeleteUsers,
    UpdateUser,
    ImportUsers,
    CreateSessionCookie,
    SendOobCode,
}

impl From<FirebaseAuthRestApi> for &'static str {
    fn from(path: FirebaseAuthRestApi) -> Self {
        match path {
            FirebaseAuthRestApi::CreateUser => "/accounts",
            FirebaseAuthRestApi::GetUsers => "/accounts:lookup",
            FirebaseAuthRestApi::ListUsers => "/accounts:batchGet",
            FirebaseAuthRestApi::DeleteUser => "/accounts:delete",
            FirebaseAuthRestApi::DeleteUsers => "/accounts:batchDelete",
            FirebaseAuthRestApi::UpdateUser => "/accounts:update",
            FirebaseAuthRestApi::ImportUsers => "/accounts:batchCreate",
            FirebaseAuthRestApi::CreateSessionCookie => ":createSessionCookie",
            FirebaseAuthRestApi::SendOobCode => "/accounts:sendOobCode",
        }
    }
}

/// Firebase Auth emulator admin REST API endpoints
pub enum FirebaseAuthEmulatorRestApi {
    ClearUserAccounts,
    Configuration,
    OobCodes,
    SmsVerificationCodes,
}

impl From<FirebaseAuthEmulatorRestApi> for &'static str {
    fn from(path: FirebaseAuthEmulatorRestApi) -> Self {
        match path {
            FirebaseAuthEmulatorRestApi::ClearUserAccounts => "/accounts",
            FirebaseAuthEmulatorRestApi::Configuration => "/config",
            FirebaseAuthEmulatorRestApi::OobCodes => "/oobCodes",
            FirebaseAuthEmulatorRestApi::SmsVerificationCodes => "/verificationCodes",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiUriBuilder {
    root_prefix: String,
}

impl ApiUriBuilder {
    pub fn new(root_prefix: String) -> Self {
        Self { root_prefix }
    }

    pub fn build<PathT: Into<&'static str>>(&self, path: PathT) -> String {
        self.root_prefix.clone() + path.into()
    }
}
