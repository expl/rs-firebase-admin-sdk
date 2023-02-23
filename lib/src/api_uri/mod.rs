pub mod error;

use error::InvalidApiUriError;
use error_stack::{IntoReport, Report, ResultExt};
use http::uri::{Authority, Parts, PathAndQuery, Scheme, Uri};

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
    scheme: Scheme,
    authority: Authority,
    path_prefix: Option<String>,
}

impl ApiUriBuilder {
    pub fn new(scheme: Scheme, authority: Authority, path_prefix: Option<String>) -> Self {
        Self {
            scheme,
            authority,
            path_prefix,
        }
    }

    pub fn build<PathT: Into<&'static str>>(
        &self,
        path: PathT,
    ) -> Result<Uri, Report<InvalidApiUriError>> {
        let mut parts = Parts::default();
        parts.scheme = Some(self.scheme.clone());
        parts.authority = Some(self.authority.clone());
        parts.path_and_query = Some(
            PathAndQuery::from_maybe_shared(if let Some(prefix) = &self.path_prefix {
                prefix.clone() + path.into()
            } else {
                String::new() + path.into()
            })
            .into_report()
            .change_context(InvalidApiUriError)?,
        );

        Uri::from_parts(parts)
            .into_report()
            .change_context(InvalidApiUriError)
    }
}
