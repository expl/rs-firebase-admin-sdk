//! Firebase Identity Provider management interface

#[cfg(test)]
mod test;

pub mod claims;
pub mod import;
pub mod oob_code;

use crate::api_uri::{ApiUriBuilder, FirebaseAuthEmulatorRestApi, FirebaseAuthRestApi};
use crate::client::ApiHttpClient;
use crate::client::error::ApiClientError;
use crate::util::{I128EpochMs, StrEpochMs, StrEpochSec};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
pub use claims::Claims;
use error_stack::{Report, ResultExt};
use http::Method;
pub use import::{UserImportRecord, UserImportRecords};
use oob_code::{OobCodeAction, OobCodeActionLink, OobCodeActionType};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec;
use time::{Duration, OffsetDateTime};

const FIREBASE_AUTH_REST_AUTHORITY: &str = "identitytoolkit.googleapis.com";
const CUSTOM_TOKEN_AUDIENCE: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";
const EMULATOR_SIGNING_ACCOUNT: &str = "firebase-auth-emulator@example.com";

/// Error returned by [`FirebaseAuthService::create_custom_token`] and
/// [`FirebaseAuthService::create_custom_token_with_claims`].
#[derive(thiserror::Error, Debug, Clone)]
pub enum CustomTokenError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error(
        "No signing service account available. Deploy to Cloud Run, GCE, or GKE for \
        auto-discovery, or use App::auth_with_signer() to provide one explicitly."
    )]
    MissingServiceAccount,
    #[error(
        "Failed to discover service account email from the GCE metadata server. \
        Ensure the instance has a service account attached, or use App::auth_with_signer()."
    )]
    ServiceAccountDiscoveryFailed,
    #[error("Failed to sign custom token via IAM Credentials API")]
    SigningFailed,
}

/// JWT claim names that Firebase reserves and cannot appear in developer claims.
/// Matches the Node.js Firebase Admin SDK `BLACKLISTED_CLAIMS` list.
const BLACKLISTED_CLAIMS: &[&str] = &[
    "acr",
    "amr",
    "at_hash",
    "aud",
    "auth_time",
    "azp",
    "cnf",
    "c_hash",
    "exp",
    "iat",
    "iss",
    "jti",
    "nbf",
    "nonce",
];

fn validate_custom_token_args(
    uid: &str,
    claims: Option<&serde_json::Value>,
) -> Result<(), Report<CustomTokenError>> {
    if uid.is_empty() {
        return Err(Report::new(CustomTokenError::InvalidArgument(
            "uid must be a non-empty string".into(),
        )));
    }
    if uid.chars().count() > 128 {
        return Err(Report::new(CustomTokenError::InvalidArgument(
            "uid must be 128 characters or fewer".into(),
        )));
    }
    if let Some(claims) = claims {
        let obj = claims.as_object().ok_or_else(|| {
            Report::new(CustomTokenError::InvalidArgument(
                "claims must be a JSON object".into(),
            ))
        })?;
        for key in obj.keys() {
            if BLACKLISTED_CLAIMS.contains(&key.as_str()) {
                return Err(Report::new(CustomTokenError::InvalidArgument(format!(
                    "claim \"{key}\" is reserved and cannot be used as a developer claim"
                ))));
            }
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct SignJwtRequest {
    payload: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignJwtResponse {
    signed_jwt: String,
}

#[derive(Serialize)]
struct CustomTokenPayload<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'static str,
    iat: u64,
    exp: u64,
    uid: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<serde_json::Value>,
}

const METADATA_SERVER_ENDPOINT: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email";

/// Fetch the service account email from the GCE metadata server.
/// Works on Cloud Run, GKE, GCE, and Cloud Functions.
async fn discover_service_account_email() -> Result<String, Report<CustomTokenError>> {
    let response = reqwest::Client::new()
        .get(METADATA_SERVER_ENDPOINT)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .change_context(CustomTokenError::ServiceAccountDiscoveryFailed)?;

    if !response.status().is_success() {
        return Err(Report::new(CustomTokenError::ServiceAccountDiscoveryFailed));
    }

    response
        .text()
        .await
        .change_context(CustomTokenError::ServiceAccountDiscoveryFailed)
}

async fn sign_custom_token<C: ApiHttpClient>(
    client: &C,
    service_account_email: &str,
    uid: &str,
    claims: Option<serde_json::Value>,
) -> Result<String, Report<CustomTokenError>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .change_context(CustomTokenError::SigningFailed)?
        .as_secs();

    let payload = CustomTokenPayload {
        iss: service_account_email,
        sub: service_account_email,
        aud: CUSTOM_TOKEN_AUDIENCE,
        iat: now,
        exp: now + 3600,
        uid,
        claims,
    };

    let payload_json =
        serde_json::to_string(&payload).change_context(CustomTokenError::SigningFailed)?;

    let encoded_email = urlencoding::encode(service_account_email);
    let iam_url = format!(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{encoded_email}:signJwt"
    );

    let response: SignJwtResponse = client
        .send_request_body(
            iam_url,
            Method::POST,
            SignJwtRequest {
                payload: payload_json,
            },
        )
        .await
        .change_context(CustomTokenError::SigningFailed)?;

    Ok(response.signed_jwt)
}

/// Build an unsigned JWT (alg: "none", empty signature) for use with the Firebase Auth
/// Emulator. The emulator accepts these tokens for `signInWithCustomToken` without
/// verifying the signature, which means no IAM call or RSA key is needed in tests.
fn sign_custom_token_emulated(
    uid: &str,
    claims: Option<serde_json::Value>,
) -> Result<String, Report<CustomTokenError>> {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .change_context(CustomTokenError::SigningFailed)?
        .as_secs();

    let payload = CustomTokenPayload {
        iss: EMULATOR_SIGNING_ACCOUNT,
        sub: EMULATOR_SIGNING_ACCOUNT,
        aud: CUSTOM_TOKEN_AUDIENCE,
        iat: now,
        exp: now + 3600,
        uid,
        claims,
    };
    let payload_json =
        serde_json::to_string(&payload).change_context(CustomTokenError::SigningFailed)?;
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload_json);

    Ok(format!("{header}.{encoded_payload}."))
}

#[derive(Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct NewUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "localId")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl NewUser {
    pub fn email_and_password(email: String, password: String) -> Self {
        Self {
            uid: None,
            email: Some(email),
            password: Some(password),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProviderUserInfo {
    pub provider_id: String,
    pub email: Option<String>,
    pub phone_number: Option<String>,
    pub federated_id: Option<String>,
    pub raw_id: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[serde(rename = "localId")]
    pub uid: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub photo_url: Option<String>,
    pub phone_number: Option<String>,
    pub last_login_at: Option<StrEpochMs>,
    pub email_verified: Option<bool>,
    pub password_updated_at: Option<I128EpochMs>,
    pub valid_since: Option<StrEpochSec>,
    pub created_at: Option<StrEpochMs>,
    pub salt: Option<String>,
    pub password_hash: Option<String>,
    pub provider_user_info: Option<Vec<ProviderUserInfo>>,
    #[serde(rename = "customAttributes")]
    pub custom_claims: Option<Claims>,
    pub disabled: Option<bool>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Users {
    pub users: Option<Vec<User>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserList {
    #[serde(default)]
    pub users: Vec<User>,
    pub next_page_token: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionCookie {
    pub id_token: String,
    pub valid_duration: i64,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SessionCookie {
    pub session_cookie: String,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedUserId {
    pub provider_id: String,
    pub raw_id: String,
}

#[derive(Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserIdentifiers {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "localId")]
    pub uid: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federated_user_id: Option<FederatedUserId>,
}

impl UserIdentifiers {
    pub fn builder() -> UserIdentifiersBuilder {
        UserIdentifiersBuilder::default()
    }
}

#[derive(Clone, Default)]
pub struct UserIdentifiersBuilder {
    ids: UserIdentifiers,
}

impl UserIdentifiersBuilder {
    pub fn with_email(mut self, email: String) -> Self {
        match &mut self.ids.email {
            Some(email_vec) => email_vec.push(email),
            None => self.ids.email = Some(vec![email]),
        };

        self
    }

    pub fn with_uid(mut self, uid: String) -> Self {
        match &mut self.ids.uid {
            Some(uid_vec) => uid_vec.push(uid),
            None => self.ids.uid = Some(vec![uid]),
        };

        self
    }

    pub fn with_phone_number(mut self, pnumber: String) -> Self {
        match &mut self.ids.phone_number {
            Some(pnumber_vec) => pnumber_vec.push(pnumber),
            None => self.ids.phone_number = Some(vec![pnumber]),
        };

        self
    }

    pub fn build(self) -> UserIdentifiers {
        self.ids
    }
}

#[derive(Serialize, Debug, Clone)]
pub enum DeleteAttribute {
    #[serde(rename = "DISPLAY_NAME")]
    DisplayName,
    #[serde(rename = "PHOTO_URL")]
    PhotoUrl,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum DeleteProvider {
    Phone,
}

#[derive(Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserUpdate {
    #[serde(rename = "localId")]
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_since: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_user: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub photo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(rename = "customAttributes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_claims: Option<Claims>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_attribute: Option<Vec<DeleteAttribute>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_provider: Option<Vec<DeleteProvider>>,
}

impl UserUpdate {
    pub fn builder(uid: String) -> UserUpdateBuilder {
        UserUpdateBuilder::new(uid)
    }
}

pub struct UserUpdateBuilder {
    update: UserUpdate,
}

pub enum AttributeOp<T> {
    Change(T),
    Delete,
}

impl UserUpdateBuilder {
    pub fn new(uid: String) -> Self {
        Self {
            update: UserUpdate {
                uid,
                ..Default::default()
            },
        }
    }

    pub fn display_name(mut self, value: AttributeOp<String>) -> Self {
        match value {
            AttributeOp::Change(new_display_name) => {
                self.update.display_name = Some(new_display_name)
            }
            AttributeOp::Delete => self
                .update
                .delete_attribute
                .get_or_insert(Vec::new())
                .push(DeleteAttribute::DisplayName),
        };

        self
    }

    pub fn photo_url(mut self, value: AttributeOp<String>) -> Self {
        match value {
            AttributeOp::Change(new_photo_url) => self.update.photo_url = Some(new_photo_url),
            AttributeOp::Delete => self
                .update
                .delete_attribute
                .get_or_insert(Vec::new())
                .push(DeleteAttribute::PhotoUrl),
        };

        self
    }

    pub fn phone_number(mut self, value: AttributeOp<String>) -> Self {
        match value {
            AttributeOp::Change(new_phone_number) => {
                self.update.phone_number = Some(new_phone_number)
            }
            AttributeOp::Delete => self
                .update
                .delete_provider
                .get_or_insert(Vec::new())
                .push(DeleteProvider::Phone),
        };

        self
    }

    pub fn custom_claims(mut self, value: Claims) -> Self {
        self.update.custom_claims = Some(value);

        self
    }

    pub fn email(mut self, value: String) -> Self {
        self.update.email = Some(value);

        self
    }

    pub fn password(mut self, value: String) -> Self {
        self.update.password = Some(value);

        self
    }

    pub fn email_verified(mut self, value: bool) -> Self {
        self.update.email_verified = Some(value);

        self
    }

    pub fn disabled(mut self, is_disabled: bool) -> Self {
        self.update.disable_user = Some(is_disabled);

        self
    }

    pub fn build(self) -> UserUpdate {
        self.update
    }
}

#[derive(Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct UserId {
    #[serde(rename = "localId")]
    pub uid: String,
}

#[derive(Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct UserIds {
    #[serde(rename = "localIds")]
    pub uids: Vec<String>,
    pub force: bool,
}

pub trait FirebaseAuthService<C: ApiHttpClient>: Send + Sync + 'static {
    fn get_client(&self) -> &C;
    fn get_auth_uri_builder(&self) -> &ApiUriBuilder;

    /// Returns `true` when this instance targets the Firebase Auth Emulator.
    fn is_emulated(&self) -> bool {
        false
    }

    /// Resolve the service account email to use for custom token signing.
    ///
    /// The default implementation always returns [`CustomTokenError::MissingServiceAccount`].
    /// [`FirebaseAuth`] overrides this: it returns the explicit email set via
    /// [`App::auth_with_signer`] if available, otherwise auto-discovers it from the
    /// GCE metadata server (cached after the first call).
    fn resolve_signing_service_account(
        &self,
    ) -> impl Future<Output = Result<String, Report<CustomTokenError>>> + Send {
        async { Err(Report::new(CustomTokenError::MissingServiceAccount)) }
    }

    /// Mint a Firebase custom token for `uid` signed via the IAM Credentials API.
    ///
    /// When deployed on Cloud Run, GCE, GKE, or Cloud Functions, the signing service
    /// account is discovered automatically from the GCE metadata server. To override,
    /// use [`App::auth_with_signer`]. The service account must have the
    /// `iam.serviceAccounts.signJwt` permission (granted by
    /// `roles/iam.serviceAccountTokenCreator`).
    fn create_custom_token(
        &self,
        uid: &str,
    ) -> impl Future<Output = Result<String, Report<CustomTokenError>>> + Send {
        let uid = uid.to_string();
        let is_emulated = self.is_emulated();
        async move {
            validate_custom_token_args(&uid, None)?;
            if is_emulated {
                return sign_custom_token_emulated(&uid, None);
            }
            let sa_email = self.resolve_signing_service_account().await?;
            sign_custom_token(self.get_client(), &sa_email, &uid, None).await
        }
    }

    /// Mint a Firebase custom token for `uid` with additional developer claims,
    /// signed via the IAM Credentials API.
    ///
    /// `claims` must be a JSON object (`serde_json::Value::Object`). Any other
    /// variant will be rejected by Firebase when the token is exchanged.
    ///
    /// See [`create_custom_token`][Self::create_custom_token] for service account
    /// discovery and permission requirements.
    fn create_custom_token_with_claims(
        &self,
        uid: &str,
        claims: serde_json::Value,
    ) -> impl Future<Output = Result<String, Report<CustomTokenError>>> + Send {
        let uid = uid.to_string();
        let is_emulated = self.is_emulated();
        async move {
            validate_custom_token_args(&uid, Some(&claims))?;
            if is_emulated {
                return sign_custom_token_emulated(&uid, Some(claims));
            }
            let sa_email = self.resolve_signing_service_account().await?;
            sign_custom_token(self.get_client(), &sa_email, &uid, Some(claims)).await
        }
    }

    /// Creates a new user account with the specified properties.
    /// # Example
    /// ```rust
    /// let new_user = auth.create_user(
    ///     NewUser::email_and_password(
    ///        "test@example.com".into(),
    ///        "123ABC".into(),
    ///     )
    /// ).await.unwrap();
    /// ```
    fn create_user(
        &self,
        user: NewUser,
    ) -> impl Future<Output = Result<User, Report<ApiClientError>>> + Send {
        let client = self.get_client();
        let uri = self
            .get_auth_uri_builder()
            .build(FirebaseAuthRestApi::CreateUser);

        client.send_request_body(uri, Method::POST, user)
    }

    /// Get first user that matches given identifier filter
    /// # Example
    /// ```rust
    /// let user = auth.get_user(
    ///     UserIdentifiers {
    ///         email: Some(vec!["me@example.com".into()]),
    ///         ..Default::default()
    ///     }
    /// ).await.unwrap();
    /// ```
    fn get_user(
        &self,
        indentifiers: UserIdentifiers,
    ) -> impl Future<Output = Result<Option<User>, Report<ApiClientError>>> + Send {
        async move {
            if let Some(users) = self.get_users(indentifiers).await? {
                return Ok(users.into_iter().next());
            }

            Ok(None)
        }
    }

    /// Get all users that match a given identifier filter
    /// # Example
    /// ```rust
    /// let users = auth.get_users(
    ///     UserIdentifiers {
    ///         email: Some(vec!["me@example.com".into()]),
    ///         uid: Some(vec!["A123456".into()]),
    ///         ..Default::default()
    ///     }
    /// ).await.unwrap().unwrap();
    /// ```
    fn get_users(
        &self,
        indentifiers: UserIdentifiers,
    ) -> impl Future<Output = Result<Option<Vec<User>>, Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_client();
            let uri_builder = self.get_auth_uri_builder();

            let users: Users = client
                .send_request_body(
                    uri_builder.build(FirebaseAuthRestApi::GetUsers),
                    Method::POST,
                    indentifiers,
                )
                .await?;

            Ok(users.users)
        }
    }

    /// Fetch all users in batches of `users_per_page`, to progress pass previous page into the method's `prev`.
    /// # Example
    /// ```rust
    /// let mut user_page: Option<UserList> = None;
    /// loop {
    ///     user_page = auth.list_users(10, user_page).await.unwrap();
    ///
    ///     if let Some(user_page) = &user_page {
    ///         for user in &user_page.users {
    ///             println!("User: {user:?}");
    ///         }
    ///     } else {
    ///         break;
    ///     }
    /// }
    /// ```
    fn list_users(
        &self,
        users_per_page: usize,
        prev: Option<UserList>,
    ) -> impl Future<Output = Result<Option<UserList>, Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_client();
            let uri_builder = self.get_auth_uri_builder();
            let mut params = vec![("maxResults".to_string(), users_per_page.clone().to_string())];

            if let Some(prev) = prev {
                if let Some(next_page_token) = prev.next_page_token {
                    params.push(("nextPageToken".to_string(), next_page_token));
                } else {
                    return Ok(None);
                }
            }

            let users: UserList = client
                .send_request_with_params(
                    uri_builder.build(FirebaseAuthRestApi::ListUsers),
                    params.into_iter(),
                    Method::GET,
                )
                .await?;

            Ok(Some(users))
        }
    }

    /// Delete user with given ID
    fn delete_user(
        &self,
        uid: String,
    ) -> impl Future<Output = Result<(), Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_client();
            let uri_builder = self.get_auth_uri_builder();

            client
                .send_request_body_empty_response(
                    uri_builder.build(FirebaseAuthRestApi::DeleteUser),
                    Method::POST,
                    UserId { uid },
                )
                .await
        }
    }

    /// Delete all users with given list of IDs
    fn delete_users(
        &self,
        uids: Vec<String>,
        force: bool,
    ) -> impl Future<Output = Result<(), Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_client();
            let uri_builder = self.get_auth_uri_builder();

            client
                .send_request_body_empty_response(
                    uri_builder.build(FirebaseAuthRestApi::DeleteUsers),
                    Method::POST,
                    UserIds { uids, force },
                )
                .await
        }
    }

    /// Update user with given changes
    /// # Example
    /// ```rust
    /// let update = UserUpdate::builder("ID123".into())
    ///     .display_name(AttributeOp::Change("My new name".into()))
    ///     .phone_number(AttributeOp::Delete)
    ///     .email("new@example.com".into())
    ///     .build();
    /// auth.update_user(update).await.unwrap();
    /// ```
    fn update_user(
        &self,
        update: UserUpdate,
    ) -> impl Future<Output = Result<User, Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_client();
            let uri_builder = self.get_auth_uri_builder();

            client
                .send_request_body(
                    uri_builder.build(FirebaseAuthRestApi::UpdateUser),
                    Method::POST,
                    update,
                )
                .await
        }
    }

    /// Create users in bulk
    /// # Example
    /// ```rust
    /// let records = vec![
    ///     UserImportRecord::builder()
    ///         .with_email("me@example.com".into(), true)
    ///         .with_display_name("My Name".into())
    ///         .build()
    /// ];
    /// auth.import_users(records).await.unwrap();
    /// ```
    fn import_users(
        &self,
        users: Vec<UserImportRecord>,
    ) -> impl Future<Output = Result<(), Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_client();
            let uri_builder = self.get_auth_uri_builder();

            client
                .send_request_body_empty_response(
                    uri_builder.build(FirebaseAuthRestApi::ImportUsers),
                    Method::POST,
                    UserImportRecords { users },
                )
                .await?;

            Ok(())
        }
    }

    /// Send email with OOB code action
    /// # Example
    /// ```rust
    /// let oob_action = OobCodeAction::builder(
    ///     OobCodeActionType::PasswordReset,
    ///     "me@example.com".into()
    /// ).build();
    ///
    /// let link = auth.generate_email_action_link(oob_action).await.unwrap();
    /// ```
    fn generate_email_action_link(
        &self,
        oob_action: OobCodeAction,
    ) -> impl Future<Output = Result<String, Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_client();
            let uri_builder = self.get_auth_uri_builder();

            let oob_link: OobCodeActionLink = client
                .send_request_body(
                    uri_builder.build(FirebaseAuthRestApi::SendOobCode),
                    Method::POST,
                    oob_action,
                )
                .await?;

            Ok(oob_link.oob_link)
        }
    }

    /// Create session cookie
    /// that then can be verified and parsed with `App::live().cookie_token_verifier()`
    fn create_session_cookie(
        &self,
        id_token: String,
        expires_in: Duration,
    ) -> impl Future<Output = Result<String, Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_client();
            let uri_builder = self.get_auth_uri_builder();

            let create_cookie = CreateSessionCookie {
                id_token,
                valid_duration: expires_in.whole_seconds(),
            };

            let session_cookie: SessionCookie = client
                .send_request_body(
                    uri_builder.build(FirebaseAuthRestApi::CreateSessionCookie),
                    Method::POST,
                    create_cookie,
                )
                .await?;

            Ok(session_cookie.session_cookie)
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EmulatorConfigurationSignIn {
    allow_duplicate_emails: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EmulatorConfiguration {
    sign_in: EmulatorConfigurationSignIn,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OobCode {
    pub email: String,
    pub oob_code: String,
    pub oob_link: String,
    pub request_type: OobCodeActionType,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OobCodes {
    pub oob_codes: Vec<OobCode>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SmsVerificationCode {
    pub phone_number: String,
    pub session_code: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SmsVerificationCodes {
    pub verification_codes: Vec<SmsVerificationCode>,
}

pub trait FirebaseEmulatorAuthService<ApiHttpClientT>
where
    Self: Send + Sync,
    ApiHttpClientT: ApiHttpClient + Send + Sync,
{
    fn get_emulator_client(&self) -> &ApiHttpClientT;
    fn get_emulator_auth_uri_builder(&self) -> &ApiUriBuilder;

    /// Delete all users within emulator
    fn clear_all_users(&self) -> impl Future<Output = Result<(), Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_emulator_client();
            let uri_builder = self.get_emulator_auth_uri_builder();

            let _result: BTreeMap<String, String> = client
                .send_request(
                    uri_builder.build(FirebaseAuthEmulatorRestApi::ClearUserAccounts),
                    Method::DELETE,
                )
                .await?;

            Ok(())
        }
    }

    /// Get current emulator configuration
    fn get_emulator_configuration(
        &self,
    ) -> impl Future<Output = Result<EmulatorConfiguration, Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_emulator_client();
            let uri_builder = self.get_emulator_auth_uri_builder();

            client
                .send_request(
                    uri_builder.build(FirebaseAuthEmulatorRestApi::Configuration),
                    Method::GET,
                )
                .await
        }
    }

    /// Update emulator configuration
    fn patch_emulator_configuration(
        &self,
        configuration: EmulatorConfiguration,
    ) -> impl Future<Output = Result<EmulatorConfiguration, Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_emulator_client();
            let uri_builder = self.get_emulator_auth_uri_builder();

            client
                .send_request_body(
                    uri_builder.build(FirebaseAuthEmulatorRestApi::Configuration),
                    Method::PATCH,
                    configuration,
                )
                .await
        }
    }

    /// Fetch all OOB codes within emulator
    fn get_oob_codes(
        &self,
    ) -> impl Future<Output = Result<Vec<OobCode>, Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_emulator_client();
            let uri_builder = self.get_emulator_auth_uri_builder();

            let oob_codes: OobCodes = client
                .send_request(
                    uri_builder.build(FirebaseAuthEmulatorRestApi::OobCodes),
                    Method::GET,
                )
                .await?;

            Ok(oob_codes.oob_codes)
        }
    }

    /// Fetch all SMS codes within emulator
    fn get_sms_verification_codes(
        &self,
    ) -> impl Future<Output = Result<SmsVerificationCodes, Report<ApiClientError>>> + Send {
        async move {
            let client = self.get_emulator_client();
            let uri_builder = self.get_emulator_auth_uri_builder();

            client
                .send_request(
                    uri_builder.build(FirebaseAuthEmulatorRestApi::SmsVerificationCodes),
                    Method::GET,
                )
                .await
        }
    }
}

pub struct FirebaseAuth<ApiHttpClientT> {
    client: ApiHttpClientT,
    auth_uri_builder: ApiUriBuilder,
    emulator_auth_uri_builder: Option<ApiUriBuilder>,
    /// Explicit service account email provided via `live_with_signer()`.
    signing_service_account: Option<String>,
    /// Service account email auto-discovered from the GCE metadata server.
    /// Populated lazily on the first `create_custom_token` call and cached thereafter.
    discovered_service_account: tokio::sync::OnceCell<String>,
}

impl<ApiHttpClientT> FirebaseAuth<ApiHttpClientT>
where
    ApiHttpClientT: ApiHttpClient + Send + Sync,
{
    /// Create Firebase Authentication manager for emulator
    pub fn emulated(emulator_url: String, project_id: &str, client: ApiHttpClientT) -> Self {
        let fb_auth_root = emulator_url.clone()
            + &format!("/{FIREBASE_AUTH_REST_AUTHORITY}/v1/projects/{project_id}");
        let fb_emu_root = emulator_url + &format!("/emulator/v1/projects/{project_id}");

        Self {
            client,
            auth_uri_builder: ApiUriBuilder::new(fb_auth_root),
            emulator_auth_uri_builder: Some(ApiUriBuilder::new(fb_emu_root)),
            signing_service_account: None,
            discovered_service_account: tokio::sync::OnceCell::new(),
        }
    }

    /// Create Firebase Authentication manager for live project
    pub fn live(project_id: &str, client: ApiHttpClientT) -> Self {
        let fb_auth_root = "https://".to_string()
            + FIREBASE_AUTH_REST_AUTHORITY
            + &format!("/v1/projects/{project_id}");

        Self {
            client,
            auth_uri_builder: ApiUriBuilder::new(fb_auth_root),
            emulator_auth_uri_builder: None,
            signing_service_account: None,
            discovered_service_account: tokio::sync::OnceCell::new(),
        }
    }

    /// Create Firebase Authentication manager for live project with IAM Credentials signing.
    ///
    /// `service_account_email` is the service account used to sign custom tokens via
    /// the IAM Credentials API. It must have `iam.serviceAccounts.signJwt` permission.
    pub fn live_with_signer(
        project_id: &str,
        service_account_email: &str,
        client: ApiHttpClientT,
    ) -> Self {
        let fb_auth_root = "https://".to_string()
            + FIREBASE_AUTH_REST_AUTHORITY
            + &format!("/v1/projects/{project_id}");

        Self {
            client,
            auth_uri_builder: ApiUriBuilder::new(fb_auth_root),
            emulator_auth_uri_builder: None,
            signing_service_account: Some(service_account_email.to_string()),
            discovered_service_account: tokio::sync::OnceCell::new(),
        }
    }
}

impl<ApiHttpClientT> FirebaseAuthService<ApiHttpClientT> for FirebaseAuth<ApiHttpClientT>
where
    ApiHttpClientT: ApiHttpClient + Send + Sync,
{
    fn get_client(&self) -> &ApiHttpClientT {
        &self.client
    }

    fn get_auth_uri_builder(&self) -> &ApiUriBuilder {
        &self.auth_uri_builder
    }

    fn is_emulated(&self) -> bool {
        self.emulator_auth_uri_builder.is_some()
    }

    async fn resolve_signing_service_account(&self) -> Result<String, Report<CustomTokenError>> {
        if let Some(email) = &self.signing_service_account {
            return Ok(email.clone());
        }
        // Auto-discovery is not meaningful for emulator instances.
        if self.emulator_auth_uri_builder.is_some() {
            return Err(Report::new(CustomTokenError::MissingServiceAccount));
        }
        // Discover from the GCE metadata server, cached after the first call.
        self.discovered_service_account
            .get_or_try_init(discover_service_account_email)
            .await
            .cloned()
    }
}

impl<ApiHttpClientT> FirebaseEmulatorAuthService<ApiHttpClientT> for FirebaseAuth<ApiHttpClientT>
where
    ApiHttpClientT: ApiHttpClient + Send + Sync,
{
    fn get_emulator_client(&self) -> &ApiHttpClientT {
        &self.client
    }

    fn get_emulator_auth_uri_builder(&self) -> &ApiUriBuilder {
        self.emulator_auth_uri_builder
            .as_ref()
            .expect("Auth emulator URI builder is unset")
    }
}
