#[cfg(test)]
mod test;

pub mod claims;
pub mod import;

use crate::api_uri::{ApiUriBuilder, FirebaseAuthEmulatorRestApi, FirebaseAuthRestApi};
use crate::client::error::ApiClientError;
use crate::client::ApiHttpClient;
use crate::util::{I128EpochMs, StrEpochMs, StrEpochSec};
use async_trait::async_trait;
pub use claims::Claims;
use error_stack::{Report, ResultExt};
use http::uri::{Authority, Scheme};
use hyper::Method;
pub use import::{UserImportRecord, UserImportRecords};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::vec;
use time::OffsetDateTime;

const FIREBASE_AUTH_REST_AUTHORITY: &str = "identitytoolkit.googleapis.com";

const FIREBASE_AUTH_SCOPES: [&str; 2] = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
];

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
    pub users: Vec<User>,
    pub next_page_token: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionCookie {
    pub id_token: String,
    pub valid_duration: u32,
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

#[async_trait]
pub trait FirebaseAuthService<ApiHttpClientT>
where
    Self: Send + Sync,
    ApiHttpClientT: ApiHttpClient + Send + Sync,
{
    fn get_client(&self) -> &ApiHttpClientT;
    fn get_auth_uri_builder(&self) -> &ApiUriBuilder;

    async fn create_user(&self, user: NewUser) -> Result<User, Report<ApiClientError>> {
        let client = self.get_client();
        let uri_builder = self.get_auth_uri_builder();

        client
            .send_request_body(
                uri_builder
                    .build(FirebaseAuthRestApi::CreateUser)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::POST,
                user,
                &FIREBASE_AUTH_SCOPES,
            )
            .await
    }

    async fn get_user(
        &self,
        indentifiers: UserIdentifiers,
    ) -> Result<Option<User>, Report<ApiClientError>> {
        if let Some(users) = self.get_users(indentifiers).await? {
            return Ok(users.into_iter().next());
        }

        Ok(None)
    }

    async fn get_users(
        &self,
        indentifiers: UserIdentifiers,
    ) -> Result<Option<Vec<User>>, Report<ApiClientError>> {
        let client = self.get_client();
        let uri_builder = self.get_auth_uri_builder();

        let users: Users = client
            .send_request_body(
                uri_builder
                    .build(FirebaseAuthRestApi::GetUsers)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::POST,
                indentifiers,
                &FIREBASE_AUTH_SCOPES,
            )
            .await?;

        Ok(users.users)
    }

    async fn list_users(
        &self,
        users_per_page: usize,
        prev: Option<UserList>,
    ) -> Result<Option<UserList>, Report<ApiClientError>> {
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
                uri_builder
                    .build(FirebaseAuthRestApi::ListUsers)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                params.into_iter(),
                Method::GET,
                &FIREBASE_AUTH_SCOPES,
            )
            .await?;

        Ok(Some(users))
    }

    async fn delete_user(&self, uid: String) -> Result<(), Report<ApiClientError>> {
        let client = self.get_client();
        let uri_builder = self.get_auth_uri_builder();

        client
            .send_request_body_empty_response(
                uri_builder
                    .build(FirebaseAuthRestApi::DeleteUser)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::POST,
                UserId { uid },
                &FIREBASE_AUTH_SCOPES,
            )
            .await
    }

    async fn delete_users(
        &self,
        uids: Vec<String>,
        force: bool,
    ) -> Result<(), Report<ApiClientError>> {
        let client = self.get_client();
        let uri_builder = self.get_auth_uri_builder();

        client
            .send_request_body_empty_response(
                uri_builder
                    .build(FirebaseAuthRestApi::DeleteUsers)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::POST,
                UserIds { uids, force },
                &FIREBASE_AUTH_SCOPES,
            )
            .await
    }

    async fn update_user(&self, update: UserUpdate) -> Result<User, Report<ApiClientError>> {
        let client = self.get_client();
        let uri_builder = self.get_auth_uri_builder();

        client
            .send_request_body(
                uri_builder
                    .build(FirebaseAuthRestApi::UpdateUser)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::POST,
                update,
                &FIREBASE_AUTH_SCOPES,
            )
            .await
    }

    async fn import_users(
        &self,
        users: Vec<UserImportRecord>,
    ) -> Result<(), Report<ApiClientError>> {
        let client = self.get_client();
        let uri_builder = self.get_auth_uri_builder();

        client
            .send_request_body_empty_response(
                uri_builder
                    .build(FirebaseAuthRestApi::ImportUsers)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::POST,
                UserImportRecords { users },
                &FIREBASE_AUTH_SCOPES,
            )
            .await?;

        Ok(())
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
    pub request_type: String,
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

#[async_trait]
pub trait FirebaseEmulatorAuthService<ApiHttpClientT>
where
    Self: Send + Sync,
    ApiHttpClientT: ApiHttpClient + Send + Sync,
{
    fn get_emulator_client(&self) -> &ApiHttpClientT;
    fn get_emulator_auth_uri_builder(&self) -> &ApiUriBuilder;

    async fn clear_all_users(&self) -> Result<(), Report<ApiClientError>> {
        let client = self.get_emulator_client();
        let uri_builder = self.get_emulator_auth_uri_builder();

        let _result: BTreeMap<String, String> = client
            .send_request(
                uri_builder
                    .build(FirebaseAuthEmulatorRestApi::ClearUserAccounts)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::DELETE,
                &FIREBASE_AUTH_SCOPES,
            )
            .await?;

        Ok(())
    }

    async fn get_emulator_configuration(
        &self,
    ) -> Result<EmulatorConfiguration, Report<ApiClientError>> {
        let client = self.get_emulator_client();
        let uri_builder = self.get_emulator_auth_uri_builder();

        client
            .send_request(
                uri_builder
                    .build(FirebaseAuthEmulatorRestApi::Configuration)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::GET,
                &FIREBASE_AUTH_SCOPES,
            )
            .await
    }

    async fn patch_emulator_configuration(
        &self,
        configuration: EmulatorConfiguration,
    ) -> Result<EmulatorConfiguration, Report<ApiClientError>> {
        let client = self.get_emulator_client();
        let uri_builder = self.get_emulator_auth_uri_builder();

        client
            .send_request_body(
                uri_builder
                    .build(FirebaseAuthEmulatorRestApi::Configuration)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::PATCH,
                configuration,
                &FIREBASE_AUTH_SCOPES,
            )
            .await
    }

    async fn get_oob_codes(&self) -> Result<OobCodes, Report<ApiClientError>> {
        let client = self.get_emulator_client();
        let uri_builder = self.get_emulator_auth_uri_builder();

        client
            .send_request(
                uri_builder
                    .build(FirebaseAuthEmulatorRestApi::OobCodes)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::GET,
                &FIREBASE_AUTH_SCOPES,
            )
            .await
    }

    async fn get_sms_verification_codes(
        &self,
    ) -> Result<SmsVerificationCodes, Report<ApiClientError>> {
        let client = self.get_emulator_client();
        let uri_builder = self.get_emulator_auth_uri_builder();

        client
            .send_request(
                uri_builder
                    .build(FirebaseAuthEmulatorRestApi::SmsVerificationCodes)
                    .change_context(ApiClientError::FailedToSendRequest)?,
                Method::GET,
                &FIREBASE_AUTH_SCOPES,
            )
            .await
    }
}

pub struct FirebaseAuth<ApiHttpClientT> {
    client: ApiHttpClientT,
    auth_uri_builder: ApiUriBuilder,
    emulator_auth_uri_builder: Option<ApiUriBuilder>,
}

impl<ApiHttpClientT> FirebaseAuth<ApiHttpClientT>
where
    ApiHttpClientT: ApiHttpClient + Send + Sync,
{
    pub fn emulated(emulator_auth: Authority, project_id: &str, client: ApiHttpClientT) -> Self {
        Self {
            client,
            auth_uri_builder: ApiUriBuilder::new(
                Scheme::HTTP,
                emulator_auth.clone(),
                Some(format!(
                    "/{FIREBASE_AUTH_REST_AUTHORITY}/v1/projects/{project_id}"
                )),
            ),
            emulator_auth_uri_builder: Some(ApiUriBuilder::new(
                Scheme::HTTP,
                emulator_auth,
                Some(format!("/emulator/v1/projects/{project_id}")),
            )),
        }
    }

    pub fn live(project_id: &str, client: ApiHttpClientT) -> Self {
        Self {
            client,
            auth_uri_builder: ApiUriBuilder::new(
                Scheme::HTTPS,
                FIREBASE_AUTH_REST_AUTHORITY
                    .parse()
                    .expect("Failed parsing auth service authority"),
                Some(format!("/v1/projects/{project_id}")),
            ),
            emulator_auth_uri_builder: None,
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
