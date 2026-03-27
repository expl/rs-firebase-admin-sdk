use super::import::{PasswordHash, UserImportRecord};
#[cfg(feature = "tokens")]
// use super::token::jwt::JWToken;
use super::{
    AttributeOp, Claims, CustomTokenError, FirebaseAuth, FirebaseAuthService,
    FirebaseEmulatorAuthService, NewUser, OobCode, OobCodeAction, OobCodeActionType,
    UserIdentifiers, UserList, UserUpdate,
};
use crate::App;
use crate::client::{ApiHttpClient, ReqwestApiClient, error::ApiClientError};
use bytes::Bytes;
use error_stack::Report;
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serial_test::serial;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[cfg(feature = "tokens")]
use time::Duration;
use tokio;

fn get_auth_service() -> FirebaseAuth<ReqwestApiClient> {
    App::emulated().auth("http://emulator:9099".parse().unwrap())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginReq {
    pub email: String,
    pub password: String,
    pub return_secure_token: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResp {
    #[allow(dead_code)]
    pub id_token: String,
}

async fn _login(email: String, password: String) -> String {
    let client = reqwest::Client::builder().build().unwrap();
    let resp = client.post("http://emulator:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=123")
        .header("content-type", "application/json")
        .json(
            &LoginReq {
                email, password, return_secure_token: true
            }
        )
        .send()
        .await
        .unwrap();

    let login_resp: LoginResp = resp.json().await.unwrap();

    login_resp.id_token
}

#[tokio::test]
#[serial]
async fn test_emulator_configuration() {
    let auth = get_auth_service();

    let mut config = auth.get_emulator_configuration().await.unwrap();
    assert!(
        !config.sign_in.allow_duplicate_emails,
        "Initial setup should disallow duplicated emails, please check emulator setup."
    );

    config.sign_in.allow_duplicate_emails = true;

    let mut config = auth.patch_emulator_configuration(config).await.unwrap();
    assert!(
        config.sign_in.allow_duplicate_emails,
        "Patching emulator configuration did not work"
    );

    // reset back to initial
    config.sign_in.allow_duplicate_emails = false;
    auth.patch_emulator_configuration(config).await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_create_user() {
    let auth = get_auth_service();

    let user = auth
        .create_user(NewUser::email_and_password(
            "test@example.com".into(),
            "123ABC".into(),
        ))
        .await
        .unwrap();

    assert_eq!(
        user.email,
        Some(String::from("test@example.com")),
        "Creating new user yielded unexpected email"
    );

    auth.clear_all_users().await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_get_users() {
    let auth = get_auth_service();

    auth.create_user(NewUser::email_and_password(
        "test1@example.com".into(),
        "123ABC".into(),
    ))
    .await
    .unwrap();

    auth.create_user(NewUser::email_and_password(
        "test2@example.com".into(),
        "123ABC".into(),
    ))
    .await
    .unwrap();

    let ids = UserIdentifiers {
        email: Some(vec!["test2@example.com".into()]),
        ..Default::default()
    };

    let users = auth.get_users(ids).await.unwrap().unwrap();
    assert_eq!(users.len(), 1, "Expected a single user result");

    let user = &users[0];
    assert_eq!(
        user.email.as_ref().unwrap(),
        "test2@example.com",
        "Wrong user returned"
    );

    auth.clear_all_users().await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_list_users() {
    let auth = get_auth_service();

    for i in 1..=10 {
        auth.create_user(NewUser::email_and_password(
            format!("test{i}@example.com"),
            "123ABC".into(),
        ))
        .await
        .unwrap();
    }

    let mut user_emails: Vec<Vec<String>> = Vec::new();
    let mut user_list: Option<UserList> = None;

    loop {
        user_list = auth.list_users(3, user_list).await.unwrap();

        if let Some(user_list) = &user_list {
            user_emails.push(
                user_list
                    .users
                    .clone()
                    .into_iter()
                    .map(|u| u.email.unwrap())
                    .collect(),
            );
        } else {
            break;
        }
    }

    assert_eq!(user_emails.len(), 4);
    assert_eq!(
        (
            user_emails[0].len(),
            user_emails[1].len(),
            user_emails[2].len(),
            user_emails[3].len()
        ),
        (3, 3, 3, 1)
    );

    auth.clear_all_users().await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_get_user() {
    let auth = get_auth_service();

    auth.create_user(NewUser::email_and_password(
        "test@example.com".into(),
        "123ABC".into(),
    ))
    .await
    .unwrap();

    let ids = UserIdentifiers::builder()
        .with_email("test2@example.com".into())
        .build();

    let user = auth.get_user(ids.clone()).await.unwrap();
    assert!(user.is_none(), "Should not match any user");

    let ids = UserIdentifiers::builder()
        .with_email("test@example.com".into())
        .build();
    let user = auth.get_user(ids.clone()).await.unwrap().unwrap();
    assert_eq!(user.email.as_ref().unwrap(), "test@example.com");

    let ids = UserIdentifiers::builder()
        .with_uid(user.uid.clone())
        .build();
    let user = auth.get_user(ids.clone()).await.unwrap().unwrap();
    assert_eq!(user.email.as_ref().unwrap(), "test@example.com");

    auth.clear_all_users().await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_delete_user() {
    let auth = get_auth_service();

    let user = auth
        .create_user(NewUser::email_and_password(
            "test@example.com".into(),
            "123ABC".into(),
        ))
        .await
        .unwrap();

    auth.delete_user(user.uid.clone()).await.unwrap();

    let ids = UserIdentifiers::builder().with_uid(user.uid).build();

    let user = auth.get_user(ids).await.unwrap();
    assert!(user.is_none(), "User did not get deleted");
}

#[tokio::test]
#[serial]
async fn test_delete_users() {
    let auth = get_auth_service();

    let user = auth
        .create_user(NewUser::email_and_password(
            "test@example.com".into(),
            "123ABC".into(),
        ))
        .await
        .unwrap();
    let user2 = auth
        .create_user(NewUser::email_and_password(
            "test2@example.com".into(),
            "123ABC".into(),
        ))
        .await
        .unwrap();

    auth.delete_users(vec![user.uid.clone(), user2.uid.clone()], true)
        .await
        .unwrap();

    let ids = UserIdentifiers::builder()
        .with_uid(user.uid)
        .with_uid(user2.uid)
        .build();

    let users = auth.get_users(ids).await.unwrap();
    assert!(users.is_none(), "Users did not get deleted");
}

#[tokio::test]
#[serial]
async fn test_update_user() {
    let auth = get_auth_service();

    let user = auth
        .create_user(NewUser::email_and_password(
            "test@example.com".into(),
            "123ABC".into(),
        ))
        .await
        .unwrap();

    let mut claims = Claims::default();
    claims
        .get_mut()
        .insert("hello".into(), Value::String("world".into()));

    let update = UserUpdate::builder(user.uid.clone())
        .display_name(AttributeOp::Change("A test user".into()))
        .photo_url(AttributeOp::Change("http://localhost/me.jpg".into()))
        .phone_number(AttributeOp::Change("+1234567".into()))
        .custom_claims(claims.clone())
        .email("new@example.com".into())
        .password("ABC123".into())
        .email_verified(false)
        .disabled(true)
        .build();

    auth.update_user(update).await.unwrap();
    let user = auth
        .get_user(UserIdentifiers::builder().with_uid(user.uid).build())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(user.display_name.as_ref().unwrap(), "A test user");
    assert_eq!(user.photo_url.as_ref().unwrap(), "http://localhost/me.jpg");
    assert_eq!(user.phone_number.as_ref().unwrap(), "+1234567");
    assert_eq!(user.custom_claims.as_ref().unwrap(), &claims);
    assert_eq!(user.email.as_ref().unwrap(), "new@example.com");
    assert_eq!(user.disabled.as_ref().unwrap(), &true);
    assert_eq!(user.email_verified.as_ref().unwrap(), &false);

    let salt = user.salt.unwrap();
    let expected_password_hash = format!("fakeHash:salt={salt}:password=ABC123");
    assert_eq!(
        user.password_hash.as_ref().unwrap(),
        &expected_password_hash
    );

    let update = UserUpdate::builder(user.uid.clone())
        .display_name(AttributeOp::Delete)
        .photo_url(AttributeOp::Delete)
        .phone_number(AttributeOp::Delete)
        .build();

    auth.update_user(update).await.unwrap();
    let user = auth
        .get_user(UserIdentifiers::builder().with_uid(user.uid).build())
        .await
        .unwrap()
        .unwrap();

    assert!(user.display_name.is_none());
    assert!(user.photo_url.is_none());
    assert!(user.phone_number.is_none());

    auth.clear_all_users().await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_import_users() {
    let passwords = vec![
        PasswordHash::HmacSha512 {
            hash: "ABC".into(),
            salt: Some("123".into()),
            key: "321".into(),
        },
        PasswordHash::HmacSha256 {
            hash: "ABC".into(),
            salt: Some("123".into()),
            key: "321".into(),
        },
        PasswordHash::HmacSha1 {
            hash: "ABC".into(),
            salt: Some("123".into()),
            key: "321".into(),
        },
        PasswordHash::HmacMd5 {
            hash: "ABC".into(),
            salt: Some("123".into()),
            key: "321".into(),
        },
        PasswordHash::Sha256 {
            hash: "ABC".into(),
            salt: Some("123".into()),
            rounds: 1,
        },
        PasswordHash::Sha512 {
            hash: "ABC".into(),
            salt: Some("123".into()),
            rounds: 1,
        },
        PasswordHash::Ppkdf2Sha1 {
            hash: "ABC".into(),
            salt: Some("123".into()),
            rounds: 1,
        },
        PasswordHash::Ppkdf2Sha256 {
            hash: "ABC".into(),
            salt: Some("123".into()),
            rounds: 1,
        },
        PasswordHash::Scrypt {
            hash: "ABC".into(),
            salt: Some("123".into()),
            rounds: 1,
            key: "321".into(),
            memory_cost: 1,
            salt_separator: Some("_".into()),
        },
        PasswordHash::StandardScrypt {
            hash: "ABC".into(),
            salt: Some("123".into()),
            block_size: 8,
            parallelization: 2,
            memory_cost: 1,
            dk_len: 12,
        },
    ];

    let mut claims = Claims::default();
    claims
        .get_mut()
        .insert("foo".into(), Value::String("bar".into()));

    let mut records: Vec<UserImportRecord> = Vec::with_capacity(passwords.len());
    for (i, password) in passwords.iter().enumerate() {
        let record = UserImportRecord::builder()
            .with_uid(i.to_string())
            .with_email(format!("{i}@example.com"), true)
            .with_display_name(format!("User {i}"))
            .with_photo_url("http://localhost/me.jpg".into())
            .with_phone_number("+123".into())
            .with_custom_claims(claims.clone())
            .with_being_disabled()
            .with_password(password.clone())
            .build();

        records.push(record);
    }

    let auth = get_auth_service();

    auth.import_users(records).await.unwrap();

    for (i, _) in passwords.iter().enumerate() {
        let user = auth
            .get_user(UserIdentifiers::builder().with_uid(i.to_string()).build())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.uid, i.to_string());
        assert_eq!(user.email.unwrap(), format!("{i}@example.com"));
        assert_eq!(user.display_name.unwrap(), format!("User {i}"));
        assert_eq!(user.photo_url.unwrap(), "http://localhost/me.jpg");
        assert_eq!(user.phone_number.unwrap(), "+123");
        assert_eq!(&user.custom_claims.unwrap(), &claims);
        assert!(user.disabled.unwrap());
        assert_eq!(user.password_hash.unwrap(), "ABC");
        assert_eq!(user.salt.unwrap(), "123");
    }

    auth.clear_all_users().await.unwrap();
}

async fn consume_oob_code(code: OobCode) {
    let mut oob_link = code.oob_link.replace("127.0.0.1", "emulator");

    if let OobCodeActionType::PasswordReset = code.request_type {
        oob_link += "&newPassword=567ABC";
    }

    println!("URL: {oob_link}");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let resp = client.get(oob_link).send().await.unwrap();
    if resp.status().is_server_error() || resp.status().is_client_error() {
        let body_str = resp.text().await.unwrap();

        panic!("{body_str}")
    }
}

#[tokio::test]
#[serial]
async fn test_generate_email_action_link() {
    let auth = get_auth_service();

    auth.create_user(NewUser::email_and_password(
        "oob@example.com".into(),
        "123ABC".into(),
    ))
    .await
    .unwrap();

    let link_pwreset = auth
        .generate_email_action_link(
            OobCodeAction::builder(OobCodeActionType::PasswordReset, "oob@example.com".into())
                .build(),
        )
        .await
        .unwrap();

    let link_email_signin = auth
        .generate_email_action_link(
            OobCodeAction::builder(OobCodeActionType::EmailSignin, "oob@example.com".into())
                .with_continue_url("http://localhost/sigin".into())
                .build(),
        )
        .await
        .unwrap();

    let link_verify_email = auth
        .generate_email_action_link(
            OobCodeAction::builder(OobCodeActionType::VerifyEmail, "oob@example.com".into())
                .build(),
        )
        .await
        .unwrap();

    let all_codes: BTreeMap<String, OobCode> = auth
        .get_oob_codes()
        .await
        .unwrap()
        .into_iter()
        .map(|c| (c.oob_link.clone(), c))
        .collect();

    for link in [link_pwreset, link_email_signin, link_verify_email] {
        let code = all_codes.get(&link).unwrap();
        consume_oob_code(code.clone()).await;
    }

    auth.clear_all_users().await.unwrap();
}

#[tokio::test]
async fn test_create_custom_token_without_signer_returns_error() {
    // Live auth (not emulated) with no signer configured — must fail.
    let auth = FirebaseAuth::live("test-project", MockIamClient::new());
    let result = auth.create_custom_token("some-uid").await;
    assert!(
        result.is_err(),
        "Expected an error when no signer is configured on a live instance"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains::<CustomTokenError>(),
        "Error should be CustomTokenError"
    );
}

#[tokio::test]
async fn test_create_custom_token_empty_uid_is_rejected() {
    let auth = get_auth_service();
    let err = auth.create_custom_token("").await.unwrap_err();
    assert!(matches!(
        err.current_context(),
        CustomTokenError::InvalidArgument(_)
    ));
}

#[tokio::test]
async fn test_create_custom_token_uid_too_long_is_rejected() {
    let auth = get_auth_service();
    let uid = "a".repeat(129);
    let err = auth.create_custom_token(&uid).await.unwrap_err();
    assert!(matches!(
        err.current_context(),
        CustomTokenError::InvalidArgument(_)
    ));
}

#[tokio::test]
async fn test_create_custom_token_claims_not_object_is_rejected() {
    let auth = get_auth_service();
    let err = auth
        .create_custom_token_with_claims("uid", Value::Array(vec![]))
        .await
        .unwrap_err();
    assert!(matches!(
        err.current_context(),
        CustomTokenError::InvalidArgument(_)
    ));
}

#[tokio::test]
async fn test_create_custom_token_blacklisted_claim_is_rejected() {
    let auth = get_auth_service();
    for reserved in ["aud", "exp", "iat", "iss", "nbf", "nonce", "jti"] {
        let claims = serde_json::json!({ reserved: "whatever" });
        let err = auth
            .create_custom_token_with_claims("uid", claims)
            .await
            .unwrap_err();
        assert!(
            matches!(err.current_context(), CustomTokenError::InvalidArgument(_)),
            "Expected InvalidArgument for reserved claim \"{reserved}\""
        );
    }
}

// uid boundary conditions

#[tokio::test]
async fn test_create_custom_token_uid_exactly_128_ascii_chars_passes_validation() {
    let auth = get_auth_service();
    let uid = "a".repeat(128);
    // Validation passes — emulated auth produces a token.
    auth.create_custom_token(&uid).await.unwrap();
}

#[tokio::test]
async fn test_create_custom_token_uid_128_unicode_chars_passes_validation() {
    let auth = get_auth_service();
    // Each '😀' is 4 bytes; 128 chars = 512 bytes — must pass char-count check
    let uid = "😀".repeat(128);
    // Validation passes — emulated auth produces a token.
    auth.create_custom_token(&uid).await.unwrap();
}

#[tokio::test]
async fn test_create_custom_token_uid_129_unicode_chars_is_rejected() {
    let auth = get_auth_service();
    let uid = "😀".repeat(129);
    let err = auth.create_custom_token(&uid).await.unwrap_err();
    assert!(
        matches!(err.current_context(), CustomTokenError::InvalidArgument(_)),
        "129 unicode chars should be rejected"
    );
}

// claims validation

#[tokio::test]
async fn test_create_custom_token_all_14_blacklisted_claims_are_rejected() {
    let auth = get_auth_service();
    let blacklisted = [
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
    for reserved in blacklisted {
        let claims = serde_json::json!({ reserved: "value" });
        let err = auth
            .create_custom_token_with_claims("uid", claims)
            .await
            .unwrap_err();
        assert!(
            matches!(err.current_context(), CustomTokenError::InvalidArgument(_)),
            "claim \"{reserved}\" should be rejected"
        );
    }
}

#[tokio::test]
async fn test_create_custom_token_valid_claims_pass_validation() {
    let auth = get_auth_service();
    let claims = serde_json::json!({ "role": "admin", "premium": true });
    // Validation passes — emulated auth produces a token.
    auth.create_custom_token_with_claims("uid", claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_custom_token_empty_claims_object_passes_validation() {
    let auth = get_auth_service();
    let claims = serde_json::json!({});
    // Validation passes — emulated auth produces a token.
    auth.create_custom_token_with_claims("uid", claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_custom_token_null_claims_rejected() {
    let auth = get_auth_service();
    let err = auth
        .create_custom_token_with_claims("uid", Value::Null)
        .await
        .unwrap_err();
    assert!(matches!(
        err.current_context(),
        CustomTokenError::InvalidArgument(_)
    ));
}

#[tokio::test]
async fn test_create_custom_token_string_claims_rejected() {
    let auth = get_auth_service();
    let err = auth
        .create_custom_token_with_claims("uid", Value::String("nope".into()))
        .await
        .unwrap_err();
    assert!(matches!(
        err.current_context(),
        CustomTokenError::InvalidArgument(_)
    ));
}

#[tokio::test]
async fn test_create_custom_token_number_claims_rejected() {
    let auth = get_auth_service();
    let err = auth
        .create_custom_token_with_claims("uid", Value::Number(42.into()))
        .await
        .unwrap_err();
    assert!(matches!(
        err.current_context(),
        CustomTokenError::InvalidArgument(_)
    ));
}

// mock IAM client

/// Captures the IAM signJwt request URL and body; returns a fake signed JWT.
struct MockIamClient {
    call_count: Arc<AtomicUsize>,
    captured_url: Arc<Mutex<Option<String>>>,
    captured_body: Arc<Mutex<Option<Value>>>,
}

impl MockIamClient {
    fn new() -> Self {
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            captured_url: Arc::new(Mutex::new(None)),
            captured_body: Arc::new(Mutex::new(None)),
        }
    }
}

impl ApiHttpClient for MockIamClient {
    async fn send_request<R: Send + serde::de::DeserializeOwned>(
        &self,
        _uri: String,
        _method: Method,
    ) -> Result<R, Report<ApiClientError>> {
        unimplemented!()
    }

    async fn send_request_with_params<
        R: serde::de::DeserializeOwned + Send,
        P: Iterator<Item = (String, String)> + Send,
    >(
        &self,
        _uri: String,
        _params: P,
        _method: Method,
    ) -> Result<R, Report<ApiClientError>> {
        unimplemented!()
    }

    async fn send_request_body<
        Req: serde::Serialize + Send,
        Resp: serde::de::DeserializeOwned + Send,
    >(
        &self,
        uri: String,
        _method: Method,
        request_body: Req,
    ) -> Result<Resp, Report<ApiClientError>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        *self.captured_url.lock().unwrap() = Some(uri);
        *self.captured_body.lock().unwrap() = Some(serde_json::to_value(&request_body).unwrap());
        let resp = serde_json::json!({ "signedJwt": "fake.jwt.token" });
        Ok(serde_json::from_value(resp).unwrap())
    }

    async fn send_request_body_get_bytes<Req: serde::Serialize + Send>(
        &self,
        _uri: String,
        _method: Method,
        _request_body: Req,
    ) -> Result<Bytes, Report<ApiClientError>> {
        unimplemented!()
    }

    async fn send_request_body_empty_response<Req: serde::Serialize + Send>(
        &self,
        _uri: String,
        _method: Method,
        _request_body: Req,
    ) -> Result<(), Report<ApiClientError>> {
        unimplemented!()
    }
}

fn make_mock_auth(
    sa_email: &str,
) -> (
    FirebaseAuth<MockIamClient>,
    Arc<AtomicUsize>,
    Arc<Mutex<Option<String>>>,
    Arc<Mutex<Option<Value>>>,
) {
    let mock = MockIamClient::new();
    let call_count = mock.call_count.clone();
    let captured_url = mock.captured_url.clone();
    let captured_body = mock.captured_body.clone();
    let auth = FirebaseAuth::live_with_signer("test-project", sa_email, mock);
    (auth, call_count, captured_url, captured_body)
}

/// Extracts and parses the `payload` JSON string from the captured IAM request body.
fn decode_captured_payload(captured_body: &Arc<Mutex<Option<Value>>>) -> Value {
    let lock = captured_body.lock().unwrap();
    let body = lock.as_ref().expect("IAM was never called");
    let payload_str = body["payload"].as_str().expect("payload field missing");
    serde_json::from_str(payload_str).expect("payload is not valid JSON")
}

// JWT payload structure

#[tokio::test]
async fn test_custom_token_payload_required_fields() {
    let sa = "signer@project.iam.gserviceaccount.com";
    let (auth, _, _, captured_body) = make_mock_auth(sa);

    let token = auth.create_custom_token("user-123").await.unwrap();
    assert_eq!(token, "fake.jwt.token");

    let payload = decode_captured_payload(&captured_body);
    assert_eq!(payload["iss"], sa);
    assert_eq!(payload["sub"], sa);
    assert_eq!(
        payload["aud"],
        "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
    );
    assert_eq!(payload["uid"], "user-123");

    let iat = payload["iat"].as_u64().unwrap();
    let exp = payload["exp"].as_u64().unwrap();
    assert_eq!(exp - iat, 3600, "token lifetime must be exactly 1 hour");

    assert!(
        payload.get("claims").is_none(),
        "claims must be absent when not provided"
    );
}

#[tokio::test]
async fn test_custom_token_payload_with_claims() {
    let sa = "signer@project.iam.gserviceaccount.com";
    let (auth, _, _, captured_body) = make_mock_auth(sa);

    let claims = serde_json::json!({ "role": "admin", "tier": 2 });
    auth.create_custom_token_with_claims("user-456", claims.clone())
        .await
        .unwrap();

    let payload = decode_captured_payload(&captured_body);
    assert_eq!(payload["uid"], "user-456");
    assert_eq!(
        payload["claims"], claims,
        "claims must be nested under 'claims' key"
    );
}

#[tokio::test]
async fn test_custom_token_payload_omits_claims_when_absent() {
    let sa = "signer@project.iam.gserviceaccount.com";
    let (auth, _, _, captured_body) = make_mock_auth(sa);

    auth.create_custom_token("user-789").await.unwrap();

    let payload = decode_captured_payload(&captured_body);
    assert!(
        payload.get("claims").is_none(),
        "claims key must not be present in the payload when not provided"
    );
}

// IAM URL

#[tokio::test]
async fn test_custom_token_iam_url_contains_service_account() {
    let sa = "signer@project.iam.gserviceaccount.com";
    let (auth, _, captured_url, _) = make_mock_auth(sa);

    auth.create_custom_token("uid").await.unwrap();

    let url = captured_url.lock().unwrap().clone().unwrap();
    assert!(
        url.contains("iamcredentials.googleapis.com"),
        "must call IAM Credentials API"
    );
    assert!(url.ends_with(":signJwt"), "must use signJwt endpoint");
    // email is URL-encoded in the path (@  → %40)
    assert!(
        url.contains("signer%40project.iam.gserviceaccount.com"),
        "service account email must be URL-encoded in the IAM path"
    );
}

// call count

#[tokio::test]
async fn test_create_custom_token_calls_iam_once_per_invocation() {
    let sa = "signer@project.iam.gserviceaccount.com";
    let (auth, call_count, _, _) = make_mock_auth(sa);

    auth.create_custom_token("uid1").await.unwrap();
    auth.create_custom_token("uid2").await.unwrap();

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "IAM must be called once per create_custom_token invocation"
    );
}

#[cfg(feature = "tokens")]
#[tokio::test]
#[serial]
async fn test_create_session_cookie() {
    use crate::jwt::{EmulatorValidator, TokenValidator};
    let auth = get_auth_service();

    auth.create_user(NewUser::email_and_password(
        "test@example.com".into(),
        "123ABC".into(),
    ))
    .await
    .unwrap();

    let id_token = _login("test@example.com".into(), "123ABC".into()).await;
    let cookie = auth
        .create_session_cookie(id_token, Duration::hours(1))
        .await
        .unwrap();

    let claims = EmulatorValidator.validate(&cookie).await.unwrap();
    let email = claims.get("email").unwrap().as_str().unwrap();
    assert_eq!(email, "test@example.com");

    auth.clear_all_users().await.unwrap();
}

// emulated custom token (unsigned JWT)

#[tokio::test]
async fn test_emulated_create_custom_token_returns_unsigned_jwt() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let auth = get_auth_service();
    let token = auth.create_custom_token("test-uid").await.unwrap();

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated parts");
    assert_eq!(parts[2], "", "signature segment must be empty for alg=none");

    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "none");
    assert_eq!(header["typ"], "JWT");

    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(payload["uid"], "test-uid");
    assert_eq!(payload["iss"], "firebase-auth-emulator@example.com");
    assert_eq!(payload["sub"], "firebase-auth-emulator@example.com");
    assert_eq!(
        payload["aud"],
        "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
    );
    assert!(payload["iat"].is_number());
    assert!(payload["exp"].is_number());
    assert_eq!(
        payload["exp"].as_u64().unwrap() - payload["iat"].as_u64().unwrap(),
        3600
    );
    assert!(
        payload.get("claims").is_none(),
        "claims must be absent when not provided"
    );
}

#[tokio::test]
async fn test_emulated_create_custom_token_with_claims() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let auth = get_auth_service();
    let claims = serde_json::json!({ "role": "admin", "tier": 2 });
    let token = auth
        .create_custom_token_with_claims("uid2", claims)
        .await
        .unwrap();

    let parts: Vec<&str> = token.split('.').collect();
    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(payload["uid"], "uid2");
    assert_eq!(payload["claims"]["role"], "admin");
    assert_eq!(payload["claims"]["tier"], 2);
}
