use super::import::{PasswordHash, UserImportRecord};
use super::token::jwt::JWToken;
use super::{
    AttributeOp, Claims, FirebaseAuth, FirebaseAuthService, FirebaseEmulatorAuthService, NewUser,
    OobCode, OobCodeAction, OobCodeActionType, UserIdentifiers, UserList, UserUpdate,
};
use crate::client::ReqwestApiClient;
use crate::credentials::emulator::EmulatorCredentials;
use crate::App;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serial_test::serial;
use std::collections::BTreeMap;
use time::Duration;
use tokio;

fn get_auth_service() -> FirebaseAuth<ReqwestApiClient<EmulatorCredentials>> {
    App::emulated("demo-firebase-project".into()).auth("http://emulator:9099".parse().unwrap())
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
#[serial]
async fn test_create_session_cookie() {
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

    JWToken::from_encoded(&cookie).expect("Got invalid session cookie token");

    auth.clear_all_users().await.unwrap();
}
