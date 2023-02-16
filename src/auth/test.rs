
use crate::App;
use super::{
    FirebaseAuth, 
    NewUser,
    UserIdentifiers,
    UserUpdate,
    AttributeOp,
    Claims,
    FirebaseAuthService, 
    FirebaseEmulatorAuthService,
    UserList
};
use crate::client::HyperApiClient;
use crate::credentials::emulator::EmulatorCredentials;
use serial_test::serial;
use serde_json::Value;
use tokio;

fn get_auth_service() -> FirebaseAuth<HyperApiClient<EmulatorCredentials>> {
    App::emulated("demo-firebase-project".into())
        .auth("emulator:9099".parse().unwrap())
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

    let user = auth.create_user(
        NewUser::email_and_password("test@example.com".into(), "123ABC".into())
    ).await.unwrap();

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

    auth.create_user(
        NewUser::email_and_password("test1@example.com".into(), "123ABC".into())
    ).await.unwrap();

    auth.create_user(
        NewUser::email_and_password("test2@example.com".into(), "123ABC".into())
    ).await.unwrap();

    let ids = UserIdentifiers {
        email: Some(vec!["test2@example.com".into()]),
        ..Default::default()
    };

    let users = auth.get_users(ids).await.unwrap().unwrap();
    assert_eq!(users.len(), 1, "Expected a single user result");

    let user = &users[0];
    assert_eq!(user.email.as_ref().unwrap(), "test2@example.com", "Wrong user returned");

    auth.clear_all_users().await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_list_users() {
    let auth = get_auth_service();

    for i in 1..=10 {
        auth.create_user(
            NewUser::email_and_password(format!("test{i}@example.com"), "123ABC".into())
        ).await.unwrap();
    }

    let mut user_emails: Vec<Vec<String>> = Vec::new();
    let mut user_list: Option<UserList> = None;

    loop {
        user_list = auth.list_users(3, user_list).await.unwrap();

        if let Some(user_list) = &user_list {
            user_emails.push(
                user_list.users
                    .iter()
                    .map(|u| u.email.as_ref().unwrap().clone())
                    .collect()
                );
        } else {
            break;
        }
    }

    assert_eq!(user_emails.len(), 4);
    assert_eq!(
        (user_emails[0].len(), user_emails[1].len(), user_emails[2].len(), user_emails[3].len()),
        (3, 3, 3, 1)
    );

    auth.clear_all_users().await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_get_user() {
    let auth = get_auth_service();

    auth.create_user(
        NewUser::email_and_password("test@example.com".into(), "123ABC".into())
    ).await.unwrap();

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

    let user = auth.create_user(
        NewUser::email_and_password("test@example.com".into(), "123ABC".into())
    ).await.unwrap();

    auth.delete_user(user.uid.clone()).await.unwrap();

    let ids = UserIdentifiers::builder()
        .with_uid(user.uid)
        .build();
    
    let user = auth.get_user(ids).await.unwrap();
    assert!(user.is_none(), "User did not get deleted");
}

#[tokio::test]
#[serial]
async fn test_delete_users() {
    let auth = get_auth_service();

    let user = auth.create_user(
        NewUser::email_and_password("test@example.com".into(), "123ABC".into())
    ).await.unwrap();
    let user2 = auth.create_user(
        NewUser::email_and_password("test2@example.com".into(), "123ABC".into())
    ).await.unwrap();

    auth.delete_users(vec![user.uid.clone(), user2.uid.clone()], true).await.unwrap();

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

    let user = auth.create_user(
        NewUser::email_and_password("test@example.com".into(), "123ABC".into())
    ).await.unwrap();

    let mut claims = Claims::default();
    claims.get_mut().insert("hello".into(), Value::String("world".into()));

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
    let user = auth.get_user(
        UserIdentifiers::builder()
            .with_uid(user.uid)
            .build()
        ).await.unwrap().unwrap();
    
    assert_eq!(user.display_name.as_ref().unwrap(), "A test user");
    assert_eq!(user.photo_url.as_ref().unwrap(), "http://localhost/me.jpg");
    assert_eq!(user.phone_number.as_ref().unwrap(), "+1234567");
    assert_eq!(user.custom_claims.as_ref().unwrap(), &claims);
    assert_eq!(user.email.as_ref().unwrap(), "new@example.com");
    assert_eq!(user.disabled.as_ref().unwrap(), &true);
    assert_eq!(user.email_verified.as_ref().unwrap(), &false);

    let salt = user.salt.unwrap();
    let expected_password_hash = format!("fakeHash:salt={salt}:password=ABC123");
    assert_eq!(user.password_hash.as_ref().unwrap(), &expected_password_hash);

    let update = UserUpdate::builder(user.uid.clone())
        .display_name(AttributeOp::Delete)
        .photo_url(AttributeOp::Delete)
        .phone_number(AttributeOp::Delete)
        .build();

    auth.update_user(update).await.unwrap();
    let user = auth.get_user(
        UserIdentifiers::builder()
            .with_uid(user.uid)
            .build()
        ).await.unwrap().unwrap();
    
    assert!(user.display_name.is_none());
    assert!(user.photo_url.is_none());
    assert!(user.phone_number.is_none());

    auth.clear_all_users().await.unwrap();
}