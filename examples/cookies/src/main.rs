use rs_firebase_admin_sdk::{App, auth::FirebaseAuthService, jwt::TokenValidator};
use time::Duration;

#[tokio::main]
async fn main() {
    let oidc_token = std::env::var("ID_TOKEN").unwrap();
    let live_app = App::live().await.unwrap();
    let cookie = live_app
        .auth()
        .create_session_cookie(oidc_token, Duration::seconds(60 * 60))
        .await
        .unwrap();

    let live_cookie_validator = live_app.cookie_token_verifier().await.unwrap();

    live_cookie_validator.validate(&cookie).await.unwrap();
}
