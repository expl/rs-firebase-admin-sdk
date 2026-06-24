use rs_firebase_admin_sdk::{App, jwt::TokenValidator};
use std::sync::Arc;

async fn verify_token(token: String, validator: Arc<dyn TokenValidator>) {
    match validator.validate(token).await {
        Ok(token) => {
            let user_id = token.get("sub").unwrap().as_str().unwrap();
            println!("Token for user {user_id} is valid!")
        }
        Err(err) => {
            println!("Token is invalid because {err:?}!")
        }
    }
}

#[tokio::main]
async fn main() {
    // Live
    let oidc_token = std::env::var("ID_TOKEN").unwrap();
    let live_app = App::live().await.unwrap();
    let live_token_validator = live_app.token_validator().unwrap();
    verify_token(oidc_token.clone(), live_token_validator.clone()).await;

    // Emulator
    let emulator_app = App::emulated("http://emulator:9099".into());
    let emulator_token_validator = emulator_app.token_validator().unwrap();
    verify_token(oidc_token, emulator_token_validator).await;
}
