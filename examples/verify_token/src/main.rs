use rs_firebase_admin_sdk::{App, jwt::TokenValidator};

async fn verify_token<T: TokenValidator>(token: &str, validator: &T) {
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
    let live_token_validator = live_app.id_token_verifier().await.unwrap();
    verify_token(&oidc_token, &live_token_validator).await;

    // Emulator
    let emulator_app = App::emulated();
    let emulator_token_validator = emulator_app.id_token_verifier();
    verify_token(&oidc_token, &emulator_token_validator).await;
}
