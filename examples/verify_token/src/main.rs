use rs_firebase_admin_sdk::{auth::token::TokenVerifier, App, AuthenticationManager};

async fn verify_token<T: TokenVerifier>(token: &str, verifier: &T) {
    match verifier.verify_token(token).await {
        Ok(token) => {
            let user_id = token.critical_claims.sub;
            println!("Token for user {user_id} is valid!")
        }
        Err(err) => {
            println!("Token is invalid because {err}!")
        }
    }
}

#[tokio::main]
async fn main() {
    let oidc_token = std::env::var("ID_TOKEN").unwrap();

    // Live Firebase App
    let gcp_service_account = AuthenticationManager::new().await.unwrap();
    let live_app = App::live(gcp_service_account).await.unwrap();
    let live_token_verifier = live_app.id_token_verifier().await.unwrap();
    verify_token(&oidc_token, &live_token_verifier).await;

    // Emulator Firebase App
    let emulator_app = App::emulated("my_project".into());
    let emulator_token_verifier = emulator_app.id_token_verifier();
    verify_token(&oidc_token, &emulator_token_verifier).await;
}
