use rs_firebase_admin_sdk::{auth::FirebaseEmulatorAuthService, client::ApiHttpClient, App};

async fn clear_emulator<A, C>(auth_emulator_admin: &A)
where
    A: FirebaseEmulatorAuthService<C>,
    C: ApiHttpClient,
{
    println!("Deleting all users!");

    auth_emulator_admin.clear_all_users().await.unwrap();
}

#[tokio::main]
async fn main() {
    let emulator_app = App::emulated("my_project".into());
    let emulator_admin = emulator_app.auth("http://localhost:9099".into());

    clear_emulator(&emulator_admin).await;
}
