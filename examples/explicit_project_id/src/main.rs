/// Demonstrates App::live_with_project_id for environments where the Firebase project
/// differs from the GCP project set in GOOGLE_CLOUD_PROJECT.
///
/// Usage:
///   FIREBASE_PROJECT_ID=my-firebase-project cargo run --example explicit_project_id
use rs_firebase_admin_sdk::{
    App,
    auth::{FirebaseAuthService, UserList},
    client::ApiHttpClient,
};

async fn print_all_users<A, C>(auth_admin: &A)
where
    A: FirebaseAuthService<C>,
    C: ApiHttpClient,
{
    let mut user_page: Option<UserList> = None;
    loop {
        user_page = auth_admin.list_users(10, user_page).await.unwrap();

        if let Some(user_page) = &user_page {
            for user in &user_page.users {
                println!("User: {user:?}");
            }
        } else {
            break;
        }
    }
}

#[tokio::main]
async fn main() {
    let project_id = std::env::var("FIREBASE_PROJECT_ID")
        .expect("FIREBASE_PROJECT_ID must be set");

    // Credentials are resolved via Application Default Credentials as usual.
    // The project ID is taken from the argument instead of GOOGLE_CLOUD_PROJECT,
    // so both env vars can point to different GCP projects simultaneously.
    let app = App::live_with_project_id(&project_id).await.unwrap();
    let auth_admin = app.auth();

    print_all_users(&auth_admin).await;
}
