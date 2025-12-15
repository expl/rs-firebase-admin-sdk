use rs_firebase_admin_sdk::{
    App,
    auth::{FirebaseAuthService, UserList},
    client::ApiHttpClient,
};

/// Generic method to print out all live users, fetch 10 at a time
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
    let live_app = App::live().await.unwrap();
    let live_auth_admin = live_app.auth();

    print_all_users(&live_auth_admin).await;

    // Emulator Firebase App
    let emulator_app = App::emulated();
    let emulator_auth_admin = emulator_app.auth("http://localhost:9099".into());

    print_all_users(&emulator_auth_admin).await;
}
