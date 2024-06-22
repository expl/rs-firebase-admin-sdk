# Firebase Admin SDK for Rust
The Firebase Admin Rust SDK enables access to Firebase services from privileged environments. Designed to be scalable and reliable with zero-overhead for performance in mind.

# Currently supports
* GCP service accounts
* User and custom authentication management
* Firebase emulator integration and management
* Firebase OIDC token and session cookie verification using asynchronous public certificate cache

# Example for interacting with Firebase on GCP
```rust
use rs_firebase_admin_sdk::{
    auth::{FirebaseAuthService, UserIdentifiers},
    client::ApiHttpClient,
    App, credentials_provider,
};

// Load your GCP SA from env, see https://crates.io/crates/gcp_auth for more details
let gcp_service_account = credentials_provider().await.unwrap();
// Create live (not emulated) context for Firebase app
let live_app = App::live(gcp_service_account.into()).await.unwrap();

// Create Firebase authentication admin client
let auth_admin = live_app.auth();

let user = auth_admin.get_user(
    // Build a filter for finding the user
    UserIdentifiers::builder()
        .with_email("me@email.com".into())
        .build()
)
.await
.expect("Error while fetching user")
.expect("User does not exist");

println!("User id: {}", user.uid);
```

For more examples please see https://github.com/expl/rs-firebase-admin-sdk/tree/main/examples