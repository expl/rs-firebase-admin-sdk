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
    App,
};

// Create live (not emulated) context for Firebase app
let live_app = App::live().await.unwrap();

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

# Example with an explicit project ID
Use `App::live_with_project_id` when your Firebase project differs from the GCP project in
`GOOGLE_CLOUD_PROJECT` — for example when identity management runs in a separate project from
Cloud Storage and other infrastructure services.

```rust
use rs_firebase_admin_sdk::{
    auth::{FirebaseAuthService, UserIdentifiers},
    client::ApiHttpClient,
    App,
};

// Supply the Firebase project ID directly instead of reading GOOGLE_CLOUD_PROJECT
let live_app = App::live_with_project_id("my-firebase-project-id").await.unwrap();

let auth_admin = live_app.auth();

let user = auth_admin.get_user(
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