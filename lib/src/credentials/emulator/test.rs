use super::{EmulatorCredentials, super::GoogleUserProject};
use google_cloud_auth::credentials::{CredentialsProvider, CacheableResource};
use headers::{Authorization, HeaderMapExt, authorization::Bearer};
use http::Extensions;

#[tokio::test]
async fn test_credentials() {
    let creds = EmulatorCredentials::default();
    let headers = match creds.headers(Extensions::new()).await.unwrap() {
        CacheableResource::New { entity_tag: _, data } => data,
        _ => unreachable!() 
    };

    let project_id: GoogleUserProject = headers.typed_get().unwrap();
    let token: Authorization<Bearer> = headers.typed_get().unwrap();

    assert_eq!("demo-firebase-project", project_id.0);
    assert_eq!("owner", token.token());
}
