use super::{emulator::EmulatorCredentials, Credentials, GoogleUserProject};
use headers::{authorization::Bearer, Authorization, HeaderMapExt};
use http::header::{HeaderMap, HeaderValue};

#[tokio::test]
async fn test_credentials() {
    let mut headers: HeaderMap<HeaderValue> = HeaderMap::default();
    let creds = EmulatorCredentials::default();

    creds.set_credentials(&mut headers, &[]).await.unwrap();

    let project_id: GoogleUserProject = headers.typed_get().unwrap();
    let token: Authorization<Bearer> = headers.typed_get().unwrap();

    assert_eq!("demo-firebase-project", project_id.0);
    assert_eq!("owner", token.token());
}
