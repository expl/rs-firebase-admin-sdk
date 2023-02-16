use super::UrlParams;

#[test]
fn test_url_params() {
    let params = vec![
        ("k".into(), "v".into()),
        ("k2".into(), "v&?".into()),
        ("k&".into(), "v&?".into()),
    ];

    assert_eq!(
        params.into_iter().into_url_params(),
        "?k=v&k2=v%26%3F&k%26=v%26%3F"
    );
}

#[test]
fn test_empty_url_params() {
    let params: Vec<(String, String)> = Vec::new();

    assert_eq!(params.into_iter().into_url_params(), "");
}