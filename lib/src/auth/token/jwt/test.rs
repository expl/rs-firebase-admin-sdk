use super::util::generate_test_token;
use super::{JWTAlgorithm, JWToken, TokenClaims, TokenHeader};
use serde_json::Value;
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime};

#[test]
fn test_jwt_parse() {
    let issued_at = OffsetDateTime::now_utc()
        .replace_microsecond(0)
        .unwrap()
        .replace_millisecond(0)
        .unwrap();
    let valid_until = issued_at + Duration::days(1);

    let (encoded_token, _) = generate_test_token(
        TokenHeader {
            alg: JWTAlgorithm::RS256,
            kid: Some("123".into()),
        },
        TokenClaims {
            exp: valid_until,
            iat: issued_at,
            aud: "FB aud".into(),
            iss: "FB iss".into(),
            sub: "FB sub".into(),
            auth_time: issued_at,
        },
    );
    let decoded = JWToken::from_encoded(&encoded_token).unwrap();

    assert_eq!(decoded.header.alg, JWTAlgorithm::RS256);
    assert_eq!(&decoded.header.kid, &Some("123".into()));
    assert_eq!(&decoded.critical_claims.exp, &valid_until);
    assert_eq!(&decoded.critical_claims.iat, &issued_at);
    assert_eq!(&decoded.critical_claims.auth_time, &issued_at);
    assert_eq!(&decoded.critical_claims.aud, "FB aud");
    assert_eq!(&decoded.critical_claims.iss, "FB iss");
    assert_eq!(&decoded.critical_claims.sub, "FB sub");

    let expected_all_claims: BTreeMap<String, Value> = vec![
        (
            "exp".into(),
            Value::Number(valid_until.unix_timestamp().into()),
        ),
        (
            "iat".into(),
            Value::Number(issued_at.unix_timestamp().into()),
        ),
        (
            "auth_time".into(),
            Value::Number(issued_at.unix_timestamp().into()),
        ),
        ("aud".into(), Value::String("FB aud".into())),
        ("iss".into(), Value::String("FB iss".into())),
        ("sub".into(), Value::String("FB sub".into())),
    ]
    .into_iter()
    .collect();

    assert_eq!(decoded.all_claims, expected_all_claims);
}
