use super::Claims;
use serde_json::{Value, to_string};

#[test]
fn test_claims() {
    let mut claims = Claims::default();
    claims
        .get_mut()
        .insert("foo".into(), Value::String("bar".into()));
    claims
        .get_mut()
        .insert("one".into(), Value::Number(1.into()));

    let claims_str = to_string(&claims).unwrap();

    assert_eq!("\"{\\\"foo\\\":\\\"bar\\\",\\\"one\\\":1}\"", &claims_str);
}
