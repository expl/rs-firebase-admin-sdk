use super::{I128EpochMs, StrEpochMs, StrEpochSec};
use serde_json::from_str;
use time::{Month, OffsetDateTime};

#[test]
fn test_str_epoch_ms() {
    let dt: StrEpochMs = from_str("\"1001\"").unwrap();
    let off_dt: OffsetDateTime = dt.into();

    assert_eq!(off_dt.year(), 1970);
    assert_eq!(off_dt.month(), Month::January);
    assert_eq!(off_dt.day(), 1);
    assert_eq!(off_dt.hour(), 0);
    assert_eq!(off_dt.minute(), 0);
    assert_eq!(off_dt.second(), 1);
    assert_eq!(off_dt.millisecond(), 1);
}

#[test]
fn test_str_epoch_sec() {
    let dt: StrEpochSec = from_str("\"1001\"").unwrap();
    let off_dt: OffsetDateTime = dt.into();

    assert_eq!(off_dt.year(), 1970);
    assert_eq!(off_dt.month(), Month::January);
    assert_eq!(off_dt.day(), 1);
    assert_eq!(off_dt.hour(), 0);
    assert_eq!(off_dt.minute(), 16);
    assert_eq!(off_dt.second(), 41);
    assert_eq!(off_dt.millisecond(), 0);
}

#[test]
fn test_int_epoch_ms() {
    let dt: I128EpochMs = from_str("1001").unwrap();
    let off_dt: OffsetDateTime = dt.into();

    assert_eq!(off_dt.year(), 1970);
    assert_eq!(off_dt.month(), Month::January);
    assert_eq!(off_dt.day(), 1);
    assert_eq!(off_dt.hour(), 0);
    assert_eq!(off_dt.minute(), 0);
    assert_eq!(off_dt.second(), 1);
    assert_eq!(off_dt.millisecond(), 1);
}
