use time::OffsetDateTime;
use serde::de::{self, Visitor};
use serde::{Serialize, Serializer};
use serde::ser::Error;
use std::fmt;
use serde_json::{Value, from_str, to_string};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Claims {
    claims: BTreeMap<String, Value>
}

impl Claims {
    pub fn get(&self) -> &BTreeMap<String, Value> {
        &self.claims
    }

    pub fn get_mut(&mut self) -> &mut BTreeMap<String, Value> {
        &mut self.claims
    }
}

impl From<BTreeMap<String, Value>> for Claims {
    fn from(value: BTreeMap<String, Value>) -> Self {
        Self { claims: value }
    }
}

struct ClaimsVisitor;

impl<'de> Visitor<'de> for ClaimsVisitor {
    type Value = Claims;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string containing count of miliseconds since UNIX epoch")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: de::Error
    {
        let claims_map: BTreeMap<String, Value> = from_str(value)
            .map_err(|e| E::custom(format!("{e:?}")))?;
        
        Ok(claims_map.into())
    }
}

impl<'de> de::Deserialize<'de> for Claims {
    fn deserialize<D>(deserializer: D) -> Result<Claims, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(ClaimsVisitor)
    }
}

impl Serialize for Claims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let claim_str = to_string(self.get())
            .map_err(|e| S::Error::custom(format!("{e:?}")))?;
        serializer.serialize_str(&claim_str)
    }
}

#[derive(Debug, Clone)]
pub struct StrEpochMs {
    dt: OffsetDateTime
}

impl From<OffsetDateTime> for StrEpochMs {
    fn from(dt: OffsetDateTime) -> Self {
        Self { dt }
    }
}

impl From<StrEpochMs> for OffsetDateTime {
    fn from(value: StrEpochMs) -> Self {
        value.dt
    }
}

struct StrEpochMsVisitor;

impl<'de> Visitor<'de> for StrEpochMsVisitor {
    type Value = StrEpochMs;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string containing count of miliseconds since UNIX epoch")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: de::Error
    {
        let unix_ts_ms: i128 = value.parse()
            .map_err(|e| E::custom(format!("{e:?}")))?;

        let off_dt = OffsetDateTime::from_unix_timestamp_nanos(
            unix_ts_ms * 1000000
        )
            .map_err(|e| E::custom(format!("{e:?}")))?;

        Ok(off_dt.into())
    }
}

impl<'de> de::Deserialize<'de> for StrEpochMs {
    fn deserialize<D>(deserializer: D) -> Result<StrEpochMs, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(StrEpochMsVisitor)
    }
}

#[derive(Debug, Clone)]
pub struct StrEpochSec {
    dt: OffsetDateTime
}

impl From<OffsetDateTime> for StrEpochSec {
    fn from(dt: OffsetDateTime) -> Self {
        Self { dt }
    }
}

impl From<StrEpochSec> for OffsetDateTime {
    fn from(value: StrEpochSec) -> Self {
        value.dt
    }
}

struct StrEpochSecVisitor;

impl<'de> Visitor<'de> for StrEpochSecVisitor {
    type Value = StrEpochSec;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string containing count of seconds since UNIX epoch")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: de::Error
    {
        let unix_ts: i64 = value.parse()
            .map_err(|e| E::custom(format!("{e:?}")))?;

        let off_dt = OffsetDateTime::from_unix_timestamp(unix_ts)
            .map_err(|e| E::custom(format!("{e:?}")))?;

        Ok(off_dt.into())
    }
}

impl<'de> de::Deserialize<'de> for StrEpochSec {
    fn deserialize<D>(deserializer: D) -> Result<StrEpochSec, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(StrEpochSecVisitor)
    }
}

#[derive(Debug, Clone)]
pub struct I128EpochMs {
    dt: OffsetDateTime
}

impl From<OffsetDateTime> for I128EpochMs {
    fn from(dt: OffsetDateTime) -> Self {
        Self { dt }
    }
}

impl From<I128EpochMs> for OffsetDateTime {
    fn from(value: I128EpochMs) -> Self {
        value.dt
    }
}

struct I128EpochMsVisitor;

impl<'de> Visitor<'de> for I128EpochMsVisitor {
    type Value = I128EpochMs;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an integer containing count of miliseconds since UNIX epoch")
    }

    fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
    where E: de::Error
    {
        let off_dt = OffsetDateTime::from_unix_timestamp_nanos(
            value * 1000000
        )
            .map_err(|e| E::custom(format!("{e:?}")))?;

        Ok(off_dt.into())
    }
}

impl<'de> de::Deserialize<'de> for I128EpochMs {
    fn deserialize<D>(deserializer: D) -> Result<I128EpochMs, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_i128(I128EpochMsVisitor)
    }
}