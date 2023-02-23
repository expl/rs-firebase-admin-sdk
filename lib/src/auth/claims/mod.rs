#[cfg(test)]
mod test;

use serde::de::{self, Visitor};
use serde::ser::Error;
use serde::{Serialize, Serializer};
use serde_json::{from_str, to_string, Value};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Claims {
    claims: BTreeMap<String, Value>,
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
        formatter.write_str("a string containing JSON encoded dictionary")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let claims_map: BTreeMap<String, Value> =
            from_str(value).map_err(|e| E::custom(format!("{e:?}")))?;

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
        let claim_str = to_string(self.get()).map_err(|e| S::Error::custom(format!("{e:?}")))?;
        serializer.serialize_str(&claim_str)
    }
}
