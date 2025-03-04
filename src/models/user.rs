use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use std::str::FromStr;

// User struct with proper UUID serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(serialize_with = "serialize_uuid", deserialize_with = "deserialize_uuid")]
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
}

// Function to serialize Uuid to String
fn serialize_uuid<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&uuid.to_string())
}

// Function to deserialize String to Uuid
fn deserialize_uuid<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Uuid::from_str(&s).map_err(serde::de::Error::custom)
}

// Login credentials struct
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

// User registration struct
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}
