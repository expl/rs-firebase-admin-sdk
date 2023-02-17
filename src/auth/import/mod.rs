use super::Claims;
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub enum HashAlgorithmName {
    #[serde(rename = "HMAC_SHA512")]
    HmacSha512,
    #[serde(rename = "HMAC_SHA256")]
    HmacSha256,
    #[serde(rename = "HMAC_SHA1")]
    HmacSha1,
    #[serde(rename = "HMAC_MD5")]
    HmacMd5,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
    #[serde(rename = "PBKDF_SHA1")]
    Ppkdf2Sha1,
    #[serde(rename = "PBKDF_SHA256")]
    Ppkdf2Sha256,
    #[serde(rename = "SCRYPT")]
    Scrypt,
    #[serde(rename = "STANDARD_SCRYPT")]
    StandardScrypt,
    #[serde(rename = "BCRYPT")]
    Bcrypt,
}

pub enum PasswordHash {
    HmacSha512 {
        hash: String,
        salt: Option<String>,
        key: String,
    },
    HmacSha256 {
        hash: String,
        salt: Option<String>,
        key: String,
    },
    HmacSha1 {
        hash: String,
        salt: Option<String>,
        key: String,
    },
    HmacMd5 {
        hash: String,
        salt: Option<String>,
        key: String,
    },
    Sha256 {
        hash: String,
        salt: Option<String>,
        rounds: u32,
    },
    Sha512 {
        hash: String,
        salt: Option<String>,
        rounds: u32,
    },
    Ppkdf2Sha1 {
        hash: String,
        salt: Option<String>,
        rounds: u32,
    },
    Ppkdf2Sha256 {
        hash: String,
        salt: Option<String>,
        rounds: u32,
    },
    Scrypt {
        hash: String,
        salt: Option<String>,
        key: String,
        rounds: u32,
        memory_cost: u8,
        salt_separator: Option<String>,
    },
    StandardScrypt {
        hash: String,
        salt: Option<String>,
        block_size: usize,
        parallelization: usize,
        memory_cost: u8,
        dk_len: usize,
    },
    Bcrypt {
        hash: String,
        salt: Option<String>,
    },
}

#[derive(Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserImportRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "localId")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub photo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<HashAlgorithmName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_cost: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelization: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dk_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rounds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_separator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "customAttributes")]
    pub custom_claims: Option<Claims>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

#[derive(Clone, Default)]
pub struct UserImportRecordBuilder {
    record: UserImportRecord,
}

impl UserImportRecordBuilder {
    pub fn with_password(mut self, password: PasswordHash) -> Self {
        match password {
            PasswordHash::HmacSha512 { hash, salt, key } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::HmacSha512);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.signer_key = Some(key);
            }
            PasswordHash::HmacSha256 { hash, salt, key } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::HmacSha256);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.signer_key = Some(key);
            }
            PasswordHash::HmacSha1 { hash, salt, key } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::HmacSha1);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.signer_key = Some(key);
            }
            PasswordHash::HmacMd5 { hash, salt, key } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::HmacMd5);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.signer_key = Some(key);
            }
            PasswordHash::Sha256 { hash, salt, rounds } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::Sha256);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.rounds = Some(rounds);
            }
            PasswordHash::Sha512 { hash, salt, rounds } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::Sha512);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.rounds = Some(rounds);
            }
            PasswordHash::Ppkdf2Sha1 { hash, salt, rounds } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::Ppkdf2Sha1);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.rounds = Some(rounds);
            }
            PasswordHash::Ppkdf2Sha256 { hash, salt, rounds } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::Ppkdf2Sha256);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.rounds = Some(rounds);
            }
            PasswordHash::Scrypt {
                hash,
                salt,
                rounds,
                key,
                memory_cost,
                salt_separator,
            } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::Scrypt);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.rounds = Some(rounds);
                self.record.signer_key = Some(key);
                self.record.memory_cost = Some(memory_cost);
                self.record.salt_separator = salt_separator;
            }
            PasswordHash::StandardScrypt {
                hash,
                salt,
                memory_cost,
                block_size,
                parallelization,
                dk_len,
            } => {
                self.record.hash_algorithm = Some(HashAlgorithmName::StandardScrypt);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
                self.record.memory_cost = Some(memory_cost);
                self.record.block_size = Some(block_size);
                self.record.parallelization = Some(parallelization);
                self.record.dk_len = Some(dk_len);
            }
            PasswordHash::Bcrypt { hash, salt} => {
                self.record.hash_algorithm = Some(HashAlgorithmName::Bcrypt);
                self.record.password_hash = Some(hash);
                self.record.salt = salt;
            }
        }

        self
    }
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserImportRecords {
    pub users: Vec<UserImportRecords>,
}
