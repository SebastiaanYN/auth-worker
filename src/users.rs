use openidconnect::core::CoreUserInfoClaims;
use serde::{Deserialize, Serialize};

mod upsert;

pub use upsert::upsert_user;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub identities: Vec<()>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_password_reset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logins_count: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub multifactor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_verified: Option<bool>,
}

impl User {
    pub fn default_with_id(id: String) -> Self {
        Self {
            id,

            email: None,
            email_verified: None,

            family_name: None,
            given_name: None,
            username: None,
            name: None,
            nickname: None,

            picture: None,

            created_at: None,
            updated_at: None,

            blocked: None,
            identities: Vec::new(),

            last_ip: None,
            last_login: None,
            last_password_reset: None,
            logins_count: None,

            multifactor: None,
            phone_number: None,
            phone_verified: None,
        }
    }

    pub fn from_claims(provider: &str, claims: CoreUserInfoClaims) -> Self {
        Self {
            id: format!("{provider}|{}", claims.subject().to_string()),

            email: claims.email().map(|x| x.to_string()),
            email_verified: claims.email_verified(),

            family_name: claims
                .family_name()
                .and_then(|x| x.get(None))
                .map(|x| x.to_string()),
            given_name: claims
                .given_name()
                .and_then(|x| x.get(None))
                .map(|x| x.to_string()),
            username: claims.preferred_username().map(|x| x.to_string()),
            name: claims
                .name()
                .and_then(|x| x.get(None))
                .map(|x| x.to_string()),
            nickname: claims
                .nickname()
                .and_then(|x| x.get(None))
                .map(|x| x.to_string()),

            picture: claims
                .picture()
                .and_then(|x| x.get(None))
                .map(|x| x.to_string()),

            created_at: None,
            updated_at: None,

            blocked: None,
            identities: Vec::new(),

            last_ip: None,
            last_login: None,
            last_password_reset: None,
            logins_count: None,

            multifactor: None,
            phone_number: claims.phone_number().map(|x| x.to_string()),
            phone_verified: claims.phone_number_verified(),
        }
    }
}
