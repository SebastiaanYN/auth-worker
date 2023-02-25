use serde::{Deserialize, Serialize};

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
}
