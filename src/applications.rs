use std::collections::HashSet;

use oauth2::{ClientId, ClientSecret, Scope};
use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::OsRng,
};
use serde::{Deserialize, Serialize};

use crate::d1;

const CLIENT_ID_LEN: usize = 32;
const CLIENT_SECRET_LEN: usize = 64;

pub async fn verify_client_creds(
    db: &d1::Database,
    client_id: &ClientId,
    client_secret: &ClientSecret,
) -> bool {
    d1::query!(
        db,
        r#"
SELECT client_secret
FROM applications
WHERE client_id = ?
        "#,
        client_id,
    )
    .unwrap()
    .first::<ClientSecret>(Some("client_secret"))
    .await
    .unwrap()
    .map(|secret| secret.secret() == client_secret.secret())
    .unwrap_or(false)
}

pub async fn get_scopes(db: &d1::Database, client_id: &ClientId) -> Option<HashSet<Scope>> {
    d1::query!(
        db,
        r#"
SELECT scopes
FROM applications
WHERE client_id = ?
        "#,
        client_id,
    )
    .unwrap()
    .first::<String>(Some("scopes"))
    .await
    .unwrap()
    .map(|scopes| {
        scopes
            .split(' ')
            .map(|s| Scope::new(s.to_string()))
            .collect::<HashSet<_>>()
    })
}

#[derive(Deserialize)]
pub struct CreateApplication {
    name: String,
    description: Option<String>,
    redirect_uri: String,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApplicationResponse {
    client_id: String,
    client_secret: String,
}

pub async fn create_application(
    db: &d1::Database,
    data: &mut CreateApplication,
) -> CreateApplicationResponse {
    data.scopes.sort_unstable();
    let mut rng = OsRng;

    d1::query!(
        db,
        r#"
INSERT INTO applications (client_id, client_secret, redirect_uri, name, description, scopes)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING client_id, client_secret
        "#,
        Alphanumeric.sample_string(&mut rng, CLIENT_ID_LEN),
        Alphanumeric.sample_string(&mut rng, CLIENT_SECRET_LEN),
        data.redirect_uri,
        data.name,
        data.description,
        data.scopes.join(" "),
    )
    .unwrap()
    .first::<CreateApplicationResponse>(None)
    .await
    .unwrap()
    .unwrap()
}
