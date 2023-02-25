use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::OsRng,
};
use serde::{Deserialize, Serialize};

use crate::d1;

const CLIENT_ID_LEN: usize = 32;
const CLIENT_SECRET_LEN: usize = 64;

pub async fn verify_client_creds(db: &d1::Database, client_id: &str, client_secret: &str) -> bool {
    d1::query!(
        db,
        r#"
SELECT client_secret
FROM applications
WHERE client_id = ?
        "#,
        client_id,
    )
    .expect("failed to create query")
    .first::<String>(Some("client_secret"))
    .await
    .expect("failed to get column")
    .map(|secret| secret == client_secret)
    .unwrap_or(false)
}

#[derive(Deserialize)]
pub struct CreateApplication {
    redirect_uri: String,
    name: String,
    description: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateApplicationResponse {
    client_id: String,
    client_secret: String,
}

pub async fn create_application(
    db: &d1::Database,
    data: &CreateApplication,
) -> Option<CreateApplicationResponse> {
    let mut rng = OsRng;

    d1::query!(
        db,
        r#"
INSERT INTO applications (client_id, client_secret, redirect_uri, name, description)
VALUES (?, ?, ?, ?, ?)
RETURNING client_id, client_secret
        "#,
        Alphanumeric.sample_string(&mut rng, CLIENT_ID_LEN),
        Alphanumeric.sample_string(&mut rng, CLIENT_SECRET_LEN),
        data.redirect_uri,
        data.name,
        data.description,
    )
    .expect("failed to create query")
    .first::<CreateApplicationResponse>(None)
    .await
    .expect("failed to get column")
}
