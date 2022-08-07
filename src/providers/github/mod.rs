use serde::Deserialize;

use crate::{error::Result, fetch, user::User};

#[derive(Deserialize)]
struct GitHub {
    login: String,
    id: u64,
    avatar_url: String,
    name: Option<String>,
    email: Option<String>,
    created_at: String,
    updated_at: String,
}

pub async fn fetch_user(access_token: &str) -> Result<User> {
    let github = fetch::RequestBuilder::get("https://api.github.com/user")
        .set_header("Authorization", &format!("token {access_token}"))?
        .set_header("User-Agent", "auth.worker")?
        .send()
        .await?
        .json::<GitHub>()
        .await?;

    Ok(User {
        username: Some(github.login),
        picture: Some(github.avatar_url),
        name: github.name,
        email: github.email,
        created_at: Some(github.created_at),
        updated_at: Some(github.updated_at),
        ..User::default_with_user_id(github.id.to_string())
    })
}
