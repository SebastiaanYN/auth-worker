use serde::Deserialize;

use crate::{error::Result, fetch, user::User};

#[derive(Deserialize)]
struct GitHub {
    login: String,
    id: u64,
    avatar_url: String,
    name: Option<String>,
    // email: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct Email {
    email: String,
    verified: bool,
    primary: bool,
}

const API: &str = "https://api.github.com";

pub async fn fetch_user(access_token: &str) -> Result<User> {
    let mut headers = worker::Headers::new();
    headers
        .set("Authorization", &format!("token {access_token}"))
        .unwrap();
    headers.set("User-Agent", "auth.worker").unwrap();

    let github = fetch::RequestBuilder::get(&format!("{API}/user"))
        .set_headers(headers.clone())
        .send()
        .await?
        .json::<GitHub>()
        .await?;

    let emails = fetch::RequestBuilder::get(&format!("{API}/user/emails"))
        .set_headers(headers)
        .send()
        .await?
        .json::<Vec<Email>>()
        .await?;

    let email = emails.iter().find(|email| email.primary).or(emails.first());

    Ok(User {
        username: Some(github.login),
        picture: Some(github.avatar_url),
        name: github.name,
        email: email.map(|e| e.email.clone()),
        email_verified: email.map(|e| e.verified),
        created_at: Some(github.created_at),
        updated_at: Some(github.updated_at),
        ..User::default_with_id(github.id.to_string())
    })
}
