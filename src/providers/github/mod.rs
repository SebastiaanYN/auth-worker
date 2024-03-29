use oauth2::AccessToken;
use reqwest::{header, Client};
use serde::Deserialize;

use crate::{error::Error, users::User};

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

pub async fn fetch_user(client: Client, access_token: &AccessToken) -> Result<User, Error> {
    let github = client
        .get(&format!("{API}/user"))
        .header(
            header::AUTHORIZATION,
            format!("token {}", access_token.secret()),
        )
        .send()
        .await?
        .json::<GitHub>()
        .await?;

    let emails = client
        .get(&format!("{API}/user/emails"))
        .header(
            header::AUTHORIZATION,
            format!("token {}", access_token.secret()),
        )
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
