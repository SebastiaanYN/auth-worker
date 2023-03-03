use oauth2::AccessToken;
use reqwest::Client;
use serde::Deserialize;

use crate::{error::Error, users::User};

#[derive(Deserialize)]
struct Discord {
    id: String,
    username: String,
    avatar: Option<String>,
    verified: Option<bool>,
    email: Option<String>,
}

pub async fn fetch_user(client: Client, access_token: &AccessToken) -> Result<User, Error> {
    let discord = client
        .get("https://discord.com/api/users/@me")
        .bearer_auth(access_token.secret())
        .send()
        .await?
        .json::<Discord>()
        .await?;

    Ok(User {
        username: Some(discord.username),
        picture: discord.avatar.map(|avatar| {
            let ext = if avatar.starts_with("a_") {
                "gif"
            } else {
                "png"
            };

            let user_id = &discord.id;
            format!("https://cdn.discordapp.com/avatars/{user_id}/{avatar}.{ext}")
        }),
        email: discord.email,
        email_verified: discord.verified,
        ..User::default_with_id(discord.id)
    })
}
