use serde::Deserialize;
use std::{env, fs, path::Path};

#[allow(unused)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct Config {
    name: String,
    style: StyleConfig,
    env: EnvConfig,
    url: UrlConfig,
}

#[allow(unused)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct StyleConfig {
    display_name: String,
    icon_url: String,
    background_color: String,
    background_color_hover: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct EnvConfig {
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
}

#[allow(unused)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct UrlConfig {
    auth: String,
    token: String,
    callback: String,
}

fn main() {
    println!("cargo:rerun-if-changed=public");
    println!("cargo:rerun-if-changed=src/providers/*/*.toml");

    let out_dir = env::var_os("OUT_DIR")
        .expect("failed to read OUT_DIR env")
        .to_str()
        .expect("failed to read OUT_DIR env")
        .to_owned();

    let mut providers = Vec::new();

    for entry in fs::read_dir("src/providers").expect("failed to read providers") {
        let path = entry.expect("failed to read provider").path();

        if path.is_dir() {
            let provider = path
                .file_name()
                .expect("invalid provider name")
                .to_str()
                .expect("invalid provider name")
                .to_owned();

            eprintln!("Handling {provider}");

            let config = fs::read_to_string(path.join("provider.toml"))
                .expect("failed to read provider config");
            let config =
                toml::from_str::<Config>(&config).expect("failed to parse provider config");

            providers.push(config);
        }
    }

    let oauth_options = providers
        .iter()
        .map(|config| {
            let Config {
                name,
                env:
                    EnvConfig {
                        client_id,
                        client_secret,
                        scopes,
                    },
                url:
                    UrlConfig {
                        auth,
                        token,
                        callback,
                    },
                ..
            } = &config;

            let scopes = scopes
                .iter()
                .map(|scope| format!(r#""{scope}".to_string()"#))
                .collect::<Vec<_>>()
                .join(", ");

            format!(
                r#"
"{name}" => Ok(OAuthOptions {{
    client_id: ctx.var("{client_id}").unwrap().to_string(),
    client_secret: Some(ctx.var("{client_secret}").unwrap().to_string()),
    auth_url: "{auth}".to_string(),
    token_url: Some("{token}".to_string()),
    callback_url: Some(ctx.var("{callback}").unwrap().to_string()),
    scopes: vec![{scopes}],
}}),
                "#
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let fetch_user = providers
        .iter()
        .map(|config| {
            let Config { name, .. } = &config;

            format!(r#""{name}" => {name}::fetch_user(access_token).await,"#)
        })
        .collect::<Vec<_>>()
        .join("");

    let file = format!(
        r#"
use crate::oauth::OAuthOptions;
use crate::user::User;
use crate::error::{{Error, Result}};

pub fn get_oauth_options(provider: &str, ctx: &worker::RouteContext<()>) -> Result<OAuthOptions> {{
    match provider {{
        {oauth_options}
        _ => Err(Error::InvalidProvider),
    }}
}}

pub async fn fetch_user(provider: &str, access_token: &str) -> Result<User> {{
    match provider {{
        {fetch_user}
        _ => Err(Error::InvalidProvider),
    }}
}}
        "#
    );

    let dest_path = Path::new(&out_dir).join("providers.rs");
    fs::write(&dest_path, file).expect("failed to write output");
}
