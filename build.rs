use serde::Deserialize;
use std::{collections::HashMap, env, fs, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct Config {
    domain: String,
    providers: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct ProviderConfig {
    name: String,
    style: StyleConfig,
    url: UrlConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct StyleConfig {
    display_name: String,
    background_color: String,
    background_color_hover: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all(deserialize = "kebab-case"))]
struct UrlConfig {
    auth: String,
    token: String,
}

fn out_dir() -> String {
    env::var_os("OUT_DIR")
        .expect("failed to read OUT_DIR env")
        .to_str()
        .expect("failed to read OUT_DIR env")
        .to_owned()
}

fn providers() -> Vec<ProviderConfig> {
    fs::read_dir("src/providers")
        .expect("failed to read providers")
        .map(|entry| entry.expect("failed to read provider").path())
        .filter(|path| path.is_dir())
        .map(|path| {
            let provider = fs::read_to_string(path.join("provider.toml"))
                .expect("failed to read provider config");

            toml::from_str::<ProviderConfig>(&provider).expect("failed to parse provider config")
        })
        .collect::<Vec<_>>()
}

fn gen_provider_def(config: &Config, provider: &ProviderConfig) -> String {
    let Config { domain, .. } = config;
    let ProviderConfig { name, url, .. } = provider;
    let UrlConfig { auth, token } = url;

    let name_upper = name.to_uppercase();

    let scopes = config
        .providers
        .get(name)
        .expect("provider not found")
        .iter()
        .map(|s| format!(r#""{s}""#))
        .collect::<Vec<String>>()
        .join(",");

    format!(
        r#"
const {name_upper}: Provider = Provider {{
    auth_url: "{auth}",
    token_url: "{token}",
    callback_url: "{domain}/oauth/callback",
    scopes: &[{scopes}],
}};
        "#
    )
}

fn gen_provider_fns(providers: &[ProviderConfig]) -> String {
    let get_match_arms = providers
        .iter()
        .map(|provider| {
            let ProviderConfig { name, .. } = provider;
            let name_upper = provider.name.to_uppercase();

            format!(r#""{name}" => Ok({name_upper}),"#)
        })
        .collect::<String>();

    let fetch_match_arms = providers
        .iter()
        .map(|provider| {
            let ProviderConfig { name, .. } = provider;

            format!(r#""{name}" => {name}::fetch_user(client, access_token).await,"#)
        })
        .collect::<String>();

    format!(
        r#"
pub fn get_provider(provider: &str) -> Result<Provider, Error> {{
    match provider {{
        {get_match_arms}
        _ => Err(Error::InvalidConnection),
    }}
}}

pub async fn fetch_user(provider: &str, client: ::reqwest::Client, access_token: &str) -> Result<User, Error> {{
    let mut user = match provider {{
        {fetch_match_arms}
        _ => Err(Error::InvalidConnection),
    }}?;

    user.id = format!("{{provider}}|{{}}", user.id);

    Ok(user)
}}
        "#
    )
}

fn gen_providers(config: &Config, providers: &[ProviderConfig]) {
    let provider_defs = providers
        .iter()
        .map(|provider| gen_provider_def(config, provider))
        .collect::<String>();

    let provider_fns = gen_provider_fns(providers);

    let dest_path = Path::new(&out_dir()).join("providers.rs");
    fs::write(&dest_path, provider_defs + &provider_fns).expect("failed to write output");
}

fn gen_provider_button(provider: &ProviderConfig) -> String {
    let ProviderConfig { name, style, .. } = provider;
    let StyleConfig {
        display_name,
        background_color,
        background_color_hover,
        ..
    } = style;

    let svg = fs::read_to_string(Path::new("src/providers").join(name).join("provider.svg"))
        .expect("provider icon not found");

    format!(
        r#"
<button
    class="oauth-provider"
    onclick="oauth('{name}')"
    style="--provider-bg-color: {background_color}; --provider-bg-color-hover: {background_color_hover}"
>
    <div class="oauth-icon">
        {svg}
    </div>
    <div class="oauth-name">{display_name}</div>
</button>
        "#
    )
}

fn gen_providers_html(providers: &[ProviderConfig]) {
    let html = providers
        .iter()
        .map(gen_provider_button)
        .collect::<String>();

    let login = include_str!("public/login.html").replace("<!-- OAUTH_PROVIDERS -->", &html);

    let dest_path = Path::new(&out_dir()).join("login.html");
    fs::write(&dest_path, login).expect("failed to write output");
}

fn main() {
    println!("cargo:rerun-if-changed=config.toml");
    println!("cargo:rerun-if-changed=public");
    println!("cargo:rerun-if-changed=src/providers/*/*");

    let config =
        toml::from_str::<Config>(include_str!("config.toml")).expect("failed to parse config");

    println!("cargo:rustc-env=DOMAIN={}", config.domain);

    let mut providers = providers()
        .into_iter()
        .filter(|provider| config.providers.contains_key(&provider.name))
        .collect::<Vec<_>>();
    providers.sort_by_key(|provider| provider.name.clone());

    gen_providers(&config, &providers);
    gen_providers_html(&providers);
}
