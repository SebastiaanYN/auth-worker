use crate::{d1, users::User};

pub async fn upsert_user(db: &d1::Database, user: &User) -> worker::Result<d1::QueryResult> {
    d1::query!(
        db,
        r#"
INSERT INTO users (
    id,
    email,
    email_verified,
    family_name,
    given_name,
    username,
    name,
    nickname,
    picture,
    created_at,
    updated_at,
    blocked,
    last_ip,
    last_login,
    last_password_reset,
    logins_count,
    multifactor,
    phone_number,
    phone_verified
)
VALUES
    (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
ON CONFLICT DO UPDATE SET
    email = excluded.email,
    email_verified = excluded.email_verified,
    family_name = excluded.family_name,
    given_name = excluded.given_name,
    username = excluded.username,
    name = excluded.name,
    nickname = excluded.nickname,
    picture = excluded.picture,
    created_at = excluded.created_at,
    updated_at = excluded.updated_at,
    blocked = excluded.blocked,
    last_ip = excluded.last_ip,
    last_login = excluded.last_login,
    last_password_reset = excluded.last_password_reset,
    logins_count = excluded.logins_count,
    multifactor = excluded.multifactor,
    phone_number = excluded.phone_number,
    phone_verified = excluded.phone_verified
        "#,
        user.id,
        user.email,
        user.email_verified.map(u8::from),
        user.family_name,
        user.given_name,
        user.username,
        user.name,
        user.nickname,
        user.picture,
        user.created_at,
        user.updated_at,
        user.blocked.map(u8::from),
        user.last_ip,
        user.last_login,
        user.last_password_reset,
        user.logins_count,
        user.multifactor,
        user.phone_number,
        user.phone_verified.map(u8::from),
    )?
    .run()
    .await
}
