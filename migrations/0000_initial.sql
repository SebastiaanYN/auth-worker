-- Migration number: 0000 	 2023-02-07T23:16:26.462Z

CREATE TABLE IF NOT EXISTS applications (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS applications_name ON applications(name);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,

    email TEXT,
    email_verified INTEGER,

    family_name TEXT,
    given_name TEXT,
    username TEXT,
    name TEXT,
    nickname TEXT,

    picture TEXT,

    created_at TEXT,
    updated_at TEXT,

    blocked INTEGER,

    last_ip TEXT,
    last_login TEXT,
    last_password_reset TEXT,
    logins_count INTEGER,

    multifactor TEXT,
    phone_number TEXT,
    phone_verified INTEGER
);

CREATE INDEX IF NOT EXISTS users_email ON users(email);
