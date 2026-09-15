CREATE TABLE bauth.password_credentials (
    user_id       uuid        PRIMARY KEY REFERENCES bauth.users (id) ON DELETE CASCADE,
    password_hash text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);