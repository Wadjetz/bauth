CREATE TABLE bauth.authorization_codes (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    code_hash   bytea       NOT NULL UNIQUE,
    flow_id     uuid        NOT NULL UNIQUE REFERENCES bauth.login_flows (id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES bauth.users (id) ON DELETE CASCADE,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX authorization_codes_user_id_idx ON bauth.authorization_codes (user_id);
