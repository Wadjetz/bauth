CREATE TABLE bauth.email_verifications (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid        NOT NULL REFERENCES bauth.users (id) ON DELETE CASCADE,
    -- Address this token proves; confirming must fail if the user's email changed since.
    email       text        NOT NULL,
    -- SHA-256 of the token sent by email; the token itself is never stored.
    token_hash  bytea       NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX email_verifications_user_id_idx ON bauth.email_verifications (user_id);

-- Purge job: `expires_at < … OR consumed_at < …`. Partial index: most rows are never consumed.
CREATE INDEX email_verifications_expires_at_idx ON bauth.email_verifications (expires_at);
CREATE INDEX email_verifications_consumed_at_idx ON bauth.email_verifications (consumed_at) WHERE consumed_at IS NOT NULL;
