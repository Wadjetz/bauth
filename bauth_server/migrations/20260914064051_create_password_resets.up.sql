CREATE TABLE bauth.password_resets (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid        NOT NULL REFERENCES bauth.users (id) ON DELETE CASCADE,
    -- Address the link was sent to: using it also proves the user owns this address.
    email       text        NOT NULL,
    -- SHA-256 of the token sent by email; the token itself is never stored.
    token_hash  bytea       NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX password_resets_user_id_idx ON bauth.password_resets (user_id);

-- Purge job: `expires_at < … OR consumed_at < …`. Partial index: most rows are never consumed.
CREATE INDEX password_resets_expires_at_idx ON bauth.password_resets (expires_at);
CREATE INDEX password_resets_consumed_at_idx ON bauth.password_resets (consumed_at) WHERE consumed_at IS NOT NULL;
