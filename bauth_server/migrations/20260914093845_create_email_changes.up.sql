CREATE TABLE bauth.email_changes (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid        NOT NULL REFERENCES bauth.users (id) ON DELETE CASCADE,
    -- Address of the account when the change was requested: if it changed since, the link is stale.
    from_email  text        NOT NULL,
    -- New address; the link is sent there, so using it proves the user owns it.
    to_email    text        NOT NULL,
    -- SHA-256 of the token sent by email; the token itself is never stored.
    token_hash  bytea       NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX email_changes_user_id_idx ON bauth.email_changes (user_id);

-- Purge job: `expires_at < … OR consumed_at < …`. Partial index: most rows are never consumed.
CREATE INDEX email_changes_expires_at_idx ON bauth.email_changes (expires_at);
CREATE INDEX email_changes_consumed_at_idx ON bauth.email_changes (consumed_at) WHERE consumed_at IS NOT NULL;
