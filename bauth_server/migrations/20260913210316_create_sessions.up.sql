-- One login of a user on a client. Every refresh token rotated from that login belongs to it,
-- so revoking the session (logout, token reuse, password reset) kills all of them at once.
CREATE TABLE bauth.sessions (
    id                    uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id               uuid        NOT NULL REFERENCES bauth.users (id) ON DELETE CASCADE,
    client_id             text        NOT NULL,
    -- Code exchanged to open this session: replaying that code revokes the session.
    authorization_code_id uuid        UNIQUE REFERENCES bauth.authorization_codes (id) ON DELETE SET NULL,
    -- Absolute limit: the user must log in again after this, however often they refresh.
    expires_at            timestamptz NOT NULL,
    revoked_at            timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user_id_idx ON bauth.sessions (user_id);

CREATE TABLE bauth.refresh_tokens (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    session_id    uuid        NOT NULL REFERENCES bauth.sessions (id) ON DELETE CASCADE,
    -- Token this one was rotated from, NULL for the first token of a session. Lets a refresh
    -- whose response was lost be retried: an old token is only a theft signal if its
    -- successor has already been used.
    parent_id     uuid        REFERENCES bauth.refresh_tokens (id) ON DELETE CASCADE,
    -- SHA-256 of the opaque token given to the app.
    token_hash    bytea       NOT NULL UNIQUE,
    -- Set when exchanged for a new token.
    rotated_at    timestamptz,
    -- Set on a successor that was never used, when its parent is retried.
    -- It must never come back: if it does, a copy of the parent is in someone else's hands.
    superseded_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_session_id_idx ON bauth.refresh_tokens (session_id);
CREATE INDEX refresh_tokens_parent_id_idx ON bauth.refresh_tokens (parent_id);

-- Purge job: `expires_at < … OR revoked_at < …`. Partial index: most sessions are never revoked.
CREATE INDEX sessions_expires_at_idx ON bauth.sessions (expires_at);
CREATE INDEX sessions_revoked_at_idx ON bauth.sessions (revoked_at) WHERE revoked_at IS NOT NULL;
