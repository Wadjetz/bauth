-- Codes emailed to confirm a sensitive change from a live session (`POST /me/confirmation`),
-- for accounts with no password to ask for.
CREATE TABLE bauth.confirmations (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id       uuid        NOT NULL REFERENCES bauth.users (id) ON DELETE CASCADE,
    -- Session that asked: a code can only be used from there, and dies with it.
    session_id    uuid        NOT NULL REFERENCES bauth.sessions (id) ON DELETE CASCADE,
    -- What the code confirms ('change_email', 'delete_account'): a code is good for that only.
    action        text        NOT NULL,
    -- Address the code was sent to: refused if the account moved since.
    email         text        NOT NULL,
    -- HMAC of the 6-digit code (see `magic_code.rs`), never the code itself.
    code_hash     bytea       NOT NULL,
    -- Wrong codes typed for this confirmation: it is consumed at the limit.
    code_failures integer     NOT NULL DEFAULT 0,
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX confirmations_user_id_created_at_idx ON bauth.confirmations (user_id, created_at);
CREATE INDEX confirmations_session_id_idx ON bauth.confirmations (session_id);
