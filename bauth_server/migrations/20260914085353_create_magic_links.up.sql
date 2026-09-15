CREATE TABLE bauth.magic_links (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    -- Login flow this link completes: the flow's PKCE challenge still protects the code.
    flow_id     uuid        NOT NULL REFERENCES bauth.login_flows (id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES bauth.users (id) ON DELETE CASCADE,
    -- Address the link was sent to: using it also proves the user owns this address.
    email       text        NOT NULL,
    -- SHA-256 of the token sent by email; the token itself is never stored.
    token_hash  bytea       NOT NULL UNIQUE,
    -- HMAC of the 6-digit code sent with the link (see `magic_code.rs`): a plain hash of
    -- 10^6 values would be reversed instantly from a dump.
    code_hash   bytea       NOT NULL,
    -- Wrong codes typed for this link: it is consumed at the limit. Summed per user as well.
    code_failures integer   NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX magic_links_flow_id_idx ON bauth.magic_links (flow_id);
CREATE INDEX magic_links_user_id_idx ON bauth.magic_links (user_id);
