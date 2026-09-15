CREATE TABLE bauth.signing_keys (
    -- Also the JWT `kid` header.
    id                    uuid        PRIMARY KEY,
    algorithm             text        NOT NULL CHECK (algorithm = 'EdDSA'),
    -- Raw 32-byte Ed25519 public key, published in the JWKS.
    public_key            bytea       NOT NULL CHECK (length(public_key) = 32),
    -- 32-byte Ed25519 seed encrypted with BAUTH_MASTER_KEY (context `signing_key:<id>`).
    encrypted_private_key bytea       NOT NULL,
    -- Published as soon as it exists; used for signing from `active_at`.
    active_at             timestamptz NOT NULL,
    -- No longer signs after this; stays published a while so issued tokens remain verifiable.
    retired_at            timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);
