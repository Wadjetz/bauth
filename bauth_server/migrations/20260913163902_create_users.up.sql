CREATE TABLE bauth.users (
    id                uuid        PRIMARY KEY DEFAULT uuidv7(),
    email             text        NOT NULL UNIQUE,
    email_verified_at timestamptz,
    disabled_at       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- Purge job: accounts never verified (squatted addresses, abandoned sign-ups).
CREATE INDEX users_unverified_created_at_idx ON bauth.users (created_at) WHERE email_verified_at IS NULL;
