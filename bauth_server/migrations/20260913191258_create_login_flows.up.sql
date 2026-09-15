CREATE TABLE bauth.login_flows (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    client_id      text        NOT NULL,
    redirect_uri   text        NOT NULL,
    code_challenge text        NOT NULL,
    state          text,
    -- Magic link emails asked for on this flow, whether the account exists or not.
    magic_link_requests integer NOT NULL DEFAULT 0,
    expires_at     timestamptz NOT NULL,
    completed_at   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- Purge job: flows expired for a day (their codes and magic links go with them).
CREATE INDEX login_flows_expires_at_idx ON bauth.login_flows (expires_at);
