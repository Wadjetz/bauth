-- Logins are passwordless (magic link and code): password login, registration with a password,
-- email verification at sign-up and password reset are gone, with their tables. The down
-- migration recreates them empty, should passwords come back.
DROP TABLE bauth.password_resets;
DROP TABLE bauth.email_verifications;
DROP TABLE bauth.password_credentials;
