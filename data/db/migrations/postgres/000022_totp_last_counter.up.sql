-- Remember the last TOTP step accepted for this user.
--
-- A TOTP code was checked against the secret and nothing else, so it stayed
-- valid for the whole 90-second window the verifier accepts. Consuming the token
-- stopped a replay against that same challenge, but not against a different one:
-- someone who saw the six digits the victim had just typed could start their own
-- sign-in, get a fresh challenge, and enter them.
--
-- RFC 6238 section 5.2 is explicit that a verifier must not accept a code twice.
-- Storing the accepted step and requiring the next one to be strictly greater is
-- how that is done.
--
-- Zero means nothing accepted yet, which is the right starting point: the first
-- code any user presents has a step far above it.
ALTER TABLE two_factor_settings
    ADD COLUMN IF NOT EXISTS last_totp_counter BIGINT NOT NULL DEFAULT 0;
