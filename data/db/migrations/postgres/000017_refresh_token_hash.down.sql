-- Hashing is one-way, so the tokens cannot be restored.
--
-- Leaving the hashes in a column the previous code compares against raw tokens
-- would make every refresh fail while looking like a valid session, so the rows
-- go instead: clients fall back to logging in again, which is the honest
-- outcome of rolling this back. Nothing else in the schema depends on them.
DELETE FROM sessions;

ALTER TABLE revoked_sessions DROP COLUMN IF EXISTS refresh_token_hash;

ALTER TABLE sessions ALTER COLUMN refresh_token TYPE VARCHAR(64);
