-- Store refresh tokens as SHA-256 hashes instead of the tokens themselves.
--
-- The column held the opaque token verbatim, so any read access to sessions --
-- a dump, a replica, a backup -- handed over working 30-day credentials for
-- every logged-in user. A refresh token is 32 bytes from crypto/rand, so a
-- plain hash is enough: there is no dictionary to run against 256 bits of
-- entropy, and the verification path is hot enough that bcrypt would be the
-- wrong instrument.
--
-- Existing sessions are migrated in place rather than deleted, so nobody is
-- signed out by this change. sha256() and convert_to() are both built in on
-- PostgreSQL 17.
ALTER TABLE sessions ALTER COLUMN refresh_token TYPE VARCHAR(128);

UPDATE sessions
SET refresh_token = encode(sha256(convert_to(refresh_token, 'UTF8')), 'hex');

-- Keep the hash of a session's refresh token when the session is revoked.
--
-- This is what makes reuse detection possible: refreshing deletes the session
-- row, so a replayed token afterwards finds nothing to compare against. With
-- the hash preserved here, presenting an already-rotated refresh token can be
-- told apart from presenting a merely unknown one -- the first is proof the
-- token leaked, the second is ordinary noise.
--
-- Nullable, because rows written before this migration have no hash to record
-- and reuse of those tokens cannot be detected retroactively.
ALTER TABLE revoked_sessions ADD COLUMN IF NOT EXISTS refresh_token_hash VARCHAR(128) NULL;
