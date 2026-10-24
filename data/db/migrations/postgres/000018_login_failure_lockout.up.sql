-- Track consecutive failed logins per account.
--
-- Until now nothing counted them and nothing recorded them: the only barrier to
-- guessing a password was the per-IP rate limit, which an attacker spreading
-- attempts across addresses does not meet. The counter is consecutive, reset by
-- any successful sign-in and by a password rotation.
--
-- login_locked_until is a deadline rather than a flag, so a lock expires on its
-- own and no job is needed to release it. NULL means not locked.
ALTER TABLE credentials
    ADD COLUMN IF NOT EXISTS failed_login_attempts SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS login_locked_until TIMESTAMPTZ NULL;
