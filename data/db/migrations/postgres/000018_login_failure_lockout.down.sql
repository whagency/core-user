ALTER TABLE credentials
    DROP COLUMN IF EXISTS failed_login_attempts,
    DROP COLUMN IF EXISTS login_locked_until;
