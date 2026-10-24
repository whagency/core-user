-- Narrowing back fails on any row already holding a value above 2147483647,
-- which is the correct behaviour: those sessions cannot be represented in the
-- old column and silently truncating them would hand out expiry dates in 1970.
ALTER TABLE sessions
    ALTER COLUMN expire TYPE INT,
    ALTER COLUMN refresh_expire TYPE INT;
