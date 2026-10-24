-- Widen the session expiry columns past 2038.
--
-- expire and refresh_expire hold Unix seconds in a 32-bit INT, which stops at
-- 2147483647 -- 2038-01-19 03:14:07 UTC. The failure does not wait for that
-- date: refresh_expire is stamped 30 days ahead, so every sign-in starts failing
-- on 2037-12-20, and expire follows a month later.
--
-- And it fails hard rather than quietly. Postgres answers "integer out of range"
-- and the INSERT is refused, so issuing a session stops working -- which means
-- sign-in stops working. Verified by reproducing it against PostgreSQL 17.
--
-- The Go side already carries these as int64; only the column stood in the way.
--
-- INT to BIGINT rewrites the table under an ACCESS EXCLUSIVE lock. That is
-- affordable here because sessions is swept by the retention job added in
-- 000018-era work: it holds live sessions rather than the history of every one
-- ever issued.
ALTER TABLE sessions
    ALTER COLUMN expire TYPE BIGINT,
    ALTER COLUMN refresh_expire TYPE BIGINT;
