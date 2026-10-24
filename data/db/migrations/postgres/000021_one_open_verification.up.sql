-- At most one open verification per user and provider.
--
-- Init read "is there a pending one?", called the KYC provider, then inserted --
-- with nothing in between. Two requests arriving together both read no, both
-- paid for an applicant form, and both wrote a row. The user ended up with two
-- open verifications and two form URLs, and the provider quota was spent twice.
--
-- The index is what makes the check meaningful: the loser of the race now fails
-- at the insert instead of proceeding, and Init hands it the winner's row.
--
-- Statuses 1 and 2 are new_request and pending. A completed verification, either
-- way, is not open and does not take part.
DO $$
DECLARE
    duplicate_groups INT;
BEGIN
    SELECT count(*) INTO duplicate_groups
    FROM (
        SELECT user_id, provider
        FROM verifications
        WHERE status IN (1, 2)
        GROUP BY user_id, provider
        HAVING count(*) > 1
    ) AS duplicates;

    IF duplicate_groups > 0 THEN
        RAISE EXCEPTION
            'verifications hold % user/provider pair(s) with more than one open request; the race this index closes has already produced them. Resolve with: SELECT user_id, provider, array_agg(id ORDER BY created_at) FROM verifications WHERE status IN (1,2) GROUP BY user_id, provider HAVING count(*) > 1;',
            duplicate_groups;
    END IF;
END
$$;

-- Not CONCURRENTLY: a unique build that hits a duplicate leaves an invalid index
-- behind when built concurrently, and this table holds one row per verification
-- attempt, so the brief lock costs nothing worth avoiding.
CREATE UNIQUE INDEX IF NOT EXISTS idx_verifications_one_open_per_user_provider
    ON verifications (user_id, provider)
    WHERE status IN (1, 2);
