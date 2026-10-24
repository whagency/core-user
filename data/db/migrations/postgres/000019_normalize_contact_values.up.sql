-- Store contact values in a single canonical form.
--
-- The column held whatever the client typed. With UNIQUE (type, value) matching
-- byte for byte, Alice@Example.com and alice@example.com were two accounts on
-- one mailbox, and signing in with a different capitalization than the one used
-- at registration returned "not found".
--
-- Step 1 refuses to go further if lowering would collide. Two accounts that
-- differ only by case are a business problem, not a data-cleanup one: they may
-- both hold balances in account-service, and picking a survivor is a decision a
-- migration has no business making. Find them with
--
--   SELECT type, lower(value), count(*), array_agg(id)
--   FROM contacts GROUP BY type, lower(value) HAVING count(*) > 1;
--
-- and resolve them before deploying.
DO $$
DECLARE
    collision_count INT;
BEGIN
    SELECT count(*) INTO collision_count
    FROM (
        SELECT type, lower(value)
        FROM contacts
        GROUP BY type, lower(value)
        HAVING count(*) > 1
    ) AS collisions;

    IF collision_count > 0 THEN
        RAISE EXCEPTION
            'contacts hold % value group(s) that differ only by case; merge or remove them before applying this migration (see the query in 000019_normalize_contact_values.up.sql)',
            collision_count;
    END IF;
END
$$;

UPDATE contacts
SET value = lower(value),
    updated_at = NOW()
WHERE value <> lower(value);

-- Step 3 makes the invariant the database's rather than a convention two
-- services have to remember. user-service and admin-service both write this
-- column, so a normalization the code merely promises is one refactor away from
-- being lost again.
--
-- Scoped to type 1 (email) on purpose. Phone values are e164 and have no case,
-- and a contact type that is genuinely case-sensitive -- a wallet address, say
-- -- should not be forced into lowercase by a constraint written before it
-- existed.
ALTER TABLE contacts
    ADD CONSTRAINT contacts_email_value_lowercase
    CHECK (type <> 1 OR value = lower(value));
