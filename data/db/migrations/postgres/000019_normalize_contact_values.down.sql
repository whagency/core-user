-- Only the constraint comes off. The original capitalization was overwritten and
-- is not recoverable, but nothing depends on it: lookups match the stored form
-- either way, and lowercase is a valid value under the old schema.
ALTER TABLE contacts
    DROP CONSTRAINT IF EXISTS contacts_email_value_lowercase;
