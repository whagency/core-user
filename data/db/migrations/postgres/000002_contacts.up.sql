CREATE TABLE IF NOT EXISTS contacts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    type SMALLINT NOT NULL,
    value VARCHAR(255) NOT NULL,
    status SMALLINT NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NULL,
    UNIQUE (type, value)
);

CREATE INDEX IF NOT EXISTS idx_contacts_user_id ON contacts(user_id);
CREATE INDEX IF NOT EXISTS idx_contacts_type ON contacts(type);
CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status);

ALTER TABLE users
ADD CONSTRAINT fk_users_primary_contact
FOREIGN KEY (primary_contact_id)
REFERENCES contacts(id)
ON DELETE SET NULL
ON UPDATE CASCADE;