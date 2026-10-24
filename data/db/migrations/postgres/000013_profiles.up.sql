CREATE TABLE IF NOT EXISTS profiles (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    country CHAR(2) NOT NULL,
    dob DATE,
    address VARCHAR(255),
    locale VARCHAR(10),
    timezone VARCHAR(50)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_user_id ON profiles(user_id);