CREATE TABLE IF NOT EXISTS role_children (
    parent VARCHAR(20) NOT NULL REFERENCES roles(name) ON DELETE CASCADE ON UPDATE CASCADE,
    child VARCHAR(20) NOT NULL REFERENCES roles(name) ON DELETE CASCADE ON UPDATE CASCADE,
    UNIQUE (parent, child)
);

CREATE INDEX IF NOT EXISTS idx_role_children_parent ON role_children(parent);
CREATE INDEX IF NOT EXISTS idx_role_children_child ON role_children(child);