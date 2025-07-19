-- 1. Create new table with UNIQUE constraint
CREATE TABLE permissions_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    can_read BOOLEAN NOT NULL DEFAULT 1,
    can_write BOOLEAN NOT NULL DEFAULT 0,
    can_delete BOOLEAN NOT NULL DEFAULT 0,
    can_share BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, path)
);

-- 2. Copy data from old table
INSERT OR IGNORE INTO permissions_new (user_id, path, can_read, can_write, can_delete, can_share, created_at, updated_at)
SELECT user_id, path, can_read, can_write, can_delete, can_share, created_at, updated_at FROM permissions;

-- 3. Drop old table
DROP TABLE permissions;

-- 4. Rename new table
ALTER TABLE permissions_new RENAME TO permissions; 