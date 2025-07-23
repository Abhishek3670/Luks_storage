-- Create cameras table for CCTV camera management
CREATE TABLE IF NOT EXISTS cameras (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    location TEXT,
    ip_address TEXT NOT NULL UNIQUE,
    port INTEGER NOT NULL DEFAULT 554,
    username TEXT,
    password TEXT,
    resolution TEXT NOT NULL DEFAULT '1920x1080',
    fps INTEGER NOT NULL DEFAULT 30,
    recording_enabled BOOLEAN NOT NULL DEFAULT 1,
    motion_detection BOOLEAN NOT NULL DEFAULT 0,
    is_online BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Create index on ip_address for faster lookups
CREATE INDEX IF NOT EXISTS idx_cameras_ip_address ON cameras(ip_address);

-- Create index on name for searching
CREATE INDEX IF NOT EXISTS idx_cameras_name ON cameras(name);

-- Insert some sample cameras for testing
INSERT INTO cameras (name, location, ip_address, port, username, password, resolution, fps, recording_enabled, motion_detection) VALUES 
('Front Door Camera', 'Front Entrance', '192.168.1.100', 554, 'admin', 'password123', '1920x1080', 30, 1, 1),
('Living Room Camera', 'Living Room', '192.168.1.101', 554, 'admin', 'password123', '1280x720', 25, 1, 0),
('Backyard Camera', 'Back Garden', '192.168.1.102', 554, 'admin', 'password123', '1920x1080', 15, 1, 1);
