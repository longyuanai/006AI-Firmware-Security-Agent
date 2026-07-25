CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id TEXT PRIMARY KEY,
    cpe_id TEXT NOT NULL,
    cvss_v3 REAL,
    description TEXT,
    in_known_exploited BOOLEAN DEFAULT 0,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cpe ON cve_entries(cpe_id);
