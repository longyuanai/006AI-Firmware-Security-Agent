-- One CVE affects many CPEs, so the identity of a row is the pair.
-- A single-column cve_id primary key silently collapsed every additional
-- CPE of the same CVE into whichever one happened to be written last.
CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id TEXT NOT NULL,
    cpe_id TEXT NOT NULL,
    cvss_v3 REAL,
    description TEXT,
    in_known_exploited BOOLEAN DEFAULT 0,
    product TEXT,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (cve_id, cpe_id)
);

CREATE INDEX IF NOT EXISTS idx_cpe ON cve_entries(cpe_id);
CREATE INDEX IF NOT EXISTS idx_product ON cve_entries(product);
