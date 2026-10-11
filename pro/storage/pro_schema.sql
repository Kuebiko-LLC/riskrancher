-- File: RiskRancher/pro/storage/pro_schema.sql
-- These tables unlock the Enterprise features

-- ==========================================
-- 0. WORKSPACES (Multi-Tenancy Foundation)
-- ==========================================
CREATE TABLE IF NOT EXISTS workspaces (
                                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                                          name TEXT UNIQUE NOT NULL,
                                          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO workspaces (id, name) VALUES (1, 'Default Enterprise Workspace');

-- ==========================================
-- 1. THE MISSING AUDIT & ACTIVITY ENGINE
-- ==========================================
CREATE TABLE IF NOT EXISTS ticket_activity (
                                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                                               ticket_id INTEGER NOT NULL,
                                               actor TEXT NOT NULL DEFAULT 'System',
                                               workspace_id INTEGER DEFAULT 1 REFERENCES workspaces(id),
    activity_type TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
    );

-- ==========================================
-- 2. PIPELINE & AUTOMATION RULES
-- ==========================================
CREATE TABLE IF NOT EXISTS routing_rules (
                                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                                             workspace_id INTEGER DEFAULT 1 REFERENCES workspaces(id),
    rule_type TEXT NOT NULL CHECK(rule_type IN ('Source', 'Asset', 'Domain')),
    match_value TEXT NOT NULL,
    assignee TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('RangeHand', 'Wrangler')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

CREATE TABLE IF NOT EXISTS auto_triage_rules (
                                                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                 workspace_id INTEGER DEFAULT 1 REFERENCES workspaces(id),
    match_source TEXT,
    match_asset TEXT,
    match_cve TEXT,
    action_type TEXT NOT NULL CHECK(action_type IN ('DowngradeSeverity', 'AssignOwner', 'MarkFalsePositive')),
    action_value TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

CREATE TABLE IF NOT EXISTS suppression_rules (
                                                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                 dedupe_hash TEXT NOT NULL,
                                                 asset_identifier TEXT NOT NULL,
                                                 rationale TEXT NOT NULL,
                                                 actor TEXT NOT NULL,
                                                 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                                 UNIQUE(dedupe_hash, asset_identifier)
    );

CREATE TABLE IF NOT EXISTS global_suppression_rules (
                                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                        match_source TEXT,
                                                        match_asset TEXT,
                                                        match_title TEXT,
                                                        rationale TEXT NOT NULL,
                                                        actor TEXT NOT NULL,
                                                        is_active BOOLEAN DEFAULT 1,
                                                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- 3. EXCEPTION PIPELINE (MAGIC LINKS)
-- ==========================================
CREATE TABLE IF NOT EXISTS magic_batches (
                                             token TEXT PRIMARY KEY,
                                             created_by TEXT NOT NULL,
                                             expires_at DATETIME NOT NULL,
                                             is_revoked BOOLEAN DEFAULT 0,
                                             ticket_ids TEXT NOT NULL, -- JSON array of IDs
                                             created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- 4. INTEGRATIONS & API
-- ==========================================
CREATE TABLE IF NOT EXISTS cisa_catalog (
                                            cve_id TEXT PRIMARY KEY,
                                            date_added DATETIME
);

CREATE TABLE IF NOT EXISTS api_keys (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        token_hash TEXT UNIQUE NOT NULL,
                                        workspace_id INTEGER DEFAULT 1 REFERENCES workspaces(id),
    name TEXT NOT NULL,
    permissions TEXT NOT NULL CHECK(permissions IN ('WriteOnly', 'ReadOnly', 'FullAdmin')),
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    last_used_at DATETIME
    );

CREATE TABLE IF NOT EXISTS webhooks (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        name TEXT NOT NULL,
                                        workspace_id INTEGER DEFAULT 1 REFERENCES workspaces(id),
    payload_url TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    event_triggers TEXT NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

CREATE TABLE IF NOT EXISTS audit_logs (
                                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                                          actor TEXT NOT NULL,
                                          action TEXT NOT NULL,
                                          target_resource TEXT NOT NULL,
                                          status_code INTEGER NOT NULL,
                                          error_details TEXT,
                                          ip_address TEXT,
                                          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- 5. ASSET TOPOLOGY (ASPM)
-- ==========================================
CREATE TABLE IF NOT EXISTS asset_sequences (
                                               asset_identifier TEXT PRIMARY KEY,
                                               prefix TEXT NOT NULL,
                                               current_sequence INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS applications (
                                            id TEXT PRIMARY KEY,
                                            name TEXT NOT NULL UNIQUE,
                                            business_criticality TEXT DEFAULT 'Medium',
                                            owner_team TEXT,
                                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS asset_aliases (
                                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                                             application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    layer TEXT NOT NULL CHECK(layer IN ('Code', 'Artifact', 'Runtime', 'Cloud', 'CompensatingControl')),
    discovery_source TEXT,
    is_verified BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(application_id, alias)
    );

CREATE TABLE IF NOT EXISTS asset_edges (
                                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                                           source_alias TEXT NOT NULL,
                                           target_alias TEXT NOT NULL,
                                           relationship TEXT NOT NULL,
                                           created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                           UNIQUE(source_alias, target_alias, relationship)
    );

-- ==========================================
-- 6. ENTERPRISE PERFORMANCE INDEXES
-- ==========================================
CREATE INDEX IF NOT EXISTS idx_activity_ticket_id ON ticket_activity(ticket_id);
CREATE INDEX IF NOT EXISTS idx_activity_created_at ON ticket_activity(created_at);
CREATE INDEX IF NOT EXISTS idx_asset_aliases ON asset_aliases(alias);
CREATE INDEX IF NOT EXISTS idx_global_suppression ON global_suppression_rules(is_active);
CREATE INDEX IF NOT EXISTS idx_tickets_cisa_kev ON tickets(status) WHERE is_cisa_kev = 1;