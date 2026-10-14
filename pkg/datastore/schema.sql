CREATE TABLE IF NOT EXISTS app_config (
                                          id INTEGER PRIMARY KEY CHECK (id = 1),
    timezone TEXT DEFAULT 'America/New_York',
    business_start INTEGER DEFAULT 9,
    business_end INTEGER DEFAULT 17,
    default_extension_days INTEGER DEFAULT 30
    );

INSERT OR IGNORE INTO app_config (id) VALUES (1);

CREATE TABLE IF NOT EXISTS domains (name TEXT PRIMARY KEY);
INSERT OR IGNORE INTO domains (name) VALUES ('Vulnerability'), ('Privacy'), ('Compliance'), ('Incident');

CREATE TABLE IF NOT EXISTS departments (name TEXT PRIMARY KEY);
INSERT OR IGNORE INTO departments (name) VALUES ('Security'), ('IT'), ('Privacy'), ('Legal'), ('Compliance');

CREATE TABLE IF NOT EXISTS sla_policies (
                                            domain TEXT NOT NULL,
                                            severity TEXT NOT NULL,
                                            days_to_triage INTEGER NOT NULL DEFAULT 3,
                                            days_to_remediate INTEGER NOT NULL,
                                            max_extensions INTEGER NOT NULL DEFAULT 3,
                                            PRIMARY KEY (domain, severity),
    FOREIGN KEY(domain) REFERENCES domains(name) ON DELETE CASCADE
    );

INSERT OR IGNORE INTO sla_policies (domain, severity, days_to_triage, days_to_remediate, max_extensions) VALUES
    ('Vulnerability', 'Critical', 3, 14, 1),
    ('Vulnerability', 'High', 3, 30, 2),
    ('Vulnerability', 'Medium', 7, 60, 2),
    ('Vulnerability', 'Low', 14, 90, 3),
    ('Vulnerability', 'Info', 30, 180, 5),
    ('Privacy', 'Critical', 3, 3, 0),
    ('Privacy', 'High', 3, 7, 1),
    ('Incident', 'Critical', 3, 1, 0);

CREATE TABLE IF NOT EXISTS users (
                                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                                     email TEXT UNIQUE NOT NULL,
                                     password_hash TEXT NOT NULL,
                                     full_name TEXT NOT NULL,
                                     global_role TEXT NOT NULL, -- validated in the app layer (supports Bounty Hunter + future custom roles)
    department TEXT NOT NULL DEFAULT 'Security',
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(department) REFERENCES departments(name) ON DELETE SET DEFAULT
    );

CREATE TABLE IF NOT EXISTS sessions (
                                        session_token TEXT PRIMARY KEY,
                                        user_id INTEGER NOT NULL,
                                        expires_at DATETIME NOT NULL,
                                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
CREATE TABLE IF NOT EXISTS tickets (
                                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                                       domain TEXT NOT NULL DEFAULT 'Vulnerability',
                                       source TEXT NOT NULL DEFAULT 'Manual',
                                       asset_identifier TEXT NOT NULL DEFAULT 'Default',
                                       title TEXT NOT NULL,
                                       description TEXT,
                                       recommended_remediation TEXT,
                                       severity TEXT NOT NULL,
                                       scanner_severity TEXT NOT NULL DEFAULT '', -- the scanner's word, normalized, before the rubric, the rules and KEV
                                       rubric_score REAL,                         -- base x exposure x criticality; NULL when the asset is not in the inventory
                                       status TEXT DEFAULT 'Waiting to be Triaged'
                                       CHECK(status IN (
                                       'Waiting to be Triaged',
                                       'Returned to Security',
                                       'Triaged',
                                       'Assigned Out',
                                       'Patched',
                                       'False Positive',
                                       'Pending Risk Approval',
                                       'Risk Accepted',
                                       'Pending Verification'
)),
    released INTEGER NOT NULL DEFAULT 1, -- 0 while held in an unreleased engagement
    cvss_vector TEXT,
    cvss_score REAL,
    cwe TEXT,
    business_impact TEXT,
    engagement_id INTEGER,
    dedupe_hash TEXT UNIQUE NOT NULL,
    patch_evidence TEXT,
    assignee TEXT DEFAULT 'Unassigned',
    latest_comment TEXT DEFAULT '',

    -- Risk acceptance and KEV tracking
    is_cisa_kev BOOLEAN DEFAULT 0,
    verification_requested_at DATETIME,
    extension_count INTEGER DEFAULT 0,
    risk_rationale TEXT,
    risk_evidence TEXT,
    risk_approved_by TEXT,
    risk_approved_at DATETIME,
    exception_expires_at DATETIME,

    assigned_at DATETIME,
    triage_due_date DATETIME,
    remediation_due_date DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    patched_at DATETIME,
    FOREIGN KEY(domain) REFERENCES domains(name) ON DELETE SET DEFAULT
    );
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_severity ON tickets(severity);
CREATE INDEX IF NOT EXISTS idx_tickets_domain ON tickets(domain);
CREATE INDEX IF NOT EXISTS idx_tickets_source_asset ON tickets(source, asset_identifier);

CREATE TABLE IF NOT EXISTS ticket_assignments (
                                                  ticket_id INTEGER NOT NULL,
                                                  assignee TEXT NOT NULL,
                                                  role TEXT NOT NULL CHECK(role IN ('RangeHand', 'Wrangler', 'Magistrate')),
    PRIMARY KEY (ticket_id, assignee, role),
    FOREIGN KEY(ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS data_adapters (
                                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                                             name TEXT NOT NULL UNIQUE,
                                             source_name TEXT NOT NULL,
                                             findings_path TEXT NOT NULL DEFAULT '.',
                                             mapping_title TEXT NOT NULL,
                                             mapping_asset TEXT NOT NULL,
                                             mapping_severity TEXT NOT NULL,
                                             mapping_description TEXT,
                                             mapping_remediation TEXT,
                                             created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                             updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sync_logs (
                                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                                         source TEXT NOT NULL,
                                         status TEXT NOT NULL,
                                         records_processed INTEGER NOT NULL,
                                         error_message TEXT,
                                         created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS draft_tickets (
                                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                                             report_id TEXT NOT NULL,
                                             title TEXT DEFAULT '',
                                             description TEXT,
                                             severity TEXT DEFAULT 'Medium',
                                             asset_identifier TEXT DEFAULT '',
                                             recommended_remediation TEXT DEFAULT '',
                                             created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_draft_tickets_report_id ON draft_tickets(report_id);

CREATE INDEX IF NOT EXISTS idx_assignments_assignee ON ticket_assignments(assignee);

CREATE INDEX IF NOT EXISTS idx_tickets_status_asset ON tickets(status, asset_identifier);
CREATE INDEX IF NOT EXISTS idx_tickets_updated_at ON tickets(updated_at);

CREATE INDEX IF NOT EXISTS idx_tickets_analytics ON tickets(status, severity, source);
CREATE INDEX IF NOT EXISTS idx_tickets_due_dates ON tickets(status, remediation_due_date, triage_due_date);
CREATE INDEX IF NOT EXISTS idx_tickets_source_status ON tickets(source, status);
-- the Holding Pen pages by asset: walk this in asset order and stop at LIMIT
CREATE INDEX IF NOT EXISTS idx_tickets_asset_status ON tickets(asset_identifier, status, released);
-- headline counts (open criticals, overdue) read these instead of filtering row by row
CREATE INDEX IF NOT EXISTS idx_tickets_severity_status ON tickets(severity, status, released);
CREATE INDEX IF NOT EXISTS idx_tickets_remediation_due ON tickets(remediation_due_date, status, released);

-- ==========================================
-- Workflow, rules, portals, reporting
-- ==========================================
-- ==========================================
-- 1. THE MISSING AUDIT & ACTIVITY ENGINE
-- ==========================================
CREATE TABLE IF NOT EXISTS ticket_activity (
                                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                                               ticket_id INTEGER NOT NULL,
                                               actor TEXT NOT NULL DEFAULT 'System',
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
    rule_type TEXT NOT NULL CHECK(rule_type IN ('Source', 'Asset', 'Domain')),
    match_value TEXT NOT NULL,
    assignee TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('RangeHand', 'Wrangler')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

CREATE TABLE IF NOT EXISTS auto_triage_rules (
                                                 id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_source TEXT,
    match_asset TEXT,
    match_cve TEXT,
    action_type TEXT NOT NULL CHECK(action_type IN ('DowngradeSeverity', 'AssignOwner', 'MarkFalsePositive')),
    action_value TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

-- ==========================================
-- 2b. ASSET INVENTORY AND PRIORITY RUBRIC
-- ==========================================
-- The book's chapter-two inventory: an asset's exposure and criticality
-- multiply the scanner's severity into a priority at ingest. Owner is shown,
-- not routed on; routing rules take an email.
CREATE TABLE IF NOT EXISTS assets (
    asset_identifier TEXT PRIMARY KEY,
    exposure    TEXT NOT NULL CHECK (exposure IN ('internet', 'internal', 'isolated')),
    criticality TEXT NOT NULL CHECK (criticality IN ('crown-jewel', 'standard', 'dev')),
    owner       TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- The weights are configuration: seeded with the book's numbers, edited in
-- Configuration. score = base x exposure x criticality; a band is the lowest
-- score for that severity, and below Medium is Low.
CREATE TABLE IF NOT EXISTS rubric_weights (
    kind   TEXT NOT NULL CHECK (kind IN ('base', 'exposure', 'criticality', 'band')),
    name   TEXT NOT NULL,
    weight REAL NOT NULL,
    PRIMARY KEY (kind, name)
);
INSERT OR IGNORE INTO rubric_weights (kind, name, weight) VALUES
    ('base', 'Critical', 4), ('base', 'High', 3), ('base', 'Medium', 2), ('base', 'Low', 1), ('base', 'Info', 0),
    ('exposure', 'internet', 2), ('exposure', 'internal', 1), ('exposure', 'isolated', 0.5),
    ('criticality', 'crown-jewel', 2), ('criticality', 'standard', 1), ('criticality', 'dev', 0.5),
    ('band', 'Critical', 12), ('band', 'High', 6), ('band', 'Medium', 3);

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
                                             kind TEXT NOT NULL DEFAULT 'owner' CHECK (kind IN ('owner', 'approver')),
                                             assignee TEXT NOT NULL DEFAULT '', -- the owner an owner link was minted for
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
    name TEXT NOT NULL,
    permissions TEXT NOT NULL CHECK(permissions IN ('WriteOnly', 'ReadOnly', 'FullAdmin')),
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    last_used_at DATETIME
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
-- 5a0. FINDING TEMPLATES (reusable finding blueprints)
-- ==========================================
CREATE TABLE IF NOT EXISTS finding_templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    title       TEXT,
    severity    TEXT,
    description TEXT,
    remediation TEXT,
    tags        TEXT,
    cvss_vector TEXT,
    cvss_score  REAL,
    cwe         TEXT,
    business_impact TEXT,
    created_by  TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- 5a. ENGAGEMENTS (a pentest, owned by a Bounty Hunter)
-- ==========================================
CREATE TABLE IF NOT EXISTS engagements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    number      TEXT UNIQUE,                       -- auto-assigned ENG-0001
    name        TEXT NOT NULL,
    client      TEXT,
    owner_email TEXT,                              -- the Bounty Hunter
    status      TEXT NOT NULL DEFAULT 'Active',    -- Active | Released | Closed
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- 5a2. SEVERITY PROPOSALS (RangeHand <-> Bounty Hunter negotiation)
-- ==========================================
CREATE TABLE IF NOT EXISTS severity_proposals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id       INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    from_severity   TEXT,
    to_severity     TEXT NOT NULL,
    justification   TEXT NOT NULL,
    proposed_by     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'Pending', -- Pending | Accepted | Contested | Resolved
    resolved_by     TEXT,
    resolution_note TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at     DATETIME
);
CREATE INDEX IF NOT EXISTS idx_sev_proposals_status ON severity_proposals(status);
CREATE INDEX IF NOT EXISTS idx_sev_proposals_ticket ON severity_proposals(ticket_id);

-- ==========================================
-- 5a3. EVIDENCE (screenshots/images attached to findings)
-- ==========================================
CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id    INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    caption      TEXT,
    content_type TEXT NOT NULL,          -- image/png or image/jpeg
    width        INTEGER,
    height       INTEGER,
    size         INTEGER,                -- bytes of the web image
    image_data   BLOB NOT NULL,          -- re-encoded, EXIF-stripped, bounded web image
    thumb_data   BLOB NOT NULL,          -- thumbnail
    created_by   TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_evidence_ticket ON evidence(ticket_id);

-- ==========================================
-- 5b. PENTEST REPORTS (findings -> deliverable)
-- ==========================================
CREATE TABLE IF NOT EXISTS pentest_reports (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    title             TEXT NOT NULL,
    client_name       TEXT,
    author            TEXT,
    scope             TEXT,
    executive_summary TEXT,
    body              TEXT,                        -- author prose/narrative (editable)
    engagement_id     INTEGER,                     -- optional link to an engagement
    ticket_ids        TEXT NOT NULL DEFAULT '[]', -- JSON array of the finding IDs snapshotted
    markdown          TEXT NOT NULL DEFAULT '',   -- rendered deliverable (frozen at generation)
    html              TEXT NOT NULL DEFAULT '',   -- rendered deliverable (frozen at generation)
    created_by        TEXT,
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- 6. INDEXES
-- ==========================================
CREATE INDEX IF NOT EXISTS idx_activity_ticket_id ON ticket_activity(ticket_id);
CREATE INDEX IF NOT EXISTS idx_activity_created_at ON ticket_activity(created_at);
CREATE INDEX IF NOT EXISTS idx_global_suppression ON global_suppression_rules(is_active);
CREATE INDEX IF NOT EXISTS idx_tickets_cisa_kev ON tickets(status) WHERE is_cisa_kev = 1;
