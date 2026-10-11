CREATE TABLE IF NOT EXISTS app_config (
                                          id INTEGER PRIMARY KEY CHECK (id = 1),
    timezone TEXT DEFAULT 'America/New_York',
    business_start INTEGER DEFAULT 9,
    business_end INTEGER DEFAULT 17,
    default_extension_days INTEGER DEFAULT 30,
    backup_enabled BOOLEAN DEFAULT 1,
    backup_interval_hours INTEGER DEFAULT 24,
    backup_retention_days INTEGER DEFAULT 30
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
                                     global_role TEXT NOT NULL CHECK(global_role IN ('Sheriff', 'RangeHand', 'Wrangler', 'CircuitRider', 'Magistrate')),
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
                                       cve_id TEXT,
                                       audit_id TEXT UNIQUE,
                                       compliance_tags TEXT,
                                       title TEXT NOT NULL,
                                       description TEXT,
                                       recommended_remediation TEXT,
                                       severity TEXT NOT NULL,
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
    dedupe_hash TEXT UNIQUE NOT NULL,
    patch_evidence TEXT,
    accessible_to_internet BOOLEAN DEFAULT 0,
    assignee TEXT DEFAULT 'Unassigned',
    latest_comment TEXT DEFAULT '',

    -- 🚀 RE-ADDED: The missing Enterprise Risk & CISA tracking fields!
    is_cisa_kev BOOLEAN DEFAULT 0,
    verification_requested_at DATETIME,
    extension_count INTEGER DEFAULT 0,
    risk_rationale TEXT,
    risk_evidence TEXT,
    risk_approved_by TEXT,
    risk_approved_at DATETIME,
    exception_expires_at DATETIME,

    assigned_at DATETIME,
    owner_viewed_at DATETIME,
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