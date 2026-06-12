-- =============================================================================
-- PostgreSQL Initialization Script
-- Database: soc_analyst
-- Run automatically on first container start
-- =============================================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For fast text search

-- =============================================================================
-- ALERTS TABLE
-- Stores normalized Wazuh alerts for the AI agent pipeline
-- =============================================================================
CREATE TABLE IF NOT EXISTS alerts (
    id                      VARCHAR(64) PRIMARY KEY,   -- Wazuh alert ID
    wazuh_id                VARCHAR(128),               -- Wazuh internal ID
    timestamp               TIMESTAMPTZ NOT NULL,
    
    -- Rule information
    rule_id                 VARCHAR(16) NOT NULL,
    rule_description        TEXT NOT NULL,
    rule_level              SMALLINT NOT NULL,          -- Wazuh severity 1-15
    rule_groups             TEXT[],                    -- e.g. {authentication_failed, sshd}
    mitre_ids               TEXT[],                    -- e.g. {T1110.001}
    
    -- Agent information
    agent_id                VARCHAR(16),
    agent_name              VARCHAR(128),
    agent_ip                VARCHAR(45),               -- IPv4 or IPv6
    
    -- Network observables
    src_ip                  VARCHAR(45),
    dst_ip                  VARCHAR(45),
    src_port                INTEGER,
    dst_port                INTEGER,
    protocol                VARCHAR(16),
    
    -- Identity
    username                VARCHAR(128),
    
    -- Raw data
    raw_data                JSONB NOT NULL,
    location                TEXT,                      -- Log source path
    
    -- Investigation tracking
    investigation_status    VARCHAR(32) DEFAULT 'new'  -- new|triaged|investigating|closed|false_positive
                            CHECK (investigation_status IN ('new','triaged','investigating','closed','false_positive')),
    investigation_id        UUID,                      -- FK to investigations table
    
    -- Metadata
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for fast querying
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp        ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_level       ON alerts (rule_level DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id          ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_name       ON alerts (agent_name);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip           ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status           ON alerts (investigation_status);
CREATE INDEX IF NOT EXISTS idx_alerts_raw_data         ON alerts USING GIN (raw_data);


-- =============================================================================
-- INVESTIGATIONS TABLE
-- Each investigation is triggered by one alert but may correlate many
-- =============================================================================
CREATE TABLE IF NOT EXISTS investigations (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Trigger
    trigger_alert_id        VARCHAR(64) REFERENCES alerts(id),
    
    -- Classification
    classification          VARCHAR(32)                -- false_positive|suspicious|confirmed_threat
                            CHECK (classification IN ('false_positive','suspicious','confirmed_threat','unknown')),
    severity                VARCHAR(16)                -- Low|Medium|High|Critical
                            CHECK (severity IN ('Low','Medium','High','Critical')),
    
    -- AI outputs
    summary                 TEXT,
    attack_type             VARCHAR(128),
    mitre_tactics           TEXT[],
    mitre_techniques        TEXT[],
    false_positive_score    FLOAT CHECK (false_positive_score BETWEEN 0 AND 1),
    
    -- Related alerts
    related_alert_ids       TEXT[],
    
    -- Status workflow
    status                  VARCHAR(32) DEFAULT 'in_progress'
                            CHECK (status IN ('in_progress','awaiting_response','closed','escalated')),
    
    -- Evidence collected
    threat_intel_results    JSONB DEFAULT '{}',
    network_intel_results   JSONB DEFAULT '{}',
    endpoint_intel_results  JSONB DEFAULT '{}',
    
    -- Final report
    report_markdown         TEXT,
    report_json             JSONB,
    
    -- Timestamps
    started_at              TIMESTAMPTZ DEFAULT NOW(),
    completed_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_investigations_status        ON investigations (status);
CREATE INDEX IF NOT EXISTS idx_investigations_classification ON investigations (classification);
CREATE INDEX IF NOT EXISTS idx_investigations_severity       ON investigations (severity);
CREATE INDEX IF NOT EXISTS idx_investigations_started_at     ON investigations (started_at DESC);



-- =============================================================================
-- RESPONSE ACTIONS TABLE
-- Human-in-the-loop approval queue for automated responses
-- =============================================================================
CREATE TABLE IF NOT EXISTS response_actions (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id    UUID REFERENCES investigations(id),
    alert_id            VARCHAR(64) REFERENCES alerts(id),
    
    -- Action definition
    action_type         VARCHAR(64) NOT NULL,          -- block_ip|disable_user|kill_process|isolate_endpoint|create_ticket
    target              VARCHAR(256) NOT NULL,          -- IP, username, PID, hostname, etc.
    reason              TEXT NOT NULL,
    
    -- Approval workflow
    requires_approval   BOOLEAN DEFAULT TRUE,
    approval_status     VARCHAR(32) DEFAULT 'pending'  -- pending|approved|rejected|auto_approved
                        CHECK (approval_status IN ('pending','approved','rejected','auto_approved')),
    approved_by         VARCHAR(128),
    approval_notes      TEXT,
    
    -- Execution
    executed            BOOLEAN DEFAULT FALSE,
    executed_at         TIMESTAMPTZ,
    execution_result    JSONB,
    error_message       TEXT,
    
    -- Timestamps
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions (approval_status);
CREATE INDEX IF NOT EXISTS idx_response_actions_type   ON response_actions (action_type);


-- =============================================================================
-- INCIDENT MEMORY TABLE
-- Persistent knowledge base for cross-incident correlation
-- =============================================================================
CREATE TABLE IF NOT EXISTS incident_memory (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Source
    investigation_id UUID REFERENCES investigations(id),
    
    -- IOCs
    ioc_type        VARCHAR(32)      -- ip|domain|hash|username|hostname
                    CHECK (ioc_type IN ('ip','domain','hash','username','hostname','url')),
    ioc_value       VARCHAR(256) NOT NULL,
    
    -- Context
    context         JSONB DEFAULT '{}',
    tags            TEXT[],
    
    -- Reputation (cached)
    reputation_score    FLOAT,
    reputation_data     JSONB DEFAULT '{}',
    
    -- Timestamps
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    occurrence_count INTEGER DEFAULT 1,
    
    UNIQUE(ioc_type, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_memory_ioc_value ON incident_memory (ioc_value);
CREATE INDEX IF NOT EXISTS idx_memory_ioc_type  ON incident_memory (ioc_type);
CREATE INDEX IF NOT EXISTS idx_memory_last_seen ON incident_memory (last_seen DESC);



-- =============================================================================
-- ANALYST NOTES TABLE
-- Human analyst annotations on investigations
-- =============================================================================
CREATE TABLE IF NOT EXISTS analyst_notes (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id),
    alert_id        VARCHAR(64) REFERENCES alerts(id),
    
    author          VARCHAR(128) DEFAULT 'analyst',
    note_type       VARCHAR(32) DEFAULT 'comment'      -- comment|false_positive|escalation|resolution
                    CHECK (note_type IN ('comment','false_positive','escalation','resolution','evidence')),
    content         TEXT NOT NULL,
    
    created_at      TIMESTAMPTZ DEFAULT NOW()
);


-- =============================================================================
-- AUTO-UPDATE updated_at trigger
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER investigations_updated_at
    BEFORE UPDATE ON investigations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER response_actions_updated_at
    BEFORE UPDATE ON response_actions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- =============================================================================
-- VIEWS for common queries
-- =============================================================================

-- Active unreviewed alerts (dashboard feed)
CREATE OR REPLACE VIEW v_active_alerts AS
SELECT
    id, timestamp, rule_id, rule_description, rule_level,
    agent_name, agent_ip, src_ip, username, investigation_status
FROM alerts
WHERE investigation_status IN ('new', 'triaged')
ORDER BY rule_level DESC, timestamp DESC;

-- Open investigations summary
CREATE OR REPLACE VIEW v_open_investigations AS
SELECT
    i.id, i.started_at, i.classification, i.severity, i.status,
    a.rule_description AS trigger_rule,
    a.agent_name, a.src_ip,
    ARRAY_LENGTH(i.related_alert_ids, 1) AS related_count
FROM investigations i
JOIN alerts a ON a.id = i.trigger_alert_id
WHERE i.status NOT IN ('closed')
ORDER BY i.started_at DESC;

-- Pending response actions (approval queue)
CREATE OR REPLACE VIEW v_pending_approvals AS
SELECT
    r.id, r.action_type, r.target, r.reason,
    r.created_at, i.severity,
    a.rule_description
FROM response_actions r
JOIN investigations i ON i.id = r.investigation_id
JOIN alerts a ON a.id = r.alert_id
WHERE r.approval_status = 'pending'
ORDER BY i.severity DESC, r.created_at ASC;


-- Seed some data for testing (remove in production)
-- INSERT INTO alerts (id, timestamp, rule_id, rule_description, rule_level, agent_id, agent_name, src_ip, raw_data)
-- VALUES ('test-001', NOW(), '5710', 'SSH brute force attempt', 10, '001', 'test-host', '10.0.0.5', '{}');

\echo 'Database initialized successfully!'