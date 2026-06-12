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