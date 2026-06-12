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
