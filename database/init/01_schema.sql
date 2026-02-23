-- AppSec Platform Database Schema
-- PostgreSQL initialization script for fresh deployment
-- This script runs automatically on first container startup

-- Enable UUID extension (optional but useful)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==================== ENUM TYPES ====================

CREATE TYPE scan_type AS ENUM ('sast', 'sca', 'secret', 'threat_model');
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed');
CREATE TYPE profile_status AS ENUM ('pending', 'profiling', 'analyzing', 'generating_suggestions', 'completed', 'failed');
CREATE TYPE suggestion_status AS ENUM ('pending', 'accepted', 'dismissed', 'implemented');
CREATE TYPE story_source AS ENUM ('manual', 'jira', 'ado', 'github', 'snow');
CREATE TYPE integration_type AS ENUM ('jira', 'ado', 'snow');
CREATE TYPE feedback_type AS ENUM ('abuse_case', 'security_requirement');
CREATE TYPE feedback_rating AS ENUM ('positive', 'negative');
CREATE TYPE threat_status AS ENUM ('new', 'existing', 'modified', 'resolved');

-- ==================== CORE TABLES ====================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    preferred_language VARCHAR(10) DEFAULT 'en',

    -- AI Provider Configuration
    ai_provider VARCHAR(50) DEFAULT 'anthropic',
    ai_api_key TEXT,
    ai_model VARCHAR(100),
    ai_base_url VARCHAR(500),
    ai_api_version VARCHAR(50),

    -- Custom SecureReq Prompts
    custom_abuse_case_prompt TEXT,
    custom_security_req_prompt TEXT,
    use_custom_prompts BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    architecture_doc TEXT,
    architecture_diagram TEXT,
    diagram_media_type VARCHAR(50),
    repository_url VARCHAR(500),
    technology_stack JSONB,
    compliance_targets JSONB,
    risk_score FLOAT DEFAULT 0.0,
    owner_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Architecture Versions table (for incremental threat modeling)
CREATE TABLE IF NOT EXISTS architecture_versions (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    architecture_hash VARCHAR(64) NOT NULL,
    architecture_snapshot JSONB NOT NULL,
    change_summary JSONB,
    change_description TEXT,
    impact_score FLOAT DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_arch_versions_project ON architecture_versions(project_id, version_number DESC);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_type scan_type NOT NULL,
    status scan_status DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    scan_config JSONB,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id INTEGER,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity severity_level NOT NULL,
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    cvss_score FLOAT,
    file_path VARCHAR(1000),
    line_number INTEGER,
    code_snippet TEXT,
    remediation TEXT,
    remediation_code TEXT,
    stride_category VARCHAR(50),
    mitre_attack_id VARCHAR(20),
    mitre_attack_name VARCHAR(200),
    is_resolved BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- AI-generated impact fields
    business_impact TEXT,
    technical_impact TEXT,
    recommendations TEXT,
    impact_generated_by VARCHAR(50)
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);

-- Threat Models table
CREATE TABLE IF NOT EXISTS threat_models (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    dfd_level INTEGER DEFAULT 0,
    dfd_data JSONB,
    stride_analysis JSONB,
    mitre_mapping JSONB,
    trust_boundaries JSONB,
    data_flows JSONB,
    assets JSONB,
    attack_paths JSONB,
    threat_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE,

    -- Enhanced threat modeling fields
    fair_risk_analysis JSONB,
    attack_trees JSONB,
    kill_chain_analysis JSONB,
    eraser_diagrams JSONB,

    -- Incremental threat modeling fields
    architecture_version_id INTEGER REFERENCES architecture_versions(id),
    is_incremental BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_threat_models_project ON threat_models(project_id);

-- Threat History table (for tracking threat lifecycle)
CREATE TABLE IF NOT EXISTS threat_history (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    threat_id VARCHAR(100) NOT NULL,
    architecture_version_id INTEGER NOT NULL REFERENCES architecture_versions(id),
    status threat_status NOT NULL,
    threat_data JSONB NOT NULL,
    previous_history_id INTEGER REFERENCES threat_history(id),
    change_reason VARCHAR(500),
    affected_components JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_history_project ON threat_history(project_id);
CREATE INDEX IF NOT EXISTS idx_threat_history_threat_id ON threat_history(threat_id);
CREATE INDEX IF NOT EXISTS idx_threat_history_version ON threat_history(architecture_version_id);

-- Chat Messages table
CREATE TABLE IF NOT EXISTS chat_messages (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message TEXT NOT NULL,
    response TEXT,
    detected_language VARCHAR(10),
    context_type VARCHAR(50),
    context_id INTEGER,
    model_used VARCHAR(50),
    tokens_used INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_user ON chat_messages(user_id);

-- System Settings table
CREATE TABLE IF NOT EXISTS system_settings (
    id SERIAL PRIMARY KEY,
    key VARCHAR(100) UNIQUE NOT NULL,
    value TEXT,
    description VARCHAR(500),
    is_secret BOOLEAN DEFAULT FALSE,
    category VARCHAR(50) DEFAULT 'general',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_system_settings_key ON system_settings(key);

-- ==================== APPLICATION INTELLIGENCE ====================

-- Application Profiles table
CREATE TABLE IF NOT EXISTS application_profiles (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,

    -- Profiling Status
    status profile_status DEFAULT 'pending',
    status_message VARCHAR(500),
    profiling_progress INTEGER DEFAULT 0,

    -- Technology Stack
    languages JSONB,
    frameworks JSONB,
    databases JSONB,
    orm_libraries JSONB,

    -- Architecture Analysis
    entry_points JSONB,
    sensitive_data_fields JSONB,
    auth_mechanisms JSONB,

    -- Dependencies
    dependencies JSONB,
    dev_dependencies JSONB,
    vulnerable_dependencies JSONB,

    -- External Integrations
    external_integrations JSONB,
    cloud_services JSONB,

    -- Code Metrics
    file_count INTEGER DEFAULT 0,
    total_lines_of_code INTEGER DEFAULT 0,
    test_coverage FLOAT,

    -- Security Posture Summary
    security_score FLOAT,
    risk_level VARCHAR(20),
    total_suggestions INTEGER DEFAULT 0,
    critical_suggestions INTEGER DEFAULT 0,
    high_suggestions INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE,
    last_profiled_at TIMESTAMP WITH TIME ZONE
);

-- Suggested Rules table
CREATE TABLE IF NOT EXISTS suggested_rules (
    id SERIAL PRIMARY KEY,
    application_profile_id INTEGER NOT NULL REFERENCES application_profiles(id) ON DELETE CASCADE,

    -- Rule Details
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    severity severity_level NOT NULL,

    -- Why this rule is suggested
    reason TEXT,
    detected_patterns JSONB,
    framework_context VARCHAR(100),

    -- Generated Rule Content
    rule_pattern TEXT,
    rule_type VARCHAR(50) DEFAULT 'semgrep',

    -- Multi-format exports
    semgrep_rule TEXT,
    codeql_rule TEXT,
    checkmarx_rule TEXT,
    fortify_rule TEXT,

    -- Rule metadata
    cwe_ids JSONB,
    owasp_categories JSONB,
    mitre_techniques JSONB,

    -- Status and feedback
    status suggestion_status DEFAULT 'pending',
    confidence_score FLOAT,
    user_feedback VARCHAR(50),
    feedback_comment TEXT,
    created_rule_id INTEGER,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP WITH TIME ZONE
);

-- ==================== SECUREREQ MODELS ====================

-- User Stories table
CREATE TABLE IF NOT EXISTS user_stories (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,

    -- Story Details
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    acceptance_criteria TEXT,

    -- Source tracking
    source story_source DEFAULT 'manual',
    external_id VARCHAR(100),
    external_url VARCHAR(500),

    -- Analysis status
    is_analyzed BOOLEAN DEFAULT FALSE,
    risk_score INTEGER DEFAULT 0,
    threat_count INTEGER DEFAULT 0,
    requirement_count INTEGER DEFAULT 0,

    -- Timestamps
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_user_stories_project ON user_stories(project_id);

-- Security Analyses table
CREATE TABLE IF NOT EXISTS security_analyses (
    id SERIAL PRIMARY KEY,
    user_story_id INTEGER NOT NULL REFERENCES user_stories(id) ON DELETE CASCADE,

    -- Version tracking
    version INTEGER DEFAULT 1,

    -- Analysis Results
    abuse_cases JSONB,
    stride_threats JSONB,
    security_requirements JSONB,

    -- Risk Assessment
    risk_score INTEGER DEFAULT 0,
    risk_factors JSONB,

    -- AI metadata
    ai_model_used VARCHAR(100),
    analysis_duration_ms INTEGER,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Compliance Mappings table
CREATE TABLE IF NOT EXISTS compliance_mappings (
    id SERIAL PRIMARY KEY,
    analysis_id INTEGER NOT NULL REFERENCES security_analyses(id) ON DELETE CASCADE,

    -- Requirement reference
    requirement_id VARCHAR(50),
    requirement_text TEXT,

    -- Compliance mapping
    standard_name VARCHAR(100),
    control_id VARCHAR(50),
    control_title VARCHAR(500),
    control_description TEXT,

    -- Relevance scoring
    relevance_score FLOAT,
    mapping_rationale TEXT
);

-- Custom Standards table
CREATE TABLE IF NOT EXISTS custom_standards (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,

    -- Standard details
    name VARCHAR(255) NOT NULL,
    description TEXT,
    version VARCHAR(50),

    -- File metadata
    file_type VARCHAR(20),
    original_filename VARCHAR(255),

    -- Parsed controls
    controls JSONB,
    control_count INTEGER DEFAULT 0,

    -- Timestamps
    uploaded_by INTEGER REFERENCES users(id),
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ==================== INTEGRATION SETTINGS ====================

-- Integration Settings table
CREATE TABLE IF NOT EXISTS integration_settings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    integration_type integration_type NOT NULL,

    -- Connection Details
    base_url VARCHAR(500) NOT NULL,
    username VARCHAR(255),
    api_token TEXT,

    -- Custom field configuration
    abuse_cases_field VARCHAR(100),
    security_req_field VARCHAR(100),

    -- Status
    is_connected BOOLEAN DEFAULT FALSE,
    last_connected_at TIMESTAMP WITH TIME ZONE,
    connection_error TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE,

    UNIQUE(user_id, integration_type)
);

-- Project Integrations table
CREATE TABLE IF NOT EXISTS project_integrations (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    integration_type integration_type NOT NULL,

    -- External project identifier
    external_project_id VARCHAR(100),
    external_project_name VARCHAR(255),

    -- Sync configuration
    sync_enabled BOOLEAN DEFAULT TRUE,
    auto_publish BOOLEAN DEFAULT FALSE,
    issue_types JSONB,

    -- SNOW specific
    snow_table VARCHAR(100),
    snow_assignment_group VARCHAR(100),

    -- Sync status
    last_synced_at TIMESTAMP WITH TIME ZONE,
    sync_status VARCHAR(50),
    sync_error TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE,

    UNIQUE(project_id, integration_type)
);

-- ==================== PROMPT FEEDBACK ====================

-- Prompt Feedback table
CREATE TABLE IF NOT EXISTS prompt_feedback (
    id SERIAL PRIMARY KEY,
    feedback_type feedback_type NOT NULL,
    rating feedback_rating NOT NULL,
    content JSONB NOT NULL,
    story_title VARCHAR(500),
    story_description TEXT,
    user_id INTEGER REFERENCES users(id),
    comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_prompt_feedback_type ON prompt_feedback(feedback_type);
CREATE INDEX IF NOT EXISTS idx_prompt_feedback_rating ON prompt_feedback(rating);

-- ==================== CUSTOM RULES ====================

-- Custom Rules table
CREATE TABLE IF NOT EXISTS custom_rules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    pattern TEXT NOT NULL,
    severity severity_level DEFAULT 'medium',
    category VARCHAR(100),
    language VARCHAR(50) DEFAULT '*',
    enabled BOOLEAN DEFAULT TRUE,

    -- Performance metrics
    scan_count INTEGER DEFAULT 0,
    match_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    true_positive_count INTEGER DEFAULT 0,

    -- CWE/OWASP mapping
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_custom_rules_user ON custom_rules(user_id);
CREATE INDEX IF NOT EXISTS idx_custom_rules_enabled ON custom_rules(enabled);

-- ==================== INITIAL DATA ====================

-- Create default admin user (password: admin123 - CHANGE IN PRODUCTION!)
-- Password hash for 'admin123' using bcrypt
INSERT INTO users (email, username, hashed_password, full_name, is_active, is_admin)
VALUES (
    'admin@appsec.local',
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4o1xYUhb7N.vA.Ty',
    'System Administrator',
    TRUE,
    TRUE
) ON CONFLICT (email) DO NOTHING;

-- Insert default system settings
INSERT INTO system_settings (key, value, description, category)
VALUES
    ('nvd_api_key', NULL, 'NVD API Key for vulnerability data', 'threat_intel'),
    ('misp_api_key', NULL, 'MISP API Key for threat intelligence', 'threat_intel'),
    ('misp_url', NULL, 'MISP Server URL', 'threat_intel'),
    ('github_token', NULL, 'GitHub Token for advisory data', 'sca_feeds'),
    ('snyk_token', NULL, 'Snyk Token for vulnerability data', 'sca_feeds')
ON CONFLICT (key) DO NOTHING;

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'AppSec Platform database initialized successfully!';
END $$;
