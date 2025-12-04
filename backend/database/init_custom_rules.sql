-- Custom Security Rules Database Schema

-- Custom rules table
CREATE TABLE IF NOT EXISTS custom_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    pattern TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    description TEXT NOT NULL,
    language VARCHAR(50) DEFAULT '*',

    -- Optional classification
    cwe VARCHAR(50),
    owasp VARCHAR(100),
    remediation TEXT,
    remediation_code TEXT,

    -- Metadata
    enabled BOOLEAN DEFAULT true,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Generation metadata
    generated_by VARCHAR(20) CHECK (generated_by IN ('ai', 'user', 'cve', 'threat_intel')),
    source VARCHAR(500),
    confidence VARCHAR(10) CHECK (confidence IN ('high', 'medium', 'low')),

    -- Performance tracking
    total_detections INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    true_positives INTEGER DEFAULT 0,
    precision DECIMAL(5,4),

    UNIQUE(name, language)
);

-- Indexes for custom_rules
CREATE INDEX idx_custom_rules_enabled ON custom_rules(enabled);
CREATE INDEX idx_custom_rules_severity ON custom_rules(severity);
CREATE INDEX idx_custom_rules_language ON custom_rules(language);
CREATE INDEX idx_custom_rules_created_by ON custom_rules(created_by);
CREATE INDEX idx_custom_rules_generated_by ON custom_rules(generated_by);

-- Rule performance metrics table
CREATE TABLE IF NOT EXISTS rule_performance_metrics (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER NOT NULL REFERENCES custom_rules(id) ON DELETE CASCADE,
    finding_id INTEGER,
    user_feedback VARCHAR(20) NOT NULL CHECK (user_feedback IN ('resolved', 'false_positive', 'ignored', 'confirmed')),
    code_snippet TEXT,
    file_path VARCHAR(500),
    feedback_comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER
);

-- Indexes for performance metrics
CREATE INDEX idx_rule_perf_rule_id ON rule_performance_metrics(rule_id);
CREATE INDEX idx_rule_perf_feedback ON rule_performance_metrics(user_feedback);
CREATE INDEX idx_rule_perf_created_at ON rule_performance_metrics(created_at);

-- Enhancement jobs table
CREATE TABLE IF NOT EXISTS enhancement_jobs (
    id SERIAL PRIMARY KEY,
    job_type VARCHAR(50) NOT NULL CHECK (job_type IN ('generate_cve', 'refine_rules', 'threat_intel', 'enhance_existing')),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    triggered_by VARCHAR(255) NOT NULL,

    -- Results
    rules_generated INTEGER DEFAULT 0,
    rules_refined INTEGER DEFAULT 0,
    errors JSONB DEFAULT '[]'::jsonb,

    -- Input parameters
    parameters JSONB,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for enhancement jobs
CREATE INDEX idx_enhancement_jobs_status ON enhancement_jobs(status);
CREATE INDEX idx_enhancement_jobs_triggered_by ON enhancement_jobs(triggered_by);
CREATE INDEX idx_enhancement_jobs_created_at ON enhancement_jobs(created_at);

-- Rule enhancement logs table
CREATE TABLE IF NOT EXISTS rule_enhancement_logs (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER NOT NULL REFERENCES custom_rules(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL CHECK (action IN ('created', 'refined', 'enabled', 'disabled', 'deleted', 'pattern_updated', 'severity_changed')),
    old_pattern TEXT,
    new_pattern TEXT,
    reason TEXT NOT NULL,
    performed_by VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ai_generated BOOLEAN DEFAULT false,

    -- Additional metadata
    changes JSONB
);

-- Indexes for enhancement logs
CREATE INDEX idx_enhancement_logs_rule_id ON rule_enhancement_logs(rule_id);
CREATE INDEX idx_enhancement_logs_action ON rule_enhancement_logs(action);
CREATE INDEX idx_enhancement_logs_timestamp ON rule_enhancement_logs(timestamp);
CREATE INDEX idx_enhancement_logs_ai_generated ON rule_enhancement_logs(ai_generated);

-- Function to update precision automatically
CREATE OR REPLACE FUNCTION update_rule_precision()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE custom_rules
    SET
        precision = CASE
            WHEN (true_positives + false_positives) > 0
            THEN true_positives::decimal / (true_positives + false_positives)
            ELSE NULL
        END,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = NEW.rule_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update precision when metrics change
CREATE TRIGGER trigger_update_rule_precision
AFTER INSERT ON rule_performance_metrics
FOR EACH ROW
EXECUTE FUNCTION update_rule_precision();

-- Function to update detection counts
CREATE OR REPLACE FUNCTION increment_rule_detection()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE custom_rules
    SET
        total_detections = total_detections + 1,
        false_positives = CASE WHEN NEW.user_feedback = 'false_positive' THEN false_positives + 1 ELSE false_positives END,
        true_positives = CASE WHEN NEW.user_feedback IN ('resolved', 'confirmed') THEN true_positives + 1 ELSE true_positives END,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = NEW.rule_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to increment detection counts
CREATE TRIGGER trigger_increment_detection
AFTER INSERT ON rule_performance_metrics
FOR EACH ROW
EXECUTE FUNCTION increment_rule_detection();

-- View for rule performance statistics
CREATE OR REPLACE VIEW rule_performance_stats AS
SELECT
    cr.id AS rule_id,
    cr.name AS rule_name,
    cr.severity,
    cr.language,
    cr.enabled,
    cr.total_detections,
    cr.true_positives,
    cr.false_positives,
    COUNT(CASE WHEN rpm.user_feedback = 'ignored' THEN 1 END) AS ignored,
    cr.precision,
    CASE
        WHEN cr.precision IS NOT NULL AND cr.precision < 0.85 THEN true
        ELSE false
    END AS needs_refinement,
    MAX(rpm.created_at) AS last_detection,
    cr.created_at,
    cr.created_by,
    cr.generated_by
FROM custom_rules cr
LEFT JOIN rule_performance_metrics rpm ON cr.id = rpm.rule_id
GROUP BY cr.id, cr.name, cr.severity, cr.language, cr.enabled, cr.total_detections,
         cr.true_positives, cr.false_positives, cr.precision, cr.created_at, cr.created_by, cr.generated_by
ORDER BY cr.total_detections DESC;

-- Insert some initial custom rules as examples
INSERT INTO custom_rules (name, pattern, severity, description, language, cwe, owasp, remediation, enabled, created_by, generated_by) VALUES
('Hardcoded AWS Credentials', 'AKIA[0-9A-Z]{16}', 'critical', 'Detects hardcoded AWS access keys', '*', 'CWE-798', 'A07:2021 - Identification and Authentication Failures', 'Remove hardcoded credentials and use AWS IAM roles or environment variables', true, 'system', 'user'),
('Insecure Random Number Generation', '(Math\.random|random\.random|rand)\s*\(', 'medium', 'Detects use of weak random number generators for security purposes', '*', 'CWE-330', 'A02:2021 - Cryptographic Failures', 'Use cryptographically secure random number generators like secrets module in Python or crypto.randomBytes in Node.js', true, 'system', 'user'),
('Command Injection via exec', 'exec\s*\(\s*[^)]*\+', 'critical', 'Detects potential command injection through string concatenation with exec', '*', 'CWE-78', 'A03:2021 - Injection', 'Avoid using exec with user input. Use parameterized commands or whitelist validation', true, 'system', 'user');

COMMENT ON TABLE custom_rules IS 'User-defined and AI-generated security detection rules';
COMMENT ON TABLE rule_performance_metrics IS 'Performance feedback for custom rules';
COMMENT ON TABLE enhancement_jobs IS 'AI enhancement job tracking';
COMMENT ON TABLE rule_enhancement_logs IS 'Audit log for rule modifications';
