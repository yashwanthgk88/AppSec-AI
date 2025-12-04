"""Initialize custom rules database tables in SQLite"""
import sqlite3

# Connect to SQLite database
conn = sqlite3.connect('appsec.db')
cursor = conn.cursor()

# Custom rules table
cursor.execute('''
CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    description TEXT NOT NULL,
    language TEXT DEFAULT '*',

    -- Optional classification
    cwe TEXT,
    owasp TEXT,
    remediation TEXT,
    remediation_code TEXT,

    -- Metadata
    enabled INTEGER DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Generation metadata
    generated_by TEXT CHECK (generated_by IN ('ai', 'user', 'cve', 'threat_intel')),
    source TEXT,
    confidence TEXT CHECK (confidence IN ('high', 'medium', 'low')),

    -- Performance tracking
    total_detections INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    true_positives INTEGER DEFAULT 0,
    precision REAL,

    UNIQUE(name, language)
)
''')

# Indexes for custom_rules
cursor.execute('CREATE INDEX IF NOT EXISTS idx_custom_rules_enabled ON custom_rules(enabled)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_custom_rules_severity ON custom_rules(severity)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_custom_rules_language ON custom_rules(language)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_custom_rules_created_by ON custom_rules(created_by)')

# Rule performance metrics table
cursor.execute('''
CREATE TABLE IF NOT EXISTS rule_performance_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    finding_id INTEGER,
    user_feedback TEXT NOT NULL CHECK (user_feedback IN ('resolved', 'false_positive', 'ignored', 'confirmed')),
    code_snippet TEXT,
    file_path TEXT,
    feedback_comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY (rule_id) REFERENCES custom_rules(id) ON DELETE CASCADE
)
''')

cursor.execute('CREATE INDEX IF NOT EXISTS idx_rule_perf_rule_id ON rule_performance_metrics(rule_id)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_rule_perf_feedback ON rule_performance_metrics(user_feedback)')

# Enhancement jobs table
cursor.execute('''
CREATE TABLE IF NOT EXISTS enhancement_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type TEXT NOT NULL CHECK (job_type IN ('generate_cve', 'refine_rules', 'threat_intel', 'enhance_existing', 'generate_custom')),
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    triggered_by TEXT NOT NULL,

    -- Results
    rules_generated INTEGER DEFAULT 0,
    rules_refined INTEGER DEFAULT 0,
    errors TEXT,

    -- Input parameters
    parameters TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

cursor.execute('CREATE INDEX IF NOT EXISTS idx_enhancement_jobs_status ON enhancement_jobs(status)')

# Rule enhancement logs table
cursor.execute('''
CREATE TABLE IF NOT EXISTS rule_enhancement_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('created', 'refined', 'enabled', 'disabled', 'deleted', 'pattern_updated', 'severity_changed')),
    old_pattern TEXT,
    new_pattern TEXT,
    reason TEXT NOT NULL,
    performed_by TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ai_generated INTEGER DEFAULT 0,
    changes TEXT,
    FOREIGN KEY (rule_id) REFERENCES custom_rules(id) ON DELETE CASCADE
)
''')

cursor.execute('CREATE INDEX IF NOT EXISTS idx_enhancement_logs_rule_id ON rule_enhancement_logs(rule_id)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_enhancement_logs_action ON rule_enhancement_logs(action)')

# Insert default custom rules
default_rules = [
    ('Hardcoded AWS Credentials', r'AKIA[0-9A-Z]{16}', 'critical', 'Detects hardcoded AWS access keys', '*', 'CWE-798', 'A07:2021 - Identification and Authentication Failures', 'Remove hardcoded credentials and use AWS IAM roles or environment variables', 1, 'system', 'user'),
    ('Insecure Random Number Generation', r'(Math\.random|random\.random|rand)\s*\(', 'medium', 'Detects use of weak random number generators', '*', 'CWE-330', 'A02:2021 - Cryptographic Failures', 'Use cryptographically secure random number generators', 1, 'system', 'user'),
    ('Command Injection via exec', r'exec\s*\(\s*[^)]*\+', 'critical', 'Detects potential command injection through string concatenation', '*', 'CWE-78', 'A03:2021 - Injection', 'Avoid using exec with user input', 1, 'system', 'user'),
    ('Eval with User Input', r'(eval|exec)\s*\(\s*[^)]*(?:request|input|params)', 'critical', 'Detects eval/exec usage with user input', '*', 'CWE-95', 'A03:2021 - Injection', 'Never use eval with user input. Use safe alternatives', 1, 'system', 'user'),
    ('Hardcoded JWT Secret', r'secret\s*[:=]\s*["\'][^"\']{20,}["\']', 'high', 'Detects hardcoded JWT secrets or signing keys', '*', 'CWE-798', 'A02:2021 - Cryptographic Failures', 'Store secrets in environment variables or secret management systems', 1, 'system', 'user')
]

cursor.executemany('''
INSERT OR IGNORE INTO custom_rules (name, pattern, severity, description, language, cwe, owasp, remediation, enabled, created_by, generated_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', default_rules)

conn.commit()

# Verify tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%rule%'")
tables = cursor.fetchall()

cursor.close()
conn.close()

print("✅ Custom rules database schema created successfully")
print(f"📊 Created tables: {[t[0] for t in tables]}")
