"""Initialize custom rules database tables in SQLite"""
import sqlite3
import os

# Use consistent database path (same as utils/db_path.py)
def get_db_path():
    persistent_path = "/app/data/appsec.db"
    if os.path.exists("/app/data"):
        return persistent_path
    return "appsec.db"

# Connect to SQLite database
db_path = get_db_path()
print(f"Using database at: {db_path}")
conn = sqlite3.connect(db_path)
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

# Insert default custom rules - OWASP Top 10 2021 Coverage
default_rules = [
    # ============================================================
    # A01:2021 - Broken Access Control
    # ============================================================
    ('Direct Object Reference - User ID in URL', r'(?:user|account|profile|order)[/_]?(?:id)?\s*[=:]\s*(?:request|params|query)', 'high',
     'Detects potential Insecure Direct Object Reference (IDOR) where user-controlled input directly references objects',
     '*', 'CWE-639', 'A01:2021 - Broken Access Control',
     'Implement proper access control checks. Verify user authorization before accessing resources', 1, 'system', 'user'),

    ('Missing Authorization Check', r'@(?:app\.route|router\.|Get|Post|Put|Delete)\s*\([^)]*\)\s*(?:(?!@(?:login_required|auth|requires_auth|authorize|permission))[\s\S])*?def\s+\w+', 'high',
     'Detects API endpoints that may be missing authorization decorators',
     'python', 'CWE-862', 'A01:2021 - Broken Access Control',
     'Add authorization checks using decorators like @login_required or implement role-based access control', 1, 'system', 'user'),

    ('Path Traversal Pattern', r'\.\.\/|\.\.\\\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c', 'critical',
     'Detects path traversal sequences that could allow unauthorized file access',
     '*', 'CWE-22', 'A01:2021 - Broken Access Control',
     'Validate and sanitize file paths. Use allowlists for permitted directories', 1, 'system', 'user'),

    ('Privilege Escalation - Admin Check Bypass', r'(?:is_admin|isAdmin|admin|role)\s*[=!]=\s*(?:true|1|["\']admin["\'])', 'high',
     'Detects simple admin checks that may be vulnerable to bypass',
     '*', 'CWE-269', 'A01:2021 - Broken Access Control',
     'Use robust role-based access control. Never trust client-side role assertions', 1, 'system', 'user'),

    # ============================================================
    # A02:2021 - Cryptographic Failures
    # ============================================================
    ('Hardcoded AWS Credentials', r'AKIA[0-9A-Z]{16}', 'critical',
     'Detects hardcoded AWS access keys',
     '*', 'CWE-798', 'A02:2021 - Cryptographic Failures',
     'Remove hardcoded credentials and use AWS IAM roles or environment variables', 1, 'system', 'user'),

    ('Hardcoded JWT Secret', r'secret\s*[:=]\s*["\'][^"\']{20,}["\']', 'high',
     'Detects hardcoded JWT secrets or signing keys',
     '*', 'CWE-798', 'A02:2021 - Cryptographic Failures',
     'Store secrets in environment variables or secret management systems', 1, 'system', 'user'),

    ('Weak Hashing Algorithm - MD5', r'(?:md5|MD5)\s*\(|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*["\']MD5', 'high',
     'Detects use of weak MD5 hashing algorithm',
     '*', 'CWE-328', 'A02:2021 - Cryptographic Failures',
     'Use strong hashing algorithms like SHA-256, SHA-3, or bcrypt for passwords', 1, 'system', 'user'),

    ('Weak Hashing Algorithm - SHA1', r'(?:sha1|SHA1)\s*\(|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*["\']SHA-?1', 'medium',
     'Detects use of deprecated SHA-1 hashing algorithm',
     '*', 'CWE-328', 'A02:2021 - Cryptographic Failures',
     'Use SHA-256 or stronger hashing algorithms', 1, 'system', 'user'),

    ('Insecure Random Number Generation', r'(?:Math\.random|random\.random|rand)\s*\(', 'medium',
     'Detects use of weak random number generators for security-sensitive operations',
     '*', 'CWE-330', 'A02:2021 - Cryptographic Failures',
     'Use cryptographically secure random number generators (secrets module, crypto.randomBytes)', 1, 'system', 'user'),

    ('Hardcoded Private Key', r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'critical',
     'Detects hardcoded private keys in source code',
     '*', 'CWE-321', 'A02:2021 - Cryptographic Failures',
     'Never commit private keys. Use secure key management systems', 1, 'system', 'user'),

    ('Hardcoded API Key Pattern', r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', 'high',
     'Detects hardcoded API keys in source code',
     '*', 'CWE-798', 'A02:2021 - Cryptographic Failures',
     'Store API keys in environment variables or secret management systems', 1, 'system', 'user'),

    ('Weak SSL/TLS Configuration', r'ssl\.PROTOCOL_SSLv[23]|SSLv[23]|TLSv1[^.]|MinVersion.*TLS1[^2-3]', 'high',
     'Detects use of deprecated SSL/TLS versions',
     '*', 'CWE-326', 'A02:2021 - Cryptographic Failures',
     'Use TLS 1.2 or higher. Disable SSLv2, SSLv3, and TLS 1.0/1.1', 1, 'system', 'user'),

    # ============================================================
    # A03:2021 - Injection
    # ============================================================
    ('SQL Injection - String Concatenation', r'(?:execute|query|cursor\.execute|executeQuery)\s*\(\s*["\']?\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*?\+', 'critical',
     'Detects SQL queries built with string concatenation - high risk of SQL injection',
     '*', 'CWE-89', 'A03:2021 - Injection',
     'Use parameterized queries or prepared statements. Never concatenate user input into SQL', 1, 'system', 'user'),

    ('SQL Injection - Format String', r'(?:execute|query)\s*\(\s*["\'].*?%s.*?%.*?\)', 'critical',
     'Detects SQL queries using format strings which may be vulnerable to injection',
     'python', 'CWE-89', 'A03:2021 - Injection',
     'Use parameterized queries with proper placeholders', 1, 'system', 'user'),

    ('SQL Injection - f-string', r'f["\'](?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}', 'critical',
     'Detects SQL queries using Python f-strings with variable interpolation',
     'python', 'CWE-89', 'A03:2021 - Injection',
     'Never use f-strings for SQL queries. Use parameterized queries', 1, 'system', 'user'),

    ('Command Injection via exec', r'exec\s*\(\s*[^)]*\+', 'critical',
     'Detects potential command injection through string concatenation',
     '*', 'CWE-78', 'A03:2021 - Injection',
     'Avoid using exec with user input. Use subprocess with shell=False', 1, 'system', 'user'),

    ('Command Injection - os.system', r'os\.system\s*\(\s*(?:.*?\+|f["\']|.*?%|.*?\.format)', 'critical',
     'Detects os.system calls with dynamic input',
     'python', 'CWE-78', 'A03:2021 - Injection',
     'Use subprocess module with shell=False and list arguments', 1, 'system', 'user'),

    ('Command Injection - subprocess shell=True', r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'high',
     'Detects subprocess calls with shell=True which enables shell injection',
     'python', 'CWE-78', 'A03:2021 - Injection',
     'Use shell=False and pass arguments as a list', 1, 'system', 'user'),

    ('Eval with User Input', r'(?:eval|exec)\s*\(\s*[^)]*(?:request|input|params|argv|stdin)', 'critical',
     'Detects eval/exec usage with user input',
     '*', 'CWE-95', 'A03:2021 - Injection',
     'Never use eval with user input. Use safe alternatives like ast.literal_eval for Python', 1, 'system', 'user'),

    ('XSS - innerHTML Assignment', r'\.innerHTML\s*=\s*(?![\s]*["\'][^"\']*["\'])', 'high',
     'Detects innerHTML assignments that may lead to XSS',
     'javascript', 'CWE-79', 'A03:2021 - Injection',
     'Use textContent for text or sanitize HTML with DOMPurify', 1, 'system', 'user'),

    ('XSS - document.write', r'document\.write\s*\(', 'high',
     'Detects document.write which can lead to XSS vulnerabilities',
     'javascript', 'CWE-79', 'A03:2021 - Injection',
     'Use DOM manipulation methods instead of document.write', 1, 'system', 'user'),

    ('LDAP Injection', r'(?:ldap_search|ldap_bind|search_s)\s*\([^)]*\+', 'high',
     'Detects LDAP queries with string concatenation',
     '*', 'CWE-90', 'A03:2021 - Injection',
     'Use parameterized LDAP queries and escape special characters', 1, 'system', 'user'),

    ('XPath Injection', r'(?:xpath|selectNodes|evaluate)\s*\([^)]*\+', 'high',
     'Detects XPath queries with string concatenation',
     '*', 'CWE-643', 'A03:2021 - Injection',
     'Use parameterized XPath queries or precompiled expressions', 1, 'system', 'user'),

    ('NoSQL Injection - MongoDB', r'\$(?:where|regex|ne|gt|lt|gte|lte)\s*:', 'high',
     'Detects MongoDB operators that may indicate NoSQL injection vulnerability',
     '*', 'CWE-943', 'A03:2021 - Injection',
     'Validate and sanitize input. Use MongoDB sanitization libraries', 1, 'system', 'user'),

    # ============================================================
    # A04:2021 - Insecure Design
    # ============================================================
    ('Missing Rate Limiting', r'@(?:app\.route|router\.|api_view).*?(?:login|auth|password|reset|register|signup)', 'medium',
     'Detects authentication endpoints that may need rate limiting',
     '*', 'CWE-307', 'A04:2021 - Insecure Design',
     'Implement rate limiting on authentication endpoints to prevent brute force attacks', 1, 'system', 'user'),

    ('Sensitive Data in URL', r'(?:password|token|secret|api_key|apikey)=[^&\s]+', 'high',
     'Detects sensitive data being passed in URL parameters',
     '*', 'CWE-598', 'A04:2021 - Insecure Design',
     'Never pass sensitive data in URLs. Use POST body or headers', 1, 'system', 'user'),

    # ============================================================
    # A05:2021 - Security Misconfiguration
    # ============================================================
    ('Debug Mode Enabled', r'(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|["\']true["\'])', 'high',
     'Detects debug mode enabled which may expose sensitive information',
     '*', 'CWE-489', 'A05:2021 - Security Misconfiguration',
     'Disable debug mode in production environments', 1, 'system', 'user'),

    ('Permissive CORS - Allow All Origins', r'(?:Access-Control-Allow-Origin|cors.*origin)\s*[:=]\s*["\']?\*', 'medium',
     'Detects overly permissive CORS configuration allowing all origins',
     '*', 'CWE-942', 'A05:2021 - Security Misconfiguration',
     'Restrict CORS to specific trusted origins', 1, 'system', 'user'),

    ('Verbose Error Messages', r'(?:app\.config|settings)\s*\[\s*["\'](?:PROPAGATE_EXCEPTIONS|TRAP_HTTP_EXCEPTIONS)["\']', 'medium',
     'Detects configuration that may expose detailed error messages',
     'python', 'CWE-209', 'A05:2021 - Security Misconfiguration',
     'Use generic error messages in production. Log detailed errors server-side', 1, 'system', 'user'),

    ('Hardcoded Database Credentials', r'(?:mysql|postgres|mongodb|redis)://[^:]+:[^@]+@', 'critical',
     'Detects hardcoded database connection strings with credentials',
     '*', 'CWE-798', 'A05:2021 - Security Misconfiguration',
     'Use environment variables for database credentials', 1, 'system', 'user'),

    ('XML External Entity (XXE) - Unsafe Parser', r'(?:etree\.parse|minidom\.parse|xml\.sax\.parse|XMLReader)\s*\(', 'high',
     'Detects XML parsing that may be vulnerable to XXE attacks',
     'python', 'CWE-611', 'A05:2021 - Security Misconfiguration',
     'Disable external entity processing in XML parsers', 1, 'system', 'user'),

    # ============================================================
    # A06:2021 - Vulnerable and Outdated Components
    # ============================================================
    ('Known Vulnerable Library - Log4j', r'log4j[_-](?:core)?[_-]?(?:1\.|2\.[0-9]\.|2\.1[0-6]\.)', 'critical',
     'Detects potentially vulnerable Log4j versions (CVE-2021-44228)',
     'java', 'CWE-1104', 'A06:2021 - Vulnerable and Outdated Components',
     'Upgrade Log4j to version 2.17.1 or later', 1, 'system', 'user'),

    # ============================================================
    # A07:2021 - Identification and Authentication Failures
    # ============================================================
    ('Weak Password Validation', r'(?:password|passwd).*?(?:len|length)\s*[<>=]=?\s*[1-7]\b', 'high',
     'Detects weak password length requirements (less than 8 characters)',
     '*', 'CWE-521', 'A07:2021 - Identification and Authentication Failures',
     'Require minimum 12 characters with complexity requirements', 1, 'system', 'user'),

    ('Hardcoded Password', r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', 'critical',
     'Detects hardcoded passwords in source code',
     '*', 'CWE-798', 'A07:2021 - Identification and Authentication Failures',
     'Never hardcode passwords. Use environment variables or secret management', 1, 'system', 'user'),

    ('Session Fixation Risk', r'(?:session|SESSION)\s*\[\s*["\'](?:id|ID|session_id)["\']', 'medium',
     'Detects direct session ID manipulation which may indicate session fixation',
     '*', 'CWE-384', 'A07:2021 - Identification and Authentication Failures',
     'Regenerate session IDs after authentication', 1, 'system', 'user'),

    ('Missing Secure Flag on Cookie', r'(?:Set-Cookie|cookie)\s*[=:][^;]*(?!;.*?[Ss]ecure)', 'medium',
     'Detects cookies that may be missing the Secure flag',
     '*', 'CWE-614', 'A07:2021 - Identification and Authentication Failures',
     'Set Secure flag on all sensitive cookies', 1, 'system', 'user'),

    # ============================================================
    # A08:2021 - Software and Data Integrity Failures
    # ============================================================
    ('Insecure Deserialization - Pickle', r'pickle\.load|cPickle\.load|pickle\.loads', 'critical',
     'Detects use of pickle deserialization which can lead to code execution',
     'python', 'CWE-502', 'A08:2021 - Software and Data Integrity Failures',
     'Avoid pickle for untrusted data. Use JSON or other safe formats', 1, 'system', 'user'),

    ('Insecure Deserialization - YAML', r'yaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:yaml\.)?SafeLoader)', 'high',
     'Detects unsafe YAML loading without SafeLoader',
     'python', 'CWE-502', 'A08:2021 - Software and Data Integrity Failures',
     'Use yaml.safe_load() or yaml.load(data, Loader=SafeLoader)', 1, 'system', 'user'),

    ('Insecure Deserialization - Java', r'(?:ObjectInputStream|readObject|XMLDecoder)', 'high',
     'Detects Java deserialization which may be vulnerable',
     'java', 'CWE-502', 'A08:2021 - Software and Data Integrity Failures',
     'Implement deserialization filters or use safe alternatives', 1, 'system', 'user'),

    ('Unsigned JWT', r'algorithm\s*[:=]\s*["\']none["\']|alg["\']?\s*:\s*["\']none', 'critical',
     'Detects JWT with "none" algorithm which bypasses signature verification',
     '*', 'CWE-347', 'A08:2021 - Software and Data Integrity Failures',
     'Always verify JWT signatures. Never accept "none" algorithm', 1, 'system', 'user'),

    # ============================================================
    # A09:2021 - Security Logging and Monitoring Failures
    # ============================================================
    ('Sensitive Data in Logs', r'(?:log|logger|logging|console\.log).*?(?:password|secret|token|api_key|credit_card|ssn)', 'high',
     'Detects potential logging of sensitive information',
     '*', 'CWE-532', 'A09:2021 - Security Logging and Monitoring Failures',
     'Never log sensitive data. Mask or redact sensitive fields', 1, 'system', 'user'),

    ('Missing Error Logging', r'except\s*:?\s*(?:pass|\.\.\.)', 'low',
     'Detects exception handlers that silently ignore errors',
     'python', 'CWE-778', 'A09:2021 - Security Logging and Monitoring Failures',
     'Log exceptions for security monitoring and debugging', 1, 'system', 'user'),

    # ============================================================
    # A10:2021 - Server-Side Request Forgery (SSRF)
    # ============================================================
    ('SSRF - URL from User Input', r'(?:requests\.get|urllib\.request\.urlopen|http\.get|fetch)\s*\(\s*(?:request|params|query|user)', 'high',
     'Detects HTTP requests with URLs from user input - potential SSRF',
     '*', 'CWE-918', 'A10:2021 - Server-Side Request Forgery',
     'Validate and allowlist URLs. Block internal IP ranges', 1, 'system', 'user'),

    ('SSRF - URL Concatenation', r'(?:requests\.get|urllib\.request\.urlopen|http\.get|fetch)\s*\([^)]*\+', 'high',
     'Detects HTTP requests with concatenated URLs',
     '*', 'CWE-918', 'A10:2021 - Server-Side Request Forgery',
     'Use allowlists for external URLs. Validate URL schemes', 1, 'system', 'user'),
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
