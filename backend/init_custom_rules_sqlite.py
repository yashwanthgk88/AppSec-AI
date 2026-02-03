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

    # ============================================================
    # PYTHON - Django Framework
    # ============================================================
    ('Django - Raw SQL Query', r'\.raw\s*\(\s*["\']|\.extra\s*\(\s*(?:select|where|tables)\s*=', 'high',
     'Detects Django raw SQL queries that may be vulnerable to injection',
     'python', 'CWE-89', 'A03:2021 - Injection',
     'Use Django ORM queries or parameterized raw queries', 1, 'system', 'user'),

    ('Django - Unsafe Template Rendering', r'mark_safe\s*\(|safe\s*\||{% autoescape off %}', 'high',
     'Detects Django mark_safe or disabled autoescape which can lead to XSS',
     'python', 'CWE-79', 'A03:2021 - Injection',
     'Avoid mark_safe with user input. Keep autoescape enabled', 1, 'system', 'user'),

    ('Django - CSRF Exempt', r'@csrf_exempt|csrf_exempt\s*=\s*True', 'high',
     'Detects disabled CSRF protection in Django views',
     'python', 'CWE-352', 'A01:2021 - Broken Access Control',
     'Only disable CSRF for API endpoints with token auth. Use csrf_protect', 1, 'system', 'user'),

    ('Django - Debug Toolbar in Production', r'debug_toolbar|DEBUG_TOOLBAR', 'medium',
     'Detects Django Debug Toolbar which should not be in production',
     'python', 'CWE-489', 'A05:2021 - Security Misconfiguration',
     'Remove debug_toolbar from production settings', 1, 'system', 'user'),

    ('Django - Hardcoded SECRET_KEY', r'SECRET_KEY\s*=\s*["\'][^"\']{20,}["\']', 'critical',
     'Detects hardcoded Django SECRET_KEY',
     'python', 'CWE-798', 'A02:2021 - Cryptographic Failures',
     'Use environment variables for SECRET_KEY', 1, 'system', 'user'),

    ('Django - Unsafe Redirect', r'HttpResponseRedirect\s*\(\s*request\.|redirect\s*\(\s*request\.', 'high',
     'Detects Django redirects using user input - potential open redirect',
     'python', 'CWE-601', 'A01:2021 - Broken Access Control',
     'Validate redirect URLs against allowlist', 1, 'system', 'user'),

    # ============================================================
    # PYTHON - Flask Framework
    # ============================================================
    ('Flask - SQL Injection via text()', r'db\.session\.execute\s*\(\s*text\s*\([^)]*\+', 'critical',
     'Detects Flask SQLAlchemy text() with string concatenation',
     'python', 'CWE-89', 'A03:2021 - Injection',
     'Use SQLAlchemy parameterized queries with bindparams', 1, 'system', 'user'),

    ('Flask - Jinja2 Template Injection', r'render_template_string\s*\(|Template\s*\([^)]*\+', 'critical',
     'Detects Flask template injection via render_template_string with user input',
     'python', 'CWE-94', 'A03:2021 - Injection',
     'Use render_template with separate template files', 1, 'system', 'user'),

    ('Flask - Session Cookie Not Secure', r'SESSION_COOKIE_SECURE\s*=\s*False', 'high',
     'Detects Flask session cookies without Secure flag',
     'python', 'CWE-614', 'A07:2021 - Identification and Authentication Failures',
     'Set SESSION_COOKIE_SECURE=True in production', 1, 'system', 'user'),

    ('Flask - Unsafe File Upload', r'request\.files\[.*?\]\.save\s*\(', 'high',
     'Detects Flask file uploads that may not validate file type/content',
     'python', 'CWE-434', 'A04:2021 - Insecure Design',
     'Validate file extensions, content type, and use secure filenames', 1, 'system', 'user'),

    # ============================================================
    # PYTHON - FastAPI Framework
    # ============================================================
    ('FastAPI - Raw SQL in Endpoint', r'@(?:app|router)\.(?:get|post|put|delete).*?(?:execute|raw)', 'high',
     'Detects FastAPI endpoints with raw SQL execution',
     'python', 'CWE-89', 'A03:2021 - Injection',
     'Use SQLAlchemy ORM or parameterized queries', 1, 'system', 'user'),

    ('FastAPI - Missing Authentication Dependency', r'@(?:app|router)\.(?:get|post|put|delete)\s*\([^)]*\)\s*\n(?:async\s+)?def\s+\w+\s*\([^)]*(?!Depends\s*\(\s*(?:get_current_user|auth|verify))', 'medium',
     'Detects FastAPI endpoints potentially missing auth dependencies',
     'python', 'CWE-862', 'A01:2021 - Broken Access Control',
     'Add authentication dependencies using Depends()', 1, 'system', 'user'),

    # ============================================================
    # JAVASCRIPT - Node.js / Express
    # ============================================================
    ('Express - Helmet Not Used', r'const\s+app\s*=\s*express\s*\(\)(?![\s\S]*?helmet)', 'medium',
     'Detects Express apps potentially missing Helmet security middleware',
     'javascript', 'CWE-693', 'A05:2021 - Security Misconfiguration',
     'Use helmet middleware for security headers', 1, 'system', 'user'),

    ('Express - Body Parser Limit Not Set', r'bodyParser\.json\s*\(\s*\)|express\.json\s*\(\s*\)', 'low',
     'Detects Express body parser without size limits',
     'javascript', 'CWE-770', 'A05:2021 - Security Misconfiguration',
     'Set limit option to prevent DoS: express.json({ limit: "10kb" })', 1, 'system', 'user'),

    ('Express - Disable X-Powered-By', r'app\.disable\s*\(\s*["\']x-powered-by["\']\s*\)', 'low',
     'X-Powered-By header should be disabled (positive pattern for verification)',
     'javascript', 'CWE-200', 'A05:2021 - Security Misconfiguration',
     'Use app.disable("x-powered-by") or helmet middleware', 1, 'system', 'user'),

    ('Express - Unsafe Redirect', r'res\.redirect\s*\(\s*(?:req\.|request\.)', 'high',
     'Detects Express redirects using user input',
     'javascript', 'CWE-601', 'A01:2021 - Broken Access Control',
     'Validate redirect URLs against allowlist', 1, 'system', 'user'),

    ('Express - SQL Injection', r'(?:query|execute)\s*\(\s*[`"\'].*?\$\{|(?:query|execute)\s*\(\s*.*?\+\s*(?:req\.|request\.)', 'critical',
     'Detects SQL injection in Express with template literals or concatenation',
     'javascript', 'CWE-89', 'A03:2021 - Injection',
     'Use parameterized queries with prepared statements', 1, 'system', 'user'),

    ('Node.js - Child Process Injection', r'(?:exec|spawn|execFile|execSync|spawnSync)\s*\([^)]*(?:req\.|request\.|user)', 'critical',
     'Detects command injection via child_process with user input',
     'javascript', 'CWE-78', 'A03:2021 - Injection',
     'Validate and sanitize input. Use execFile with argument array', 1, 'system', 'user'),

    ('Node.js - Path Traversal', r'(?:readFile|writeFile|readdir|unlink|stat)\s*\([^)]*(?:req\.|request\.|params\.|query\.)', 'high',
     'Detects file system operations with user-controlled paths',
     'javascript', 'CWE-22', 'A01:2021 - Broken Access Control',
     'Use path.resolve and validate against base directory', 1, 'system', 'user'),

    ('Node.js - Prototype Pollution', r'(?:Object\.assign|_\.merge|_\.extend|_\.defaultsDeep)\s*\([^,]*,\s*(?:req\.|request\.|body)', 'high',
     'Detects potential prototype pollution via object merge with user input',
     'javascript', 'CWE-1321', 'A03:2021 - Injection',
     'Validate object keys. Use Object.create(null) or Map', 1, 'system', 'user'),

    # ============================================================
    # JAVASCRIPT - React Framework
    # ============================================================
    ('React - dangerouslySetInnerHTML', r'dangerouslySetInnerHTML\s*=\s*\{\s*\{', 'high',
     'Detects React dangerouslySetInnerHTML which can lead to XSS',
     'javascript', 'CWE-79', 'A03:2021 - Injection',
     'Avoid dangerouslySetInnerHTML. Use DOMPurify if absolutely needed', 1, 'system', 'user'),

    ('React - href javascript:', r'href\s*=\s*[{"\'].*?javascript:', 'high',
     'Detects React href with javascript: protocol',
     'javascript', 'CWE-79', 'A03:2021 - Injection',
     'Never use javascript: in href. Use onClick handlers', 1, 'system', 'user'),

    ('React - Unsafe Component Rendering', r'React\.createElement\s*\(\s*(?:props\.|this\.props\.)', 'high',
     'Detects dynamic component creation from props',
     'javascript', 'CWE-94', 'A03:2021 - Injection',
     'Use allowlist for dynamic component names', 1, 'system', 'user'),

    # ============================================================
    # JAVASCRIPT - Angular Framework
    # ============================================================
    ('Angular - bypassSecurityTrust', r'bypassSecurityTrust(?:Html|Style|Script|Url|ResourceUrl)', 'high',
     'Detects Angular security bypass methods',
     'javascript', 'CWE-79', 'A03:2021 - Injection',
     'Avoid bypass methods. Sanitize input properly instead', 1, 'system', 'user'),

    ('Angular - innerHTML Binding', r'\[innerHTML\]\s*=', 'medium',
     'Detects Angular innerHTML binding which may lead to XSS',
     'javascript', 'CWE-79', 'A03:2021 - Injection',
     'Use Angular sanitization or textContent for plain text', 1, 'system', 'user'),

    # ============================================================
    # JAVASCRIPT - Vue.js Framework
    # ============================================================
    ('Vue - v-html Directive', r'v-html\s*=', 'high',
     'Detects Vue v-html directive which can lead to XSS',
     'javascript', 'CWE-79', 'A03:2021 - Injection',
     'Avoid v-html with user input. Use v-text or sanitize content', 1, 'system', 'user'),

    ('Vue - Dynamic Component', r':is\s*=\s*["\']?\s*(?:user|input|data)', 'high',
     'Detects Vue dynamic components with user-controlled names',
     'javascript', 'CWE-94', 'A03:2021 - Injection',
     'Use allowlist for dynamic component names', 1, 'system', 'user'),

    # ============================================================
    # JAVA - General
    # ============================================================
    ('Java - SQL Injection Statement', r'Statement\s*\w*\s*=.*?(?:createStatement|prepareStatement\s*\([^?])', 'critical',
     'Detects Java SQL statements without parameterization',
     'java', 'CWE-89', 'A03:2021 - Injection',
     'Use PreparedStatement with parameter placeholders', 1, 'system', 'user'),

    ('Java - Runtime.exec Command Injection', r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', 'critical',
     'Detects Java command execution with string concatenation',
     'java', 'CWE-78', 'A03:2021 - Injection',
     'Use ProcessBuilder with argument array. Validate input', 1, 'system', 'user'),

    ('Java - Unsafe Reflection', r'Class\.forName\s*\([^)]*(?:request|input|param)', 'high',
     'Detects Java reflection with user-controlled class names',
     'java', 'CWE-470', 'A03:2021 - Injection',
     'Use allowlist for permitted class names', 1, 'system', 'user'),

    ('Java - XXE Vulnerable Parser', r'(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(\)', 'high',
     'Detects Java XML parsers that may be vulnerable to XXE',
     'java', 'CWE-611', 'A05:2021 - Security Misconfiguration',
     'Disable external entities: setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)', 1, 'system', 'user'),

    ('Java - Insecure Cookie', r'new\s+Cookie\s*\([^)]*\)(?![\s\S]*?setSecure\s*\(\s*true)', 'medium',
     'Detects Java cookies potentially missing Secure flag',
     'java', 'CWE-614', 'A07:2021 - Identification and Authentication Failures',
     'Call setSecure(true) and setHttpOnly(true) on cookies', 1, 'system', 'user'),

    # ============================================================
    # JAVA - Spring Framework
    # ============================================================
    ('Spring - SpEL Injection', r'(?:SpelExpressionParser|@Value)\s*\([^)]*(?:request|input|param)', 'critical',
     'Detects Spring Expression Language injection',
     'java', 'CWE-917', 'A03:2021 - Injection',
     'Never use user input in SpEL expressions', 1, 'system', 'user'),

    ('Spring - CSRF Disabled', r'csrf\(\)\.disable\(\)|csrf\.disable', 'high',
     'Detects disabled CSRF protection in Spring Security',
     'java', 'CWE-352', 'A01:2021 - Broken Access Control',
     'Only disable CSRF for stateless APIs with token auth', 1, 'system', 'user'),

    ('Spring - Open Redirect', r'redirect:\s*["\']?\s*\+|RedirectView\s*\([^)]*(?:request|param)', 'high',
     'Detects Spring MVC open redirect vulnerabilities',
     'java', 'CWE-601', 'A01:2021 - Broken Access Control',
     'Validate redirect URLs against allowlist', 1, 'system', 'user'),

    ('Spring - Actuator Exposed', r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', 'high',
     'Detects Spring Actuator exposing all endpoints',
     'java', 'CWE-200', 'A05:2021 - Security Misconfiguration',
     'Only expose necessary actuator endpoints', 1, 'system', 'user'),

    ('Spring - Mass Assignment', r'@ModelAttribute|@RequestBody\s+(?!@Valid)', 'medium',
     'Detects Spring endpoints potentially vulnerable to mass assignment',
     'java', 'CWE-915', 'A04:2021 - Insecure Design',
     'Use DTOs and @Valid annotation. Avoid binding directly to entities', 1, 'system', 'user'),

    # ============================================================
    # PHP - General
    # ============================================================
    ('PHP - SQL Injection mysql_query', r'mysql_query\s*\(\s*["\'].*?\.\s*\$', 'critical',
     'Detects PHP mysql_query with string concatenation',
     'php', 'CWE-89', 'A03:2021 - Injection',
     'Use PDO with prepared statements', 1, 'system', 'user'),

    ('PHP - Command Injection', r'(?:shell_exec|system|passthru|exec|popen|proc_open)\s*\([^)]*\$', 'critical',
     'Detects PHP command execution with variables',
     'php', 'CWE-78', 'A03:2021 - Injection',
     'Use escapeshellarg() and escapeshellcmd(). Prefer avoiding shell commands', 1, 'system', 'user'),

    ('PHP - File Inclusion', r'(?:include|require|include_once|require_once)\s*\(\s*\$', 'critical',
     'Detects PHP file inclusion with variables - LFI/RFI risk',
     'php', 'CWE-98', 'A03:2021 - Injection',
     'Use allowlist for included files. Never include user input', 1, 'system', 'user'),

    ('PHP - eval Usage', r'eval\s*\(\s*\$', 'critical',
     'Detects PHP eval with variables',
     'php', 'CWE-95', 'A03:2021 - Injection',
     'Never use eval with user input', 1, 'system', 'user'),

    ('PHP - Unserialize', r'unserialize\s*\(\s*\$(?!_(?:SESSION|COOKIE))', 'critical',
     'Detects PHP unserialize with potentially untrusted data',
     'php', 'CWE-502', 'A08:2021 - Software and Data Integrity Failures',
     'Use JSON instead of serialize. If needed, use allowed_classes option', 1, 'system', 'user'),

    ('PHP - XSS via echo', r'echo\s+\$(?:_GET|_POST|_REQUEST)', 'high',
     'Detects PHP echoing user input without sanitization',
     'php', 'CWE-79', 'A03:2021 - Injection',
     'Use htmlspecialchars() with ENT_QUOTES', 1, 'system', 'user'),

    ('PHP - Unsafe File Upload', r'move_uploaded_file\s*\([^)]*\$_FILES', 'high',
     'Detects PHP file upload handling',
     'php', 'CWE-434', 'A04:2021 - Insecure Design',
     'Validate file type, extension, content. Use random filenames', 1, 'system', 'user'),

    # ============================================================
    # PHP - Laravel Framework
    # ============================================================
    ('Laravel - Raw Query', r'DB::(?:raw|select|insert|update|delete)\s*\([^)]*\.\s*\$', 'critical',
     'Detects Laravel raw queries with concatenation',
     'php', 'CWE-89', 'A03:2021 - Injection',
     'Use query builder with parameter bindings', 1, 'system', 'user'),

    ('Laravel - Mass Assignment', r'(?:create|update|fill)\s*\(\s*\$request->all\(\)', 'high',
     'Detects Laravel mass assignment vulnerability',
     'php', 'CWE-915', 'A04:2021 - Insecure Design',
     'Use $fillable or $guarded in models. Use $request->only()', 1, 'system', 'user'),

    ('Laravel - Blade Unescaped', r'\{!!\s*\$', 'high',
     'Detects Laravel Blade unescaped output',
     'php', 'CWE-79', 'A03:2021 - Injection',
     'Use {{ }} for escaped output. Sanitize if {!! !!} is required', 1, 'system', 'user'),

    ('Laravel - Debug Mode', r"'debug'\s*=>\s*(?:true|env\s*\(\s*'APP_DEBUG'\s*,\s*true\s*\))", 'high',
     'Detects Laravel debug mode configuration',
     'php', 'CWE-489', 'A05:2021 - Security Misconfiguration',
     'Set APP_DEBUG=false in production .env', 1, 'system', 'user'),

    # ============================================================
    # GO - General
    # ============================================================
    ('Go - SQL Injection', r'(?:Query|Exec|QueryRow)\s*\([^)]*\+|fmt\.Sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)', 'critical',
     'Detects Go SQL queries with string concatenation or Sprintf',
     'go', 'CWE-89', 'A03:2021 - Injection',
     'Use parameterized queries with ? placeholders', 1, 'system', 'user'),

    ('Go - Command Injection', r'exec\.Command\s*\([^)]*\+', 'critical',
     'Detects Go command execution with concatenation',
     'go', 'CWE-78', 'A03:2021 - Injection',
     'Pass arguments separately to exec.Command', 1, 'system', 'user'),

    ('Go - Path Traversal', r'(?:os\.Open|ioutil\.ReadFile|os\.ReadFile)\s*\([^)]*(?:r\.|c\.|request|param)', 'high',
     'Detects Go file operations with user input',
     'go', 'CWE-22', 'A01:2021 - Broken Access Control',
     'Use filepath.Clean and validate against base path', 1, 'system', 'user'),

    ('Go - Insecure TLS Config', r'InsecureSkipVerify\s*:\s*true', 'high',
     'Detects Go TLS configuration skipping certificate verification',
     'go', 'CWE-295', 'A02:2021 - Cryptographic Failures',
     'Never skip TLS verification in production', 1, 'system', 'user'),

    ('Go - Weak Random', r'math/rand|rand\.(?:Int|Intn|Float)', 'medium',
     'Detects Go math/rand usage for potentially security-sensitive operations',
     'go', 'CWE-330', 'A02:2021 - Cryptographic Failures',
     'Use crypto/rand for security-sensitive random numbers', 1, 'system', 'user'),

    # ============================================================
    # GO - Gin Framework
    # ============================================================
    ('Gin - HTML Rendering', r'c\.HTML\s*\([^)]*,\s*gin\.H\s*\{[^}]*(?:c\.|request)', 'medium',
     'Detects Gin HTML rendering with potentially user-controlled data',
     'go', 'CWE-79', 'A03:2021 - Injection',
     'Ensure template auto-escaping is enabled', 1, 'system', 'user'),

    ('Gin - File Serving', r'c\.File\s*\([^)]*(?:c\.Param|c\.Query)', 'high',
     'Detects Gin file serving with user input',
     'go', 'CWE-22', 'A01:2021 - Broken Access Control',
     'Validate file paths. Use allowlist for permitted files', 1, 'system', 'user'),

    # ============================================================
    # RUBY - General
    # ============================================================
    ('Ruby - Command Injection backticks', r'`[^`]*#\{', 'critical',
     'Detects Ruby backtick command execution with interpolation',
     'ruby', 'CWE-78', 'A03:2021 - Injection',
     'Use Open3.capture3 with separate arguments', 1, 'system', 'user'),

    ('Ruby - system/exec Command Injection', r'(?:system|exec|%x)\s*[(\[].*?#\{', 'critical',
     'Detects Ruby system/exec with string interpolation',
     'ruby', 'CWE-78', 'A03:2021 - Injection',
     'Pass command and arguments separately', 1, 'system', 'user'),

    ('Ruby - eval Usage', r'eval\s*[(\[].*?(?:params|request|input)', 'critical',
     'Detects Ruby eval with user input',
     'ruby', 'CWE-95', 'A03:2021 - Injection',
     'Never use eval with user input', 1, 'system', 'user'),

    ('Ruby - send with User Input', r'\.send\s*\(\s*params|\.public_send\s*\(\s*params', 'high',
     'Detects Ruby dynamic method calls with user input',
     'ruby', 'CWE-470', 'A03:2021 - Injection',
     'Use allowlist for permitted method names', 1, 'system', 'user'),

    # ============================================================
    # RUBY - Rails Framework
    # ============================================================
    ('Rails - SQL Injection', r'(?:where|find_by_sql|select|group|order|having)\s*\([^)]*#\{', 'critical',
     'Detects Rails SQL with string interpolation',
     'ruby', 'CWE-89', 'A03:2021 - Injection',
     'Use parameterized queries: where("name = ?", params[:name])', 1, 'system', 'user'),

    ('Rails - XSS raw/html_safe', r'(?:raw|html_safe)\s*[(\[]?\s*(?:params|@|user)', 'high',
     'Detects Rails raw/html_safe with potentially unsafe data',
     'ruby', 'CWE-79', 'A03:2021 - Injection',
     'Avoid raw/html_safe with user input. Use sanitize helper', 1, 'system', 'user'),

    ('Rails - Mass Assignment', r'(?:create|update|new)\s*\(\s*params(?:\[:[a-z_]+\])?\s*\)', 'high',
     'Detects Rails mass assignment without strong parameters',
     'ruby', 'CWE-915', 'A04:2021 - Insecure Design',
     'Use strong parameters: params.require(:model).permit(:field1, :field2)', 1, 'system', 'user'),

    ('Rails - Open Redirect', r'redirect_to\s+(?:params|request)', 'high',
     'Detects Rails redirect with user input',
     'ruby', 'CWE-601', 'A01:2021 - Broken Access Control',
     'Validate redirect URLs. Use only_path: true for internal redirects', 1, 'system', 'user'),

    ('Rails - Unsafe YAML Load', r'YAML\.load\s*\(', 'high',
     'Detects Rails unsafe YAML deserialization',
     'ruby', 'CWE-502', 'A08:2021 - Software and Data Integrity Failures',
     'Use YAML.safe_load instead', 1, 'system', 'user'),

    ('Rails - render inline', r'render\s+inline:\s*["\'].*?#\{', 'critical',
     'Detects Rails inline rendering with interpolation',
     'ruby', 'CWE-94', 'A03:2021 - Injection',
     'Use render template with separate files', 1, 'system', 'user'),

    # ============================================================
    # C# / .NET - General
    # ============================================================
    ('C# - SQL Injection SqlCommand', r'new\s+SqlCommand\s*\([^)]*\+|SqlCommand\s*\([^)]*String\.Format', 'critical',
     'Detects C# SQL commands with concatenation',
     'csharp', 'CWE-89', 'A03:2021 - Injection',
     'Use SqlParameter for parameterized queries', 1, 'system', 'user'),

    ('C# - Command Injection Process.Start', r'Process\.Start\s*\([^)]*(?:\+|String\.Format|request|input)', 'critical',
     'Detects C# process execution with user input',
     'csharp', 'CWE-78', 'A03:2021 - Injection',
     'Validate input. Use ProcessStartInfo with Arguments array', 1, 'system', 'user'),

    ('C# - XSS Response.Write', r'Response\.Write\s*\([^)]*(?:Request|input|user)', 'high',
     'Detects C# Response.Write with user input',
     'csharp', 'CWE-79', 'A03:2021 - Injection',
     'Use HttpUtility.HtmlEncode or Razor automatic encoding', 1, 'system', 'user'),

    ('C# - XXE Vulnerable', r'new\s+XmlDocument\s*\(\)|XmlReader\.Create\s*\(', 'high',
     'Detects C# XML parsing potentially vulnerable to XXE',
     'csharp', 'CWE-611', 'A05:2021 - Security Misconfiguration',
     'Set XmlResolver = null and DtdProcessing = Prohibit', 1, 'system', 'user'),

    ('C# - Insecure Deserialization BinaryFormatter', r'BinaryFormatter\s*\(\)|BinaryFormatter\.Deserialize', 'critical',
     'Detects C# BinaryFormatter deserialization',
     'csharp', 'CWE-502', 'A08:2021 - Software and Data Integrity Failures',
     'Avoid BinaryFormatter. Use System.Text.Json or protobuf', 1, 'system', 'user'),

    ('C# - Hardcoded Connection String', r'(?:connectionString|ConnectionString)\s*=\s*["\'][^"\']*(?:Password|pwd)\s*=', 'critical',
     'Detects hardcoded database connection strings with passwords',
     'csharp', 'CWE-798', 'A05:2021 - Security Misconfiguration',
     'Use configuration with encrypted secrets or Azure Key Vault', 1, 'system', 'user'),

    # ============================================================
    # C# / ASP.NET
    # ============================================================
    ('ASP.NET - ValidateRequest Disabled', r'ValidateRequest\s*=\s*["\']?false', 'high',
     'Detects ASP.NET request validation disabled',
     'csharp', 'CWE-79', 'A03:2021 - Injection',
     'Keep ValidateRequest enabled. Use AntiXSS library for output encoding', 1, 'system', 'user'),

    ('ASP.NET - CSRF AntiForgery Missing', r'\[HttpPost\](?![\s\S]*?\[ValidateAntiForgeryToken\])', 'high',
     'Detects ASP.NET POST actions potentially missing CSRF protection',
     'csharp', 'CWE-352', 'A01:2021 - Broken Access Control',
     'Add [ValidateAntiForgeryToken] attribute to POST actions', 1, 'system', 'user'),

    ('ASP.NET Core - HTTPS Not Enforced', r'app\.UseHttpsRedirection\s*\(\s*\)', 'medium',
     'Check for HTTPS redirection (verification pattern)',
     'csharp', 'CWE-319', 'A02:2021 - Cryptographic Failures',
     'Ensure UseHttpsRedirection is called in production', 1, 'system', 'user'),

    # ============================================================
    # MOBILE - iOS (Swift/Objective-C)
    # ============================================================
    ('iOS - NSLog Sensitive Data', r'NSLog\s*\(@[^)]*(?:password|token|secret|key|credential)', 'high',
     'Detects iOS logging of potentially sensitive data',
     'swift', 'CWE-532', 'A09:2021 - Security Logging and Monitoring Failures',
     'Remove sensitive data from logs in production', 1, 'system', 'user'),

    ('iOS - Insecure Data Storage', r'NSUserDefaults.*?(?:password|token|secret|key)', 'high',
     'Detects iOS storing sensitive data in NSUserDefaults',
     'swift', 'CWE-922', 'A02:2021 - Cryptographic Failures',
     'Use Keychain for sensitive data storage', 1, 'system', 'user'),

    ('iOS - ATS Disabled', r'NSAppTransportSecurity.*?NSAllowsArbitraryLoads.*?true', 'high',
     'Detects iOS App Transport Security disabled',
     'swift', 'CWE-319', 'A02:2021 - Cryptographic Failures',
     'Enable ATS. Only add specific exceptions if absolutely necessary', 1, 'system', 'user'),

    ('iOS - Hardcoded API Key', r'(?:let|var)\s+(?:apiKey|api_key|token)\s*=\s*["\'][^"\']{15,}["\']', 'high',
     'Detects hardcoded API keys in iOS code',
     'swift', 'CWE-798', 'A02:2021 - Cryptographic Failures',
     'Use secure storage or fetch keys from server at runtime', 1, 'system', 'user'),

    # ============================================================
    # MOBILE - Android (Kotlin/Java)
    # ============================================================
    ('Android - Log Sensitive Data', r'Log\.(?:d|i|v|w|e)\s*\([^)]*(?:password|token|secret|key|credential)', 'high',
     'Detects Android logging of potentially sensitive data',
     'kotlin', 'CWE-532', 'A09:2021 - Security Logging and Monitoring Failures',
     'Remove sensitive data from logs. Use ProGuard to strip logs', 1, 'system', 'user'),

    ('Android - SharedPreferences Sensitive Data', r'SharedPreferences.*?(?:password|token|secret|key)', 'high',
     'Detects Android storing sensitive data in SharedPreferences',
     'kotlin', 'CWE-922', 'A02:2021 - Cryptographic Failures',
     'Use EncryptedSharedPreferences or Android Keystore', 1, 'system', 'user'),

    ('Android - WebView JavaScript Enabled', r'setJavaScriptEnabled\s*\(\s*true\s*\)', 'medium',
     'Detects Android WebView with JavaScript enabled',
     'kotlin', 'CWE-79', 'A03:2021 - Injection',
     'Only enable JS if needed. Validate loaded URLs', 1, 'system', 'user'),

    ('Android - WebView addJavascriptInterface', r'addJavascriptInterface\s*\(', 'high',
     'Detects Android WebView JavaScript interface which can be exploited',
     'kotlin', 'CWE-749', 'A03:2021 - Injection',
     'Use @JavascriptInterface annotation. Restrict to API 17+', 1, 'system', 'user'),

    ('Android - Cleartext Traffic', r'usesCleartextTraffic\s*=\s*["\']?true|cleartextTrafficPermitted', 'high',
     'Detects Android allowing cleartext HTTP traffic',
     'kotlin', 'CWE-319', 'A02:2021 - Cryptographic Failures',
     'Set usesCleartextTraffic=false. Use HTTPS only', 1, 'system', 'user'),

    ('Android - Exported Component', r'android:exported\s*=\s*["\']?true', 'medium',
     'Detects Android exported components that may be vulnerable',
     'kotlin', 'CWE-926', 'A01:2021 - Broken Access Control',
     'Only export components that need to be accessible. Add permissions', 1, 'system', 'user'),

    # ============================================================
    # INFRASTRUCTURE - Docker
    # ============================================================
    ('Docker - Running as Root', r'USER\s+root|(?<!#\s*)(?:ENTRYPOINT|CMD).*?(?!--user)', 'medium',
     'Detects Docker containers potentially running as root',
     '*', 'CWE-250', 'A05:2021 - Security Misconfiguration',
     'Use USER directive to run as non-root user', 1, 'system', 'user'),

    ('Docker - Latest Tag', r'FROM\s+[^:]+:latest|FROM\s+[^\s:]+\s*$', 'medium',
     'Detects Docker images using latest tag or no tag',
     '*', 'CWE-1104', 'A06:2021 - Vulnerable and Outdated Components',
     'Use specific version tags for reproducible builds', 1, 'system', 'user'),

    ('Docker - Secrets in ENV', r'ENV\s+(?:PASSWORD|SECRET|API_KEY|TOKEN)\s*=', 'high',
     'Detects secrets in Docker ENV instructions',
     '*', 'CWE-798', 'A02:2021 - Cryptographic Failures',
     'Use Docker secrets or runtime environment variables', 1, 'system', 'user'),

    # ============================================================
    # INFRASTRUCTURE - Kubernetes
    # ============================================================
    ('K8s - privileged Container', r'privileged\s*:\s*true', 'critical',
     'Detects Kubernetes privileged containers',
     '*', 'CWE-250', 'A05:2021 - Security Misconfiguration',
     'Avoid privileged containers. Use specific capabilities if needed', 1, 'system', 'user'),

    ('K8s - hostNetwork', r'hostNetwork\s*:\s*true', 'high',
     'Detects Kubernetes pods using host network',
     '*', 'CWE-668', 'A05:2021 - Security Misconfiguration',
     'Avoid hostNetwork unless absolutely necessary', 1, 'system', 'user'),

    ('K8s - No Resource Limits', r'containers\s*:(?![\s\S]*?(?:limits|requests))', 'medium',
     'Detects Kubernetes containers without resource limits',
     '*', 'CWE-770', 'A05:2021 - Security Misconfiguration',
     'Set resource limits and requests for all containers', 1, 'system', 'user'),

    # ============================================================
    # INFRASTRUCTURE - Terraform
    # ============================================================
    ('Terraform - S3 Public Access', r'acl\s*=\s*["\']public-read|block_public_acls\s*=\s*false', 'critical',
     'Detects Terraform S3 buckets with public access',
     '*', 'CWE-732', 'A01:2021 - Broken Access Control',
     'Block all public access. Use bucket policies for specific access', 1, 'system', 'user'),

    ('Terraform - Unencrypted Storage', r'encrypted\s*=\s*false|storage_encrypted\s*=\s*false', 'high',
     'Detects Terraform resources with encryption disabled',
     '*', 'CWE-311', 'A02:2021 - Cryptographic Failures',
     'Enable encryption at rest for all storage resources', 1, 'system', 'user'),

    ('Terraform - Security Group 0.0.0.0/0', r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]', 'high',
     'Detects Terraform security groups allowing all traffic',
     '*', 'CWE-284', 'A01:2021 - Broken Access Control',
     'Restrict CIDR blocks to specific IP ranges', 1, 'system', 'user'),
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
