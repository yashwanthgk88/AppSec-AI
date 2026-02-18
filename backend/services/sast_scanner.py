"""
SAST (Static Application Security Testing) Scanner
Professional-grade multi-language security analyzer with comprehensive vulnerability detection
"""
import re
import logging
from typing import List, Dict, Any, Set, Optional
import os

logger = logging.getLogger(__name__)

class SASTScanner:
    """
    Enhanced SAST scanner supporting multiple languages with comprehensive vulnerability detection
    Supports: Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, C#, C/C++, Kotlin, Swift
    """

    # Language-specific file extensions mapping
    LANGUAGE_EXTENSIONS = {
        'python': ['.py'],
        'javascript': ['.js', '.jsx', '.mjs'],
        'typescript': ['.ts', '.tsx'],
        'java': ['.java'],
        'php': ['.php'],
        'ruby': ['.rb'],
        'go': ['.go'],
        'csharp': ['.cs'],
        'c_cpp': ['.c', '.cpp', '.h', '.hpp', '.cc', '.cxx'],
        'kotlin': ['.kt', '.kts'],
        'swift': ['.swift'],
        'rust': ['.rs'],
        'scala': ['.scala'],
        'perl': ['.pl', '.pm'],
        'shell': ['.sh', '.bash'],
    }

    # Comprehensive vulnerability patterns organized by category
    VULNERABILITY_PATTERNS = {
        # ==================== INJECTION VULNERABILITIES ====================
        "SQL Injection": {
            "patterns": [
                # Standard SQL concatenation patterns
                r'(execute|query|exec|executemany|rawQuery)\s*\(\s*["\'].*?(\+|%|\$\{|f["\'])',
                r'(cursor|db|conn)\.(execute|query)\s*\([^)]*\+',
                r'(SELECT|INSERT|UPDATE|DELETE).*?(\+|%s|\$\{)',
                r'createQuery\s*\([^)]*\+',  # JPA
                r'\$wpdb->query\s*\([^)]*\$',  # WordPress
                # F-string SQL injection patterns (Python)
                r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER).*?\{',
                r'f["\'].*?WHERE.*?\{',
                r'f["\'].*?FROM\s+\w+.*?\{',
                r'f["\'].*?VALUES\s*\(.*?\{',
                r'f["\'].*?SET\s+\w+\s*=.*?\{',
                r'f["\'].*?ORDER\s+BY.*?\{',
                r'f["\'].*?GROUP\s+BY.*?\{',
                r'f["\'].*?HAVING.*?\{',
                r'f["\'].*?UNION.*?\{',
                r'f["\'].*?JOIN.*?ON.*?\{',
                # Template literal SQL injection (JavaScript)
                r'`.*?(SELECT|INSERT|UPDATE|DELETE|DROP).*?\$\{',
                # String format SQL injection
                r'["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']\.format\s*\(',
                r'["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\'].*?%\s*\(',
                # Execute with user input
                r'execute\s*\(\s*["\']?\s*\+',
                r'query\s*\(\s*["\']?\s*\+',
                # Raw queries with variables
                r'raw\s*\([^)]*\+',
                r'rawQuery\s*\([^)]*\+',
            ],
            "cwe": "CWE-89",
            "owasp": "A05:2025 - Injection",
            "severity": "critical",
            "description": "SQL query construction using string concatenation or formatting. Vulnerable to SQL injection attacks.",
            "impact": """**Business Impact:**
- Complete database compromise allowing unauthorized access to all stored data
- Data breach exposing sensitive customer information (PII, financial data, credentials)
- Data manipulation or deletion causing business disruption and data integrity loss
- Potential regulatory violations (GDPR, HIPAA, PCI-DSS) leading to fines up to €20M or 4% of annual revenue
- Reputational damage and loss of customer trust

**Technical Impact:**
- Authentication bypass allowing attackers to login as any user including administrators
- Extraction of entire database contents including passwords, credit cards, and personal data
- Database modification enabling privilege escalation and persistent backdoor access
- Potential server compromise through database features (xp_cmdshell, INTO OUTFILE)
- Denial of service through resource-intensive queries or data deletion""",
            "remediation": """**Immediate Actions:**
1. Use parameterized queries (prepared statements) for ALL database operations
2. Implement input validation using allowlists for expected data formats
3. Apply principle of least privilege - database accounts should have minimal permissions
4. Enable SQL query logging and monitoring for anomaly detection

**Long-term Remediation:**
1. Adopt an ORM framework (SQLAlchemy, Hibernate, Entity Framework) that handles parameterization
2. Implement Web Application Firewall (WAF) rules for SQL injection patterns
3. Conduct regular code reviews focusing on database interaction code
4. Use static analysis tools to detect SQL injection vulnerabilities in CI/CD pipeline
5. Implement database activity monitoring (DAM) for real-time threat detection""",
            "remediation_code": """# Python - VULNERABLE
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)

# Python - SECURE (parameterized query)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Python - SECURE (using SQLAlchemy ORM)
user = session.query(User).filter(User.id == user_id).first()

// Java - VULNERABLE
String query = "SELECT * FROM users WHERE id = " + userId;
statement.executeQuery(query);

// Java - SECURE (PreparedStatement)
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
stmt.executeQuery();

// Node.js - SECURE (parameterized)
connection.query('SELECT * FROM users WHERE id = ?', [userId], callback);"""
        },

        "NoSQL Injection": {
            "patterns": [
                r'(find|findOne|update|remove)\s*\(\s*\{.*?(\$|request\.|params\.)',
                r'db\.collection.*?\$where',
                r'new\s+ObjectId\s*\([^)]*req\.',
            ],
            "cwe": "CWE-943",
            "owasp": "A05:2025 - Injection",
            "severity": "high",
            "description": "NoSQL query constructed with unsanitized user input.",
            "impact": """**Business Impact:**
- Unauthorized access to NoSQL database bypassing authentication and authorization
- Data exfiltration of sensitive documents and collections
- Data manipulation affecting business logic and application integrity
- Potential for denial of service through malicious query operators

**Technical Impact:**
- Authentication bypass using operator injection ($ne, $gt, $regex)
- Extraction of sensitive data through query manipulation
- Server-side JavaScript execution via $where operator leading to RCE
- Database enumeration revealing schema and data structure""",
            "remediation": """**Immediate Actions:**
1. Validate and sanitize all user inputs before database queries
2. Explicitly cast expected data types (strings, numbers, ObjectIds)
3. Disable or restrict $where operator usage in production
4. Implement query depth and complexity limits

**Long-term Remediation:**
1. Use ODM libraries (Mongoose) with schema validation
2. Implement allowlist validation for query operators
3. Apply principle of least privilege for database connections
4. Enable audit logging for all database operations""",
            "remediation_code": """// VULNERABLE - Direct user input in query
db.collection.find({ name: req.query.name })
db.users.find({ $where: "this.name == '" + username + "'" })

// SECURE - Type validation and sanitization
const sanitizedName = String(req.query.name).substring(0, 100);
db.collection.find({ name: sanitizedName })

// SECURE - Using Mongoose with schema validation
const User = mongoose.model('User', userSchema);
User.findOne({ name: validator.escape(req.query.name) });

// SECURE - Explicit type casting for ObjectId
const mongoose = require('mongoose');
if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ error: 'Invalid ID' });
}
db.collection.findOne({ _id: new mongoose.Types.ObjectId(req.params.id) });"""
        },

        "XSS (Cross-Site Scripting)": {
            "patterns": [
                # DOM-based XSS patterns
                r'(innerHTML|outerHTML)\s*=\s*[^;]+',  # Any innerHTML/outerHTML assignment
                r'(innerHTML|outerHTML)\s*=.*?(\+|`\$\{)',
                r'document\.write\s*\([^)]+',  # document.write with any content
                r'document\.writeln\s*\([^)]+',
                # React dangerous patterns
                r'dangerouslySetInnerHTML\s*=',
                r'dangerouslySetInnerHTML\s*=\s*\{\{.*?\}\}',
                # jQuery XSS patterns
                r'\.html\s*\([^)]*(\+|\$\{|`)',  # jQuery .html() with concatenation/template
                r'\.html\s*\(\s*\w+\s*\)',  # jQuery .html(variable)
                r'\.append\s*\(\s*["\']?<',  # jQuery .append with HTML
                r'\.prepend\s*\(\s*["\']?<',  # jQuery .prepend with HTML
                r'\.after\s*\(\s*["\']?<',  # jQuery .after with HTML
                r'\.before\s*\(\s*["\']?<',  # jQuery .before with HTML
                r'\.replaceWith\s*\(\s*["\']?<',  # jQuery .replaceWith with HTML
                r'\$\s*\([^)]*<[^>]+>',  # jQuery selector with HTML
                # Template injection
                r'<script>.*?\$\{',
                r'<script>.*?\{\{',
                # eval/Function with user input
                r'(eval|Function)\s*\(.*?(request\.|params\.|req\.|args\.|query\.)',
                r'(eval|Function)\s*\(\s*\w+\s*\)',  # eval(variable)
                # URL-based XSS
                r'location\s*=\s*[^;]+',
                r'location\.href\s*=\s*[^;]+',
                r'location\.replace\s*\([^)]+',
                r'window\.open\s*\([^)]*\+',
                # Attribute injection
                r'setAttribute\s*\([^,]*,\s*[^)]+',
                r'\.src\s*=\s*[^;]+',
                r'\.href\s*=\s*[^;]+',
                # Server-side template injection
                r'render_template_string\s*\(',
                r'Markup\s*\([^)]*\+',
                r'\{\%.*?autoescape\s+false',
                r'\{\{.*?\|safe\}\}',
                # PHP XSS
                r'echo\s+\$',
                r'print\s+\$',
                r'<\?=\s*\$',
            ],
            "cwe": "CWE-79",
            "owasp": "A05:2025 - Injection",
            "severity": "high",
            "description": "Direct DOM manipulation or HTML rendering with unsanitized user input. Vulnerable to XSS attacks.",
            "impact": """**Business Impact:**
- Session hijacking allowing attackers to impersonate legitimate users
- Credential theft through fake login forms or keyloggers
- Defacement damaging brand reputation and user trust
- Malware distribution to users visiting the compromised application
- Compliance violations (PCI-DSS requires protection against XSS)

**Technical Impact:**
- Theft of session cookies bypassing authentication
- Keylogging and form data interception capturing user credentials
- DOM manipulation to display fraudulent content or redirect users
- Execution of arbitrary JavaScript in user's browser context
- CSRF attacks using stolen session tokens""",
            "remediation": """**Immediate Actions:**
1. Implement Content Security Policy (CSP) headers to restrict script sources
2. Use context-aware output encoding (HTML, JavaScript, URL, CSS contexts)
3. Set HttpOnly and Secure flags on session cookies
4. Sanitize all user input using established libraries (DOMPurify)

**Long-term Remediation:**
1. Adopt frontend frameworks with automatic escaping (React, Vue, Angular)
2. Implement input validation using allowlists for expected formats
3. Use template engines with auto-escaping enabled by default
4. Regular security testing including XSS-specific fuzzing
5. Train developers on secure coding practices for XSS prevention""",
            "remediation_code": """// VULNERABLE - Direct innerHTML assignment
element.innerHTML = userInput;
element.outerHTML = "<div>" + userInput + "</div>";
document.write(userInput);

// SECURE - Use textContent for plain text
element.textContent = userInput;

// SECURE - Sanitize with DOMPurify for HTML content
element.innerHTML = DOMPurify.sanitize(userInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
});

// React - VULNERABLE
<div dangerouslySetInnerHTML={{__html: userInput}} />

// React - SECURE (auto-escaped)
<div>{userInput}</div>

// CSP Header Example
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"""
        },

        "Command Injection": {
            "patterns": [
                r'(exec|system|popen|shell_exec|passthru|proc_open)\s*\(.*?(\+|f["\']|\$\{)',
                r'subprocess\.(call|run|Popen).*?shell\s*=\s*True',
                r'os\.(system|popen|exec).*?(\+|f["\'])',
                r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',
                r'cmd\s*/c.*?(\+|\$)',
            ],
            "cwe": "CWE-78",
            "owasp": "A05:2025 - Injection",
            "severity": "critical",
            "description": "Command execution with user-controlled input. Allows arbitrary command execution on the server.",
            "impact": """**Business Impact:**
- Complete server compromise with potential lateral movement to internal systems
- Data breach affecting all data accessible by the application server
- Ransomware deployment causing business disruption and financial loss
- Use of compromised server for cryptocurrency mining or botnet operations
- Regulatory penalties and legal liability from security breach

**Technical Impact:**
- Remote Code Execution (RCE) with privileges of the application process
- File system access enabling data theft, modification, or destruction
- Network pivoting to attack internal infrastructure
- Installation of persistent backdoors and rootkits
- Denial of service through resource exhaustion or system commands""",
            "remediation": """**Immediate Actions:**
1. NEVER use shell=True in subprocess calls with user input
2. Use argument lists instead of string concatenation for commands
3. Implement strict allowlist validation for command arguments
4. Apply principle of least privilege - run services with minimal permissions

**Long-term Remediation:**
1. Use language-native libraries instead of system commands (e.g., socket library instead of ping)
2. Implement sandbox environments (containers, seccomp) for command execution
3. Deploy application-level firewalls to detect command injection patterns
4. Enable comprehensive logging of all system command executions
5. Consider removing command execution capabilities entirely if not essential""",
            "remediation_code": """# Python - VULNERABLE
os.system("ping " + user_input)
subprocess.call("ping " + user_input, shell=True)
os.popen("ls " + directory)

# Python - SECURE (argument list, no shell)
import shlex
import subprocess

# Validate input first
allowed_hosts = ['google.com', 'github.com']
if user_input not in allowed_hosts:
    raise ValueError("Invalid host")

subprocess.run(["ping", "-c", "4", user_input], shell=False, timeout=30)

// Java - VULNERABLE
Runtime.getRuntime().exec("ping " + userInput);

// Java - SECURE
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", userInput);
pb.redirectErrorStream(true);
Process p = pb.start();

// Node.js - SECURE
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', userInput], (error, stdout, stderr) => {
    // Handle output
});"""
        },

        "LDAP Injection": {
            "patterns": [
                r'search\s*\(\s*["\'][^"\']*\+.*?["\']',
                r'LdapTemplate.*?search.*?\+',
            ],
            "cwe": "CWE-90",
            "owasp": "A05:2025 - Injection",
            "severity": "high",
            "description": "LDAP query constructed with unsanitized user input.",
            "impact": """**Business Impact:**
- Unauthorized access to directory services (Active Directory, OpenLDAP)
- Exposure of organizational structure, user accounts, and group memberships
- Authentication bypass allowing access as any user
- Data exfiltration of sensitive directory attributes (emails, phone numbers, roles)

**Technical Impact:**
- LDAP filter injection to bypass authentication checks
- Enumeration of all users and groups in the directory
- Modification of directory entries if write access is available
- Access to password hashes or other sensitive attributes""",
            "remediation": """**Immediate Actions:**
1. Escape all special LDAP characters in user input: * ( ) \\ NUL
2. Use LDAP libraries with built-in escaping functions
3. Implement input validation with allowlist of permitted characters
4. Use parameterized LDAP queries where supported

**Long-term Remediation:**
1. Implement LDAP query builders that handle escaping automatically
2. Use least privilege for LDAP bind accounts
3. Enable LDAP audit logging for query monitoring
4. Consider using higher-level identity APIs instead of raw LDAP
5. Implement rate limiting on authentication endpoints""",
            "remediation_code": """# VULNERABLE - Direct string concatenation
ldap_filter = "(uid=" + username + ")"
ldap_filter = f"(&(uid={username})(password={password}))"

# SECURE - Proper escaping with ldap3
from ldap3.utils.conv import escape_filter_chars

username = escape_filter_chars(user_input)
ldap_filter = f"(uid={username})"

# SECURE - Using python-ldap
import ldap
safe_username = ldap.filter.escape_filter_chars(user_input)
ldap_filter = f"(uid={safe_username})"

// Java - SECURE
import javax.naming.directory.SearchControls;
String safeName = LdapEncoder.filterEncode(username);
String filter = "(uid=" + safeName + ")";"""
        },

        "XML Injection": {
            "patterns": [
                r'(parseXML|XMLParser|xml\.etree).*?(\+|\$\{)',
                r'XXE|ENTITY',
            ],
            "cwe": "CWE-91",
            "owasp": "A05:2025 - Injection",
            "severity": "high",
            "description": "XML parsing with unsanitized input. May allow XXE attacks.",
            "impact": """**Business Impact:**
- Server-Side Request Forgery through external entity resolution
- Exposure of sensitive server files (/etc/passwd, configuration files)
- Denial of service through recursive entity expansion (Billion Laughs attack)
- Port scanning and internal network reconnaissance

**Technical Impact:**
- File disclosure via file:// protocol in external entities
- SSRF attacks using http:// entities to access internal services
- Memory exhaustion through entity expansion attacks
- Remote code execution in some XML processors""",
            "remediation": """**Immediate Actions:**
1. Disable external entity processing in XML parser configuration
2. Disable DTD processing entirely if not required
3. Use defusedxml library in Python (drop-in replacement)
4. Validate XML against a strict schema before processing

**Long-term Remediation:**
1. Prefer JSON over XML for data interchange where possible
2. Use XML parsers with secure defaults (defusedxml, woodstox)
3. Implement XML schema validation to reject malformed input
4. Run XML processing in sandboxed environments
5. Monitor for XXE attack patterns in WAF logs""",
            "remediation_code": """# VULNERABLE - Standard XML parsing allows XXE
import xml.etree.ElementTree as ET
tree = ET.parse(user_file)
root = ET.fromstring(user_xml)

# SECURE - Use defusedxml (drop-in replacement)
import defusedxml.ElementTree as ET
tree = ET.parse(user_file)  # XXE disabled by default

# SECURE - Disable entities in lxml
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(user_file, parser)

// Java - SECURE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);"""
        },

        # ==================== AUTHENTICATION & SESSION VULNERABILITIES ====================
        "Hardcoded Credentials": {
            "patterns": [
                r'(password|passwd|pwd|secret|api[_-]?key|token|auth)\s*=\s*["\'][^"\']{6,}["\']',
                r'(DB_PASSWORD|DATABASE_PASSWORD|SECRET_KEY)\s*=\s*["\'][^"\']{6,}["\']',
                r'(AWS_SECRET|PRIVATE_KEY|CLIENT_SECRET)\s*=\s*["\'][^"\']{8,}["\']',
            ],
            "cwe": "CWE-798",
            "owasp": "A07:2025 - Authentication Failures",
            "severity": "critical",
            "description": "Hardcoded credentials or secrets found in source code. Exposes sensitive authentication data.",
            "impact": """**Business Impact:**
- Immediate unauthorized access to protected systems and data
- Supply chain attacks if credentials are exposed in public repositories
- Inability to rotate compromised credentials without code deployment
- Compliance violations (PCI-DSS, SOC2, HIPAA require proper secret management)
- Financial loss from unauthorized resource usage (cloud services, APIs)

**Technical Impact:**
- Direct access to databases, APIs, and third-party services
- Potential for credential stuffing if passwords are reused
- Persistent access even after incident detection (credentials in version history)
- Lateral movement using exposed service accounts
- Cloud infrastructure compromise through exposed AWS/Azure/GCP keys""",
            "remediation": """**Immediate Actions:**
1. Remove hardcoded credentials and rotate ALL exposed secrets immediately
2. Scan git history for previously committed secrets using tools like git-secrets, truffleHog
3. Revoke and regenerate any API keys or tokens found in code
4. Enable secret scanning alerts in your repository (GitHub, GitLab)

**Long-term Remediation:**
1. Implement secrets management solution (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)
2. Use environment variables for configuration in development
3. Integrate pre-commit hooks to prevent secret commits (git-secrets, detect-secrets)
4. Implement secret rotation policies with automated rotation where possible
5. Use short-lived tokens and credentials where feasible""",
            "remediation_code": """# VULNERABLE - Hardcoded secrets
password = "MySecretPassword123"
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgres://admin:password123@localhost/db"

# SECURE - Environment variables
import os
password = os.environ.get('DB_PASSWORD')
api_key = os.environ.get('API_KEY')

# SECURE - AWS Secrets Manager
import boto3
client = boto3.client('secretsmanager')
response = client.get_secret_value(SecretId='prod/db/password')
password = response['SecretString']

# SECURE - HashiCorp Vault
import hvac
client = hvac.Client(url='https://vault.example.com')
secret = client.secrets.kv.read_secret_version(path='myapp/config')
password = secret['data']['data']['password']

# .env file (for local development only, never commit)
# DB_PASSWORD=secure_password_here"""
        },

        "Weak Password Storage": {
            "patterns": [
                r'(md5|sha1|base64)\s*\(\s*password',
                r'password\s*=\s*(md5|sha1)',
                r'hashlib\.(md5|sha1)\s*\(',
            ],
            "cwe": "CWE-916",
            "owasp": "A04:2025 - Cryptographic Failures",
            "severity": "critical",
            "description": "Password stored using weak hashing algorithm (MD5, SHA1). Vulnerable to rainbow table attacks.",
            "impact": """**Business Impact:**
- Mass credential compromise if database is breached (MD5/SHA1 can be cracked in seconds)
- Account takeover attacks affecting all users with weak password hashes
- Regulatory non-compliance (NIST, PCI-DSS mandate strong password hashing)
- Legal liability from failure to protect user credentials with industry standards
- Reputational damage from password breach disclosure

**Technical Impact:**
- Rainbow table attacks can reverse MD5/SHA1 hashes instantly
- GPU-accelerated cracking can test billions of hashes per second
- Unsalted hashes allow attackers to crack multiple passwords simultaneously
- Base64 is encoding, NOT hashing - provides zero protection
- Credential stuffing attacks using cracked passwords on other services""",
            "remediation": """**Immediate Actions:**
1. Identify all password storage locations using weak algorithms
2. Plan migration to bcrypt/argon2 (rehash on next user login)
3. Force password reset for users with legacy hashes if breach suspected
4. Audit for any plain-text password storage or logging

**Long-term Remediation:**
1. Use Argon2id (winner of Password Hashing Competition) as primary choice
2. Alternatively use bcrypt with cost factor >= 12 or scrypt
3. Implement password policies (minimum length, complexity, breach checking)
4. Add rate limiting and account lockout to prevent brute force
5. Consider passwordless authentication (WebAuthn, passkeys) for enhanced security""",
            "remediation_code": """# VULNERABLE - Weak hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # Crackable in seconds
password_hash = hashlib.sha1(password.encode()).hexdigest()  # Also weak
password_encoded = base64.b64encode(password.encode())  # NOT encryption!

# SECURE - bcrypt (recommended)
import bcrypt
# Hash with automatic salt generation
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# Verify password
if bcrypt.checkpw(password.encode(), stored_hash):
    print("Password matches")

# SECURE - Argon2id (strongest option)
from argon2 import PasswordHasher
ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # Memory usage in KB
    parallelism=4       # Number of parallel threads
)
password_hash = ph.hash(password)
# Verify password
try:
    ph.verify(stored_hash, password)
except argon2.exceptions.VerifyMismatchError:
    print("Invalid password")"""
        },

        "Insecure JWT": {
            "patterns": [
                r'jwt\.encode.*?algorithm\s*=\s*["\']none["\']',
                r'jwt\.decode.*?verify\s*=\s*False',
                r'jsonwebtoken\.sign\(\s*[^,]*,\s*["\']["\']',  # Empty secret
            ],
            "cwe": "CWE-347",
            "owasp": "A04:2025 - Cryptographic Failures",
            "severity": "critical",
            "description": "JWT token with 'none' algorithm or disabled verification. Allows token forgery.",
            "impact": """**Business Impact:**
- Complete authentication bypass allowing attackers to impersonate any user
- Unauthorized access to protected resources and administrative functions
- Data breach through forged admin tokens
- Compliance violations (OAuth/OIDC security requirements)
- Loss of audit trail integrity through forged identity claims

**Technical Impact:**
- Token forgery using 'none' algorithm (no signature verification)
- Algorithm confusion attacks (RS256 to HS256 downgrade)
- Privilege escalation by modifying token claims
- Session hijacking through token manipulation
- Bypass of role-based access controls via claim modification""",
            "remediation": """**Immediate Actions:**
1. Explicitly specify allowed algorithms in decode/verify calls
2. Use strong secrets (256+ bits) for symmetric algorithms (HS256)
3. Implement token expiration and refresh token rotation
4. Reject tokens with 'none' algorithm at the library level

**Long-term Remediation:**
1. Use asymmetric algorithms (RS256, ES256) for distributed systems
2. Implement JWT validation middleware with strict checks
3. Add token binding (fingerprint) to prevent token theft
4. Use short-lived access tokens with refresh token rotation
5. Implement token revocation for logout and security incidents""",
            "remediation_code": """# VULNERABLE - No algorithm or verification
token = jwt.encode(payload, '', algorithm='none')
data = jwt.decode(token, verify=False)
data = jwt.decode(token, options={"verify_signature": False})

# SECURE - Explicit algorithm and verification
import jwt
from datetime import datetime, timedelta

SECRET_KEY = os.environ.get('JWT_SECRET')  # 256+ bit secret

# Create token with expiration
payload = {
    'user_id': user.id,
    'exp': datetime.utcnow() + timedelta(hours=1),
    'iat': datetime.utcnow()
}
token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Verify with explicit algorithm whitelist
try:
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
except jwt.ExpiredSignatureError:
    raise AuthError('Token expired')
except jwt.InvalidTokenError:
    raise AuthError('Invalid token')

// Node.js - SECURE
const jwt = require('jsonwebtoken');
const token = jwt.sign(payload, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '1h'
});
const decoded = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256']
});"""
        },

        # ==================== DESERIALIZATION & DATA INTEGRITY ====================
        "Insecure Deserialization": {
            "patterns": [
                r'pickle\.(loads|load)\s*\(',
                r'yaml\.load\s*\([^)]*(?!Loader)',
                r'eval\s*\(',
                r'exec\s*\(',
                r'(ObjectInputStream|readObject)\s*\(',
                r'unserialize\s*\(',  # PHP
            ],
            "cwe": "CWE-502",
            "owasp": "A03:2025 - Software Supply Chain Failures",
            "severity": "critical",
            "description": "Insecure deserialization of untrusted data. Can lead to remote code execution.",
            "impact": """**Business Impact:**
- Remote Code Execution (RCE) leading to complete system compromise
- Data breach through unauthorized server access
- Ransomware deployment and business disruption
- Supply chain attacks if serialized data is exchanged between systems
- Significant incident response and recovery costs

**Technical Impact:**
- Arbitrary code execution in the context of the application
- Object injection attacks manipulating application logic
- Denial of service through resource exhaustion (billion laughs attack in XML)
- Memory corruption and application crashes
- Bypass of authentication and authorization through object manipulation""",
            "remediation": """**Immediate Actions:**
1. Replace pickle/marshal with JSON for data serialization
2. Use yaml.safe_load() instead of yaml.load()
3. Remove all eval() and exec() calls with user-controlled input
4. Implement input validation before any deserialization

**Long-term Remediation:**
1. Use data formats that don't support code execution (JSON, Protocol Buffers)
2. Implement digital signatures to verify serialized data integrity
3. Run deserialization in sandboxed environments with limited privileges
4. Use allowlists for expected classes during deserialization (Java)
5. Consider using serialization libraries with built-in security (e.g., marshmallow for Python)""",
            "remediation_code": """# VULNERABLE - pickle can execute arbitrary code
import pickle
data = pickle.loads(user_input)  # RCE vulnerability!

# VULNERABLE - eval executes any Python code
result = eval(user_input)  # Never do this!
exec(user_code)  # Extremely dangerous!

# VULNERABLE - yaml.load with untrusted input
import yaml
data = yaml.load(user_input)  # Can execute code via !!python/object

# SECURE - Use JSON for data serialization
import json
data = json.loads(user_input)

# SECURE - yaml.safe_load blocks code execution
import yaml
data = yaml.safe_load(user_input)

# SECURE - Use marshmallow for structured deserialization
from marshmallow import Schema, fields

class UserSchema(Schema):
    name = fields.Str(required=True, validate=lambda x: len(x) < 100)
    email = fields.Email(required=True)

schema = UserSchema()
user = schema.load(json.loads(user_input))

// Java - VULNERABLE
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // Gadget chain attacks possible

// Java - SECURE (use JSON)
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);"""
        },

        # ==================== FILE & PATH VULNERABILITIES ====================
        "Path Traversal": {
            "patterns": [
                # Basic path traversal patterns
                r'(open|read|readFile|file_get_contents)\s*\([^)]*(\+|f["\']|\$\{)',
                r'(File|FileInputStream|FileReader)\s*\([^)]*\+',
                r'\.\./',
                r'os\.path\.join\([^)]*(?!os\.path\.basename)',
                # Python file operations with user input
                r'open\s*\(\s*f["\']',  # open with f-string
                r'open\s*\([^)]*\+',  # open with concatenation
                r'open\s*\([^)]*\.format',  # open with format
                r'pathlib\.Path\s*\([^)]*\+',
                r'shutil\.(copy|move|rmtree)\s*\([^)]*\+',
                r'os\.(remove|unlink|rmdir|mkdir|makedirs)\s*\([^)]*\+',
                # Detecting path concatenation patterns (before open)
                r'path\s*=\s*["\'][^"\']*["\'].*?\+',  # path = "..." + something
                r'(file_?path|filepath|fname|filename)\s*=\s*["\'][^"\']*["\'].*?\+',
                r'=\s*["\'][^"\']+["\']\s*\+\s*(filename|path|file|name|fname)',  # "..." + filename
                # JavaScript/Node.js file operations
                r'fs\.(readFile|writeFile|readFileSync|writeFileSync|readdir|unlink)\s*\([^)]*\+',
                r'fs\.(readFile|writeFile|readFileSync|writeFileSync)\s*\(\s*\w+',
                r'path\.join\s*\([^)]*req\.',
                r'path\.resolve\s*\([^)]*req\.',
                # Java file operations
                r'new\s+File\s*\([^)]*\+',
                r'new\s+FileInputStream\s*\([^)]*\+',
                r'new\s+FileOutputStream\s*\([^)]*\+',
                r'new\s+FileReader\s*\([^)]*\+',
                r'new\s+FileWriter\s*\([^)]*\+',
                r'Paths\.get\s*\([^)]*\+',
                r'Files\.(read|write|delete|move|copy)\s*\([^)]*\+',
                # PHP file operations
                r'(include|require|include_once|require_once)\s*\([^)]*\$',
                r'(fopen|fread|fwrite|file)\s*\([^)]*\$',
                r'file_put_contents\s*\([^)]*\$',
                r'readfile\s*\([^)]*\$',
                # Go file operations
                r'os\.Open\s*\([^)]*\+',
                r'ioutil\.ReadFile\s*\([^)]*\+',
                r'filepath\.Join\s*\([^)]*',
                # Zip/Archive extraction (Zip Slip)
                r'extractall\s*\(',
                r'ZipFile\s*\([^)]*\+',
                r'unzip\s*\([^)]*\+',
            ],
            "cwe": "CWE-22",
            "owasp": "A01:2025 - Broken Access Control",
            "severity": "high",
            "description": "File path constructed with unsanitized user input. Allows reading arbitrary files via path traversal.",
            "impact": """**Business Impact:**
- Exposure of sensitive configuration files (database credentials, API keys)
- Access to source code revealing business logic and additional vulnerabilities
- Reading of user data files violating privacy regulations (GDPR, HIPAA)
- Exposure of system files enabling further attacks
- Intellectual property theft through source code access

**Technical Impact:**
- Reading /etc/passwd, /etc/shadow for system user enumeration
- Accessing application configuration files with database credentials
- Extraction of private keys and certificates
- Reading log files containing sensitive session data
- Zip Slip attacks allowing arbitrary file overwrites during extraction""",
            "remediation": """**Immediate Actions:**
1. Use os.path.basename() to strip directory components from user input
2. Validate resolved paths stay within intended directory (jail)
3. Implement allowlist of permitted file names/patterns
4. Never expose absolute file paths to users

**Long-term Remediation:**
1. Use secure file handling libraries with built-in path validation
2. Implement file access abstraction layer that enforces access controls
3. Store files with random UUIDs instead of user-provided names
4. Use chroot or container isolation for file operations
5. Implement comprehensive logging of file access attempts""",
            "remediation_code": """# VULNERABLE - Direct path concatenation
with open("/var/files/" + user_filename, 'r') as f:
    content = f.read()

with open(f"/uploads/{request.args['file']}", 'r') as f:
    content = f.read()

# SECURE - Validate path stays within intended directory
import os

def safe_file_read(base_dir, user_filename):
    # Strip directory components
    safe_name = os.path.basename(user_filename)
    # Build full path
    full_path = os.path.join(base_dir, safe_name)
    # Resolve to absolute and verify it's within base_dir
    abs_path = os.path.realpath(full_path)
    abs_base = os.path.realpath(base_dir)

    if not abs_path.startswith(abs_base + os.sep):
        raise ValueError("Path traversal attempt detected")

    with open(abs_path, 'r') as f:
        return f.read()

# Node.js - SECURE
const path = require('path');
const baseDir = '/var/files';
const userFile = path.basename(req.query.file);  // Strip ../
const fullPath = path.join(baseDir, userFile);
const realPath = fs.realpathSync(fullPath);

if (!realPath.startsWith(baseDir)) {
    throw new Error('Invalid file path');
}"""
        },

        "Unrestricted File Upload": {
            "patterns": [
                r'(save|saveAs|upload|write).*?filename\s*=',
                r'move_uploaded_file.*?\$_FILES',
                r'file\.write\s*\([^)]*request\.',
            ],
            "cwe": "CWE-434",
            "owasp": "A01:2025 - Broken Access Control",
            "severity": "critical",
            "description": "File upload without proper validation. May allow uploading malicious files.",
            "impact": """**Business Impact:**
- Remote Code Execution through uploaded web shells
- Server compromise leading to data breach
- Website defacement damaging brand reputation
- Use of server for malware distribution
- Regulatory penalties from security incident

**Technical Impact:**
- Web shell upload enabling persistent backdoor access
- Execution of malicious scripts (PHP, JSP, ASPX)
- Storage exhaustion through large file uploads
- Cross-site scripting through uploaded HTML/SVG files
- Overwriting existing files including application code""",
            "remediation": """**Immediate Actions:**
1. Validate file extension against strict allowlist
2. Check MIME type and magic bytes (content sniffing)
3. Limit file size to reasonable maximum
4. Store files outside web-accessible directories

**Long-term Remediation:**
1. Use content delivery network (CDN) for serving uploaded files
2. Implement virus/malware scanning for all uploads
3. Store files with randomized names (UUIDs)
4. Serve files with Content-Disposition: attachment header
5. Use separate domain for user-uploaded content""",
            "remediation_code": """# VULNERABLE - No validation
file.save(f"uploads/{file.filename}")

# SECURE - Comprehensive validation
import os
import uuid
import magic
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
ALLOWED_MIME_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'application/pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def validate_upload(file):
    # Check extension
    if '.' not in file.filename:
        raise ValueError("No file extension")
    ext = file.filename.rsplit('.', 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension {ext} not allowed")

    # Check file size
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset
    if size > MAX_FILE_SIZE:
        raise ValueError("File too large")

    # Check MIME type using magic bytes
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    if mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"MIME type {mime} not allowed")

    return True

if validate_upload(file):
    # Use secure filename and random prefix
    safe_name = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4()}_{safe_name}"
    # Store OUTSIDE web root
    file.save(os.path.join('/var/uploads/', unique_name))"""
        },

        # ==================== CRYPTOGRAPHY VULNERABILITIES ====================
        "Weak Cryptography": {
            "patterns": [
                r'(md5|sha1|DES|RC4|RC2)\s*\(',
                r'(MD5|SHA1)DigestUtils',
                r'Cipher\.getInstance\s*\(["\']DES',
                r'crypto\.createCipheriv\s*\(["\']des',
            ],
            "cwe": "CWE-327",
            "owasp": "A04:2025 - Cryptographic Failures",
            "severity": "high",
            "description": "Use of weak or broken cryptographic algorithms. MD5, SHA1, and DES are cryptographically broken.",
            "impact": """**Business Impact:**
- Encrypted data can be decrypted by attackers with moderate resources
- Password hashes can be cracked using rainbow tables or GPU attacks
- Compliance violations (PCI-DSS, HIPAA require strong cryptography)
- False sense of security leading to inadequate data protection

**Technical Impact:**
- MD5/SHA1 collision attacks allow forging digital signatures
- DES/3DES can be brute-forced with modern hardware
- RC4 has known biases that leak plaintext information
- Weak algorithms provide no protection against state-level attackers""",
            "remediation": """**Immediate Actions:**
1. Inventory all cryptographic usage in the codebase
2. Replace MD5/SHA1 hashing with SHA-256 or SHA-3
3. Replace DES/3DES/RC4 encryption with AES-256-GCM
4. Replace weak password hashing with bcrypt or Argon2id

**Long-term Remediation:**
1. Use cryptography libraries with secure defaults (cryptography, libsodium)
2. Implement crypto-agility to allow algorithm upgrades
3. Conduct regular cryptographic audits
4. Follow NIST guidelines for algorithm selection
5. Plan for post-quantum cryptography migration""",
            "remediation_code": """# VULNERABLE - Weak hashing
import hashlib
hash = hashlib.md5(data).hexdigest()   # Broken
hash = hashlib.sha1(data).hexdigest()  # Deprecated

# SECURE - Strong hashing
import hashlib
hash = hashlib.sha256(data).hexdigest()
hash = hashlib.sha3_256(data).hexdigest()

# VULNERABLE - Weak encryption
from Crypto.Cipher import DES  # Only 56-bit key

# SECURE - Strong encryption with AES-256-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = os.urandom(32)  # 256-bit key
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)"""
        },

        "Hardcoded Cryptographic Key": {
            "patterns": [
                r'(key|secret|iv|salt)\s*=\s*b?["\'][^"\']{16,}["\']',
                r'AES\.new\s*\([^,]*b?["\'][^"\']{16}',
            ],
            "cwe": "CWE-321",
            "owasp": "A04:2025 - Cryptographic Failures",
            "severity": "critical",
            "description": "Hardcoded cryptographic key in source code. Compromises all encrypted data.",
            "impact": """**Business Impact:**
- All encrypted data can be decrypted by anyone with source code access
- Key compromise affects all environments using the same code
- Cannot rotate keys without code changes and redeployment
- Historical encrypted data remains vulnerable forever

**Technical Impact:**
- Attackers can decrypt all data encrypted with the exposed key
- Cannot implement proper key rotation
- Keys exposed in version control history even after removal
- No separation between development and production encryption""",
            "remediation": """**Immediate Actions:**
1. Remove hardcoded keys from source code immediately
2. Rotate all encryption keys that were hardcoded
3. Re-encrypt affected data with new keys
4. Scan git history for previously committed keys

**Long-term Remediation:**
1. Use Key Management Service (AWS KMS, Azure Key Vault, HashiCorp Vault)
2. Generate keys at runtime using secure random generators
3. Implement envelope encryption for large data sets
4. Use separate keys per environment (dev, staging, prod)
5. Implement automated key rotation policies""",
            "remediation_code": """# VULNERABLE - Hardcoded key
key = b'my_secret_key_16'
cipher = AES.new(key, AES.MODE_GCM)

# SECURE - Runtime key generation
import os
key = os.urandom(32)  # Generate random 256-bit key

# SECURE - AWS KMS
import boto3
kms = boto3.client('kms')
response = kms.generate_data_key(KeyId='alias/my-key', KeySpec='AES_256')
plaintext_key = response['Plaintext']

# SECURE - HashiCorp Vault
import hvac
client = hvac.Client(url='https://vault.example.com')
key = client.secrets.transit.generate_data_key(name='my-key')['data']['plaintext']

# SECURE - Environment variable (for simpler cases)
import os
key = os.environ.get('ENCRYPTION_KEY').encode()"""
        },

        "Insecure Random": {
            "patterns": [
                r'random\.(random|randint|choice)',
                r'Math\.random\(\)',
                r'new Random\(',
            ],
            "cwe": "CWE-338",
            "owasp": "A04:2025 - Cryptographic Failures",
            "severity": "medium",
            "description": "Use of non-cryptographic random number generator for security-sensitive operations.",
            "impact": """**Business Impact:**
- Predictable tokens enable account takeover attacks
- Session IDs can be guessed, bypassing authentication
- Password reset tokens can be predicted
- CSRF tokens become ineffective

**Technical Impact:**
- Math.random() and random.random() use predictable algorithms (Mersenne Twister)
- Attacker can predict future values after observing enough outputs
- Seeds are often based on time, making output reproducible
- No entropy from hardware sources""",
            "remediation": """**Immediate Actions:**
1. Replace random/Math.random with cryptographic alternatives
2. Audit all token generation code for secure random usage
3. Regenerate any tokens created with weak random sources

**Long-term Remediation:**
1. Use secrets module (Python), crypto (Node.js), SecureRandom (Java)
2. Create utility functions that enforce secure random usage
3. Add linting rules to detect insecure random usage
4. Use UUIDs (v4) for identifiers when appropriate
5. Consider hardware random number generators for high-security needs""",
            "remediation_code": """# VULNERABLE - Predictable random
import random
token = random.randint(100000, 999999)
session_id = ''.join(random.choices(string.ascii_letters, k=32))

# SECURE - Cryptographic random
import secrets
token = secrets.randbelow(900000) + 100000
session_id = secrets.token_urlsafe(32)
api_key = secrets.token_hex(32)

// VULNERABLE - JavaScript Math.random
const token = Math.floor(Math.random() * 1000000);

// SECURE - Node.js crypto
const crypto = require('crypto');
const token = crypto.randomInt(100000, 1000000);
const sessionId = crypto.randomBytes(32).toString('hex');
const apiKey = crypto.randomUUID();

// Java - SECURE
import java.security.SecureRandom;
SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);"""
        },

        # ==================== INPUT VALIDATION ====================
        "Insufficient Input Validation": {
            "patterns": [
                r'request\.(GET|POST|args|form|json|query|body|params)\[',
                r'req\.(query|params|body)\.',
                r'\$_(GET|POST|REQUEST|COOKIE)\[',
            ],
            "cwe": "CWE-20",
            "owasp": "A05:2025 - Injection",
            "severity": "medium",
            "description": "Direct use of user input without validation or sanitization.",
            "impact": """**Business Impact:**
- Gateway for injection attacks (SQL, XSS, command injection)
- Data corruption through malformed input
- Application crashes from unexpected data types
- Business logic bypass through manipulated parameters

**Technical Impact:**
- Type confusion vulnerabilities
- Buffer overflows from oversized input
- Format string vulnerabilities
- Integer overflow/underflow attacks""",
            "remediation": """**Immediate Actions:**
1. Implement input validation at all entry points
2. Define expected data types, formats, and ranges
3. Reject invalid input with clear error messages
4. Use schema validation libraries for complex inputs

**Long-term Remediation:**
1. Create centralized validation utilities
2. Use strong typing (TypeScript, Pydantic, dataclasses)
3. Implement allowlist validation over blocklist
4. Add validation to API schemas (OpenAPI, GraphQL)
5. Implement rate limiting to prevent abuse""",
            "remediation_code": """# VULNERABLE - No validation
user_id = request.args['id']
email = request.json['email']

# SECURE - Python with Pydantic
from pydantic import BaseModel, EmailStr, conint

class UserInput(BaseModel):
    id: conint(gt=0, lt=1000000)
    email: EmailStr
    name: str = Field(max_length=100, regex='^[a-zA-Z ]+$')

data = UserInput(**request.json)

# SECURE - Express with Joi
const Joi = require('joi');
const schema = Joi.object({
    id: Joi.number().integer().positive().max(1000000).required(),
    email: Joi.string().email().required(),
    name: Joi.string().max(100).pattern(/^[a-zA-Z ]+$/)
});
const { error, value } = schema.validate(req.body);
if (error) return res.status(400).json({ error: error.details });

// SECURE - Java with Bean Validation
public class UserInput {
    @NotNull @Min(1) @Max(1000000)
    private Long id;
    @Email @NotBlank
    private String email;
}"""
        },

        "Mass Assignment": {
            "patterns": [
                r'(Model|model)\.(create|update).*?request\.(data|json|body)',
                r'User\.objects\.(create|update).*?\*\*request',
                r'new\s+\w+\(req\.body\)',
            ],
            "cwe": "CWE-915",
            "owasp": "A01:2025 - Broken Access Control",
            "severity": "high",
            "description": "Direct assignment of user input to model. May allow modifying unintended fields.",
            "impact": """**Business Impact:**
- Privilege escalation by setting admin/role fields
- Bypassing payment by modifying price fields
- Data tampering affecting business integrity
- Unauthorized access to premium features

**Technical Impact:**
- Users can set fields like is_admin, role, permissions
- Internal fields (created_at, modified_by) can be manipulated
- Foreign key manipulation to access other users' data
- Bypassing business logic validations""",
            "remediation": """**Immediate Actions:**
1. Implement explicit field whitelisting for all model updates
2. Define separate DTOs/schemas for input vs. internal fields
3. Review all create/update operations for mass assignment
4. Add tests to verify protected fields cannot be set

**Long-term Remediation:**
1. Use serializer/form classes that define allowed fields
2. Implement field-level permissions
3. Separate read and write models (CQRS pattern)
4. Add audit logging for sensitive field changes
5. Use immutable fields where appropriate""",
            "remediation_code": """# VULNERABLE - Mass assignment
User.objects.create(**request.data)
user.update(**request.json)

# SECURE - Explicit field whitelist
ALLOWED_FIELDS = ['username', 'email', 'first_name', 'last_name']
user_data = {k: v for k, v in request.data.items() if k in ALLOWED_FIELDS}
User.objects.create(**user_data)

# SECURE - Django REST Framework Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        read_only_fields = ['is_admin', 'is_staff', 'date_joined']

# SECURE - Pydantic model
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    # is_admin and role NOT included - cannot be set by user

user = User(**user_create.dict())

// SECURE - Express/Mongoose
const allowedFields = ['username', 'email', 'firstName', 'lastName'];
const userData = _.pick(req.body, allowedFields);
await User.create(userData);"""
        },

        # ==================== SECURITY MISCONFIGURATION ====================
        "Debug Mode Enabled": {
            "patterns": [
                r'(DEBUG|debug)\s*=\s*True',
                r'app\.debug\s*=\s*True',
                r'(development|dev)\s*:\s*true',
            ],
            "cwe": "CWE-489",
            "owasp": "A02:2025 - Security Misconfiguration",
            "severity": "high",
            "description": "Debug mode enabled. Exposes sensitive information including stack traces, variable values, and source code.",
            "impact": """**Business Impact:**
- Exposure of sensitive configuration and environment variables
- Source code disclosure revealing business logic and vulnerabilities
- Database credentials and API keys visible in error pages
- Detailed attack surface information provided to adversaries

**Technical Impact:**
- Full stack traces expose internal file paths and code structure
- Interactive debugger (Werkzeug) allows remote code execution
- SQL queries and parameters logged in debug output
- Session tokens and authentication details exposed""",
            "remediation": """**Immediate Actions:**
1. Disable debug mode in all production deployments
2. Review error handling to ensure generic messages in production
3. Check for debug endpoints (/debug, /trace, etc.)
4. Verify environment variables are correctly set

**Long-term Remediation:**
1. Use environment-specific configuration files
2. Implement separate logging for development vs. production
3. Use structured error responses without internal details
4. Add deployment checks that verify debug is disabled
5. Implement health check endpoints for monitoring""",
            "remediation_code": """# VULNERABLE - Debug always enabled
DEBUG = True
app.run(debug=True)

# SECURE - Environment-based configuration
import os
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# SECURE - Environment detection
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')
DEBUG = ENVIRONMENT == 'development'

# SECURE - Never run debug in production
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0' if not debug_mode else '127.0.0.1')

// Node.js - SECURE
const isProduction = process.env.NODE_ENV === 'production';
if (!isProduction) {
    app.use(errorHandler({ log: true, stack: true }));
} else {
    app.use(productionErrorHandler);  // Generic errors only
}"""
        },

        "CORS Misconfiguration": {
            "patterns": [
                r'Access-Control-Allow-Origin.*?\*',
                r'cors\s*\(\s*\{\s*origin\s*:\s*["\' ]\*',
                r'AllowAnyOrigin\s*\(\s*\)',
            ],
            "cwe": "CWE-942",
            "owasp": "A02:2025 - Security Misconfiguration",
            "severity": "medium",
            "description": "Overly permissive CORS policy allows any origin. May enable cross-origin attacks.",
            "remediation": "Restrict CORS to specific trusted origins. Avoid wildcard in production.",
            "remediation_code": """// Bad
app.use(cors({ origin: '*' }));

// Good
const whitelist = ['https://example.com', 'https://app.example.com'];
app.use(cors({
  origin: function(origin, callback) {
    if (whitelist.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));"""
        },

        "SSL/TLS Verification Disabled": {
            "patterns": [
                r'verify\s*=\s*False',
                r'VERIFY_SSL\s*=\s*False',
                r'InsecureRequestWarning',
                r'ssl._create_unverified_context',
            ],
            "cwe": "CWE-295",
            "owasp": "A04:2025 - Cryptographic Failures",
            "severity": "high",
            "description": "SSL/TLS certificate verification disabled. Vulnerable to man-in-the-middle attacks.",
            "remediation": "Always verify SSL certificates. Use proper certificate authorities.",
            "remediation_code": """# Bad
import requests
response = requests.get(url, verify=False)

# Good
import requests
response = requests.get(url, verify=True)  # Or verify='/path/to/ca-bundle.crt'"""
        },

        # ==================== BUSINESS LOGIC ====================
        "Broken Access Control": {
            "patterns": [
                r'@app\.route.*?methods\s*=\s*\[[^\]]*POST[^\]]*\](?!.*@login_required)',
                r'def\s+(update|delete|edit).*?\((?!.*permission)',
            ],
            "cwe": "CWE-284",
            "owasp": "A01:2025 - Broken Access Control",
            "severity": "high",
            "description": "Missing access control checks on sensitive operations.",
            "remediation": "Implement proper authentication and authorization checks for all sensitive endpoints.",
            "remediation_code": """# Bad
@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    user_id = request.json['user_id']
    User.delete(user_id)

# Good
@app.route('/admin/delete_user', methods=['POST'])
@login_required
@admin_required
def delete_user():
    user_id = request.json['user_id']
    User.delete(user_id)"""
        },

        "Information Disclosure": {
            "patterns": [
                r'(print|console\.log|echo)\s*\([^)]*password',
                r'(print|console\.log|echo)\s*\([^)]*secret',
                r'traceback\.print_exc\(\)',
                r'error_reporting\s*\(\s*E_ALL',
            ],
            "cwe": "CWE-200",
            "owasp": "A06:2025 - Insecure Design",
            "severity": "medium",
            "description": "Sensitive information may be exposed through logging or error messages.",
            "remediation": "Remove or redact sensitive data from logs. Implement structured logging.",
            "remediation_code": """# Bad
print(f"User password: {password}")
console.log("API Key:", api_key)

# Good
logger.info("User authenticated", extra={'user_id': user_id})
logger.debug("API request", extra={'endpoint': endpoint})  # No sensitive data"""
        },

        # ==================== RACE CONDITIONS & CONCURRENCY ====================
        "Time-of-Check Time-of-Use (TOCTOU)": {
            "patterns": [
                r'os\.path\.exists.*?open\s*\(',
                r'if\s+os\.path\.isfile.*?open',
            ],
            "cwe": "CWE-367",
            "owasp": "A06:2025 - Insecure Design",
            "severity": "medium",
            "description": "Time-of-check to time-of-use race condition. File state may change between check and use.",
            "remediation": "Use atomic operations or proper file locking mechanisms.",
            "remediation_code": """# Bad
if os.path.exists(filename):
    with open(filename, 'r') as f:
        data = f.read()

# Better
try:
    with open(filename, 'r') as f:
        data = f.read()
except FileNotFoundError:
    pass"""
        },

        # ==================== MOBILE-SPECIFIC ====================
        "Insecure Data Storage": {
            "patterns": [
                r'SharedPreferences.*?putString.*?(password|token|key)',
                r'NSUserDefaults.*?(password|secret|token)',
            ],
            "cwe": "CWE-312",
            "owasp": "A04:2025 - Cryptographic Failures",
            "severity": "high",
            "description": "Sensitive data stored insecurely in mobile storage.",
            "remediation": "Use secure storage mechanisms: Keychain (iOS), Keystore (Android).",
            "remediation_code": """// Android - Bad
SharedPreferences prefs = getSharedPreferences("app", MODE_PRIVATE);
prefs.edit().putString("api_key", apiKey).apply();

// Android - Good
// Use Android Keystore for sensitive data"""
        },

        # ==================== API SECURITY ====================
        "Missing Rate Limiting": {
            "patterns": [
                r'@app\.route.*?/api/(?!.*@limiter)',
                r'app\.(get|post).*?/api/(?!.*limiter)',
            ],
            "cwe": "CWE-770",
            "owasp": "A06:2025 - Insecure Design",
            "severity": "medium",
            "description": "API endpoint lacks rate limiting. Vulnerable to brute force and DoS attacks.",
            "remediation": "Implement rate limiting on all API endpoints using libraries like Flask-Limiter or express-rate-limit.",
            "remediation_code": """# Python Flask - Bad
@app.route('/api/login', methods=['POST'])
def login():
    pass

# Python Flask - Good
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    pass"""
        },

        "Sensitive Data in URL": {
            "patterns": [
                r'@app\.route.*?<.*?(password|token|key|secret)',
                r'(GET|get).*?/api/.*?\?(password|token|api[_-]?key)',
            ],
            "cwe": "CWE-598",
            "owasp": "A06:2025 - Insecure Design",
            "severity": "high",
            "description": "Sensitive data passed in URL parameters. Logged in server logs and browser history.",
            "remediation": "Use POST requests with body parameters or headers for sensitive data.",
            "remediation_code": """# Bad
@app.route('/reset-password/<token>')

# Good
@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.json.get('token')"""
        },

        # ==================== SSRF (Server-Side Request Forgery) ====================
        "SSRF (Server-Side Request Forgery)": {
            "patterns": [
                # Python SSRF patterns
                r'requests\.(get|post|put|delete|head|options)\s*\([^)]*\+',
                r'requests\.(get|post|put|delete)\s*\(\s*f["\']',
                r'requests\.(get|post|put|delete)\s*\(\s*\w+\s*[,)]',
                r'urllib\.request\.urlopen\s*\([^)]*\+',
                r'urllib\.request\.urlopen\s*\(\s*\w+',
                r'urlopen\s*\([^)]*\+',
                r'http\.client\.HTTPConnection\s*\([^)]*\+',
                # JavaScript/Node.js SSRF
                r'fetch\s*\(\s*\w+',
                r'fetch\s*\([^)]*\+',
                r'axios\.(get|post|put|delete)\s*\([^)]*\+',
                r'axios\.(get|post|put|delete)\s*\(\s*\w+',
                r'http\.request\s*\([^)]*\+',
                r'https\.request\s*\([^)]*\+',
                # Java SSRF
                r'new\s+URL\s*\([^)]*\+',
                r'HttpURLConnection.*?\+',
                r'RestTemplate.*?getForObject\s*\([^)]*\+',
                # PHP SSRF
                r'file_get_contents\s*\([^)]*\$',
                r'curl_setopt.*?CURLOPT_URL.*?\$',
                r'fopen\s*\([^)]*\$',
                # Go SSRF
                r'http\.Get\s*\([^)]*\+',
                r'http\.Post\s*\([^)]*\+',
            ],
            "cwe": "CWE-918",
            "owasp": "A08:2025 - Server-Side Request Forgery (SSRF)",
            "severity": "high",
            "description": "HTTP request with user-controlled URL. Can be exploited to access internal services or bypass firewalls.",
            "impact": """**Business Impact:**
- Access to internal services not intended for public access
- Cloud metadata API exploitation (AWS, GCP, Azure) exposing credentials
- Bypass of network security controls and firewalls
- Data exfiltration from internal systems
- Potential for lateral movement within internal network

**Technical Impact:**
- Access to cloud instance metadata (169.254.169.254) exposing IAM credentials
- Port scanning of internal network from trusted server
- Reading internal files via file:// protocol
- Accessing internal APIs and databases
- Exploitation of services that trust internal network traffic""",
            "remediation": """**Immediate Actions:**
1. Implement URL allowlist for permitted external domains
2. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x)
3. Block localhost, 127.0.0.1, 0.0.0.0, and IPv6 loopback
4. Block cloud metadata IPs (169.254.169.254)

**Long-term Remediation:**
1. Use a dedicated proxy service for external requests
2. Implement network segmentation to isolate backend services
3. Deploy Web Application Firewall with SSRF protection
4. Use DNS resolution verification to catch DNS rebinding attacks
5. Implement request timeout and size limits""",
            "remediation_code": """# VULNERABLE - Direct URL from user
url = request.args.get('url')
response = requests.get(url)

# SECURE - Comprehensive URL validation
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_HOSTS = ['api.github.com', 'api.example.com']
BLOCKED_PORTS = [22, 23, 25, 445, 3389]

def is_safe_url(url):
    try:
        parsed = urlparse(url)

        # Only allow http/https
        if parsed.scheme not in ['http', 'https']:
            return False

        # Check against allowlist
        if ALLOWED_HOSTS and parsed.hostname not in ALLOWED_HOSTS:
            return False

        # Resolve hostname to IP
        hostname = parsed.hostname
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)

        # Block private, loopback, link-local IPs
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False

        # Block cloud metadata IP
        if ip_str == '169.254.169.254':
            return False

        # Block dangerous ports
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if port in BLOCKED_PORTS:
            return False

        return True
    except Exception:
        return False

url = request.args.get('url')
if is_safe_url(url):
    response = requests.get(url, timeout=10, allow_redirects=False)"""
        },

        # ==================== OPEN REDIRECT ====================
        "Open Redirect": {
            "patterns": [
                # Python redirect patterns
                r'redirect\s*\(\s*request\.',
                r'redirect\s*\(\s*\w+\s*\)',
                r'redirect\s*\([^)]*\+',
                r'HttpResponseRedirect\s*\([^)]*\+',
                r'HttpResponseRedirect\s*\(\s*\w+',
                # JavaScript/Express redirect
                r'res\.redirect\s*\([^)]*\+',
                r'res\.redirect\s*\(\s*req\.',
                r'location\.href\s*=\s*[^;]*\+',
                r'window\.location\s*=\s*[^;]*\+',
                # Java redirect
                r'sendRedirect\s*\([^)]*\+',
                r'response\.sendRedirect\s*\(\s*\w+',
                # PHP redirect
                r'header\s*\([^)]*Location[^)]*\$',
            ],
            "cwe": "CWE-601",
            "owasp": "A01:2025 - Broken Access Control",
            "severity": "medium",
            "description": "Redirect to user-controlled URL. Can be used for phishing attacks.",
            "remediation": "Validate redirect URLs against a whitelist. Use relative URLs when possible.",
            "remediation_code": """# Python Flask - Bad
@app.route('/redirect')
def redirect_handler():
    url = request.args.get('url')
    return redirect(url)

# Python Flask - Good
ALLOWED_HOSTS = ['example.com', 'app.example.com']

@app.route('/redirect')
def redirect_handler():
    url = request.args.get('url')
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        abort(400, 'Invalid redirect URL')
    return redirect(url)"""
        },

        # ==================== TEMPLATE INJECTION ====================
        "Server-Side Template Injection (SSTI)": {
            "patterns": [
                # Python/Jinja2 SSTI
                r'render_template_string\s*\([^)]*\+',
                r'render_template_string\s*\(\s*\w+',
                r'Template\s*\([^)]*\+',
                r'Template\s*\(\s*\w+\s*\)',
                r'Environment\s*\(.*?undefined\s*=',
                r'from_string\s*\([^)]*\+',
                # JavaScript template engines
                r'ejs\.render\s*\([^)]*,\s*\{',
                r'pug\.render\s*\([^)]*\+',
                r'handlebars\.compile\s*\([^)]*\+',
                r'nunjucks\.renderString\s*\([^)]*\+',
                # Java template engines
                r'FreeMarkerConfigurer.*?processTemplate',
                r'VelocityEngine.*?evaluate',
                r'Thymeleaf.*?process',
            ],
            "cwe": "CWE-1336",
            "owasp": "A05:2025 - Injection",
            "severity": "critical",
            "description": "Template rendered with user-controlled input. Can lead to remote code execution.",
            "remediation": "Never pass user input directly to template engines. Use sandboxed environments.",
            "remediation_code": """# Python Flask - Bad
from flask import render_template_string
template = request.args.get('template')
return render_template_string(template)

# Python Flask - Good
# Use pre-defined templates with placeholders
from flask import render_template
return render_template('page.html', content=user_content)

# Or use strict sandboxing
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string(safe_template)"""
        },

        # ==================== XML EXTERNAL ENTITY (XXE) ====================
        "XML External Entity (XXE)": {
            "patterns": [
                # Python XXE
                r'xml\.etree\.ElementTree\.parse\s*\(',
                r'lxml\.etree\.parse\s*\(',
                r'xml\.dom\.minidom\.parse\s*\(',
                r'xmltodict\.parse\s*\(',
                # Java XXE
                r'DocumentBuilderFactory\.newInstance\s*\(',
                r'SAXParserFactory\.newInstance\s*\(',
                r'XMLInputFactory\.newInstance\s*\(',
                r'TransformerFactory\.newInstance\s*\(',
                # PHP XXE
                r'simplexml_load_string\s*\(',
                r'DOMDocument.*?loadXML\s*\(',
                # .NET XXE
                r'XmlDocument\s*\(\)',
                r'XmlReader\.Create\s*\(',
            ],
            "cwe": "CWE-611",
            "owasp": "A02:2025 - Security Misconfiguration",
            "severity": "high",
            "description": "XML parsing without disabling external entity processing. Vulnerable to XXE attacks.",
            "remediation": "Disable external entity processing. Use defusedxml in Python.",
            "remediation_code": """# Python - Bad
import xml.etree.ElementTree as ET
tree = ET.parse(user_xml)

# Python - Good
import defusedxml.ElementTree as ET
tree = ET.parse(user_xml)

// Java - Bad
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Java - Good
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);"""
        },

        # ==================== PROTOTYPE POLLUTION ====================
        "Prototype Pollution": {
            "patterns": [
                r'Object\.assign\s*\([^)]*,\s*\w+\s*\)',
                r'_\.merge\s*\([^)]*,\s*\w+\s*\)',
                r'_\.extend\s*\([^)]*,\s*\w+\s*\)',
                r'_\.defaultsDeep\s*\(',
                r'\[__proto__\]',
                r'\["__proto__"\]',
                r"__proto__\s*:",
                r'constructor\[.*?prototype',
            ],
            "cwe": "CWE-1321",
            "owasp": "A03:2025 - Software Supply Chain Failures",
            "severity": "high",
            "description": "JavaScript object merge with user-controlled input. Can lead to prototype pollution.",
            "remediation": "Sanitize object keys. Use Object.create(null) or frozen prototypes.",
            "remediation_code": """// Bad
const merged = Object.assign({}, req.body);
const merged = _.merge({}, req.body);

// Good
function sanitize(obj) {
    if (typeof obj !== 'object') return obj;
    const safe = Object.create(null);
    for (const key of Object.keys(obj)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        safe[key] = sanitize(obj[key]);
    }
    return safe;
}
const merged = Object.assign({}, sanitize(req.body));"""
        },

        # ==================== REGEX & LOGIC ====================
        "Regular Expression DoS (ReDoS)": {
            "patterns": [
                r're\.compile\([^)]*\(\.\*\)\+',
                r're\.compile\([^)]*\(\.\+\)\*',
                r'new RegExp\([^)]*\(\.\*\)\+',
            ],
            "cwe": "CWE-1333",
            "owasp": "A06:2025 - Insecure Design",
            "severity": "medium",
            "description": "Regex pattern with catastrophic backtracking. Can cause denial of service.",
            "remediation": "Avoid nested quantifiers. Use atomic groups or possessive quantifiers. Test regex with ReDoS checkers.",
            "remediation_code": """# Bad (ReDoS vulnerable)
pattern = re.compile(r'(a+)+b')

# Good
pattern = re.compile(r'a+b')

# Or limit input length
if len(user_input) <= 100:
    pattern.match(user_input)"""
        },

        # ==================== A01:2025 - BROKEN ACCESS CONTROL ====================
        "Insecure Direct Object Reference (IDOR)": {
            "patterns": [
                # Direct ID usage without authorization check
                r'User\.objects\.get\s*\(\s*id\s*=\s*request\.',
                r'Model\.objects\.get\s*\(\s*pk\s*=\s*\w+\s*\)',
                r'findById\s*\(\s*req\.(params|query|body)',
                r'findOne\s*\(\s*\{\s*_id\s*:\s*req\.',
                r'\.get\s*\(\s*["\']?/\w+/:\w+["\']?\s*\)',
                # Missing ownership checks
                r'DELETE\s+FROM\s+\w+\s+WHERE\s+id\s*=',
                r'UPDATE\s+\w+\s+SET.*?WHERE\s+id\s*=',
            ],
            "cwe": "CWE-639",
            "owasp": "A01:2025 - Broken Access Control",
            "severity": "high",
            "description": "Direct object reference without proper authorization. Users may access other users' data.",
            "remediation": "Always verify resource ownership. Use indirect references or authorization decorators.",
            "remediation_code": """# Bad - IDOR vulnerable
@app.route('/user/<id>')
def get_user(id):
    return User.query.get(id)

# Good - Check ownership
@app.route('/user/<id>')
@login_required
def get_user(id):
    user = User.query.get(id)
    if user.id != current_user.id and not current_user.is_admin:
        abort(403)
    return user"""
        },

        "Missing Authorization Check": {
            "patterns": [
                # Routes without auth decorators
                r'@app\.route.*?def\s+\w+\([^)]*\):\s*\n\s+[^@]',
                r'router\.(get|post|put|delete)\s*\([^)]+,\s*\(?[^)]*\)?\s*=>\s*\{',
                # Admin functions without admin check
                r'def\s+(admin|delete|update|create)_\w+\s*\([^)]*\):',
                r'async\s+function\s+(admin|delete|update|create)\w+\s*\(',
                # Direct database modifications
                r'\.delete\s*\(\s*\)',
                r'\.destroy\s*\(\s*\)',
            ],
            "cwe": "CWE-862",
            "owasp": "A01:2025 - Broken Access Control",
            "severity": "high",
            "description": "Sensitive operation without authorization check. May allow unauthorized access.",
            "remediation": "Add authorization decorators or middleware to all sensitive endpoints.",
            "remediation_code": """# Bad
@app.route('/admin/users', methods=['DELETE'])
def delete_user():
    pass

# Good
@app.route('/admin/users', methods=['DELETE'])
@login_required
@admin_required
def delete_user():
    pass"""
        },

        "Privilege Escalation": {
            "patterns": [
                # Role/privilege modification
                r'user\.role\s*=\s*(request|req)\.',
                r'user\.is_admin\s*=\s*(True|true|1)',
                r'\.update\s*\(\s*\{[^}]*role[^}]*\}\s*\)',
                r'\.update\s*\(\s*\{[^}]*admin[^}]*\}\s*\)',
                r'user\[["\']role["\']\]\s*=',
                r'user\[["\']permissions["\']\]\s*=',
            ],
            "cwe": "CWE-269",
            "owasp": "A01:2025 - Broken Access Control",
            "severity": "critical",
            "description": "User role or privilege modification without proper authorization.",
            "remediation": "Never allow users to modify their own roles. Implement strict role assignment policies.",
            "remediation_code": """# Bad
user.role = request.json.get('role')

# Good - Only admins can change roles
@admin_required
def update_user_role(user_id, new_role):
    if new_role not in ALLOWED_ROLES:
        abort(400)
    user = User.query.get(user_id)
    user.role = new_role
    db.session.commit()"""
        },

        # ==================== A02:2025 - SECURITY MISCONFIGURATION ====================
        "Debug Mode in Production": {
            "patterns": [
                r'DEBUG\s*=\s*(True|true|1|"true")',
                r'app\.debug\s*=\s*(True|true)',
                r'\.run\s*\([^)]*debug\s*=\s*(True|true)',
                r'FLASK_DEBUG\s*=\s*1',
                r'NODE_ENV\s*[=:]\s*["\']?development',
                r'environment\s*[=:]\s*["\']?development',
                r'settings\.DEBUG',
            ],
            "cwe": "CWE-489",
            "owasp": "A02:2025 - Security Misconfiguration",
            "severity": "high",
            "description": "Debug mode enabled. Exposes sensitive information and stack traces.",
            "remediation": "Disable debug mode in production. Use environment variables for configuration.",
            "remediation_code": """# Bad
app.run(debug=True)
DEBUG = True

# Good
import os
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
app.run(debug=False)"""
        },

        "Insecure CORS Configuration": {
            "patterns": [
                r'Access-Control-Allow-Origin["\']?\s*[=:]\s*["\']?\*',
                r'CORS\s*\(\s*\w+\s*,\s*origins\s*=\s*["\']?\*',
                r'cors\s*\(\s*\{\s*origin\s*:\s*["\']?\*',
                r'allowedOrigins\s*[=:]\s*\[\s*["\']?\*',
                r'Access-Control-Allow-Credentials.*?true.*?Allow-Origin.*?\*',
            ],
            "cwe": "CWE-942",
            "owasp": "A02:2025 - Security Misconfiguration",
            "severity": "high",
            "description": "CORS configured to allow all origins. May enable cross-origin attacks.",
            "remediation": "Restrict CORS to specific trusted domains. Never use wildcard with credentials.",
            "remediation_code": """# Bad
CORS(app, origins='*')

# Good
CORS(app, origins=['https://trusted-domain.com'])"""
        },

        "Default Credentials": {
            "patterns": [
                r'password\s*[=:]\s*["\']?(admin|password|123456|default|test)',
                r'username\s*[=:]\s*["\']?(admin|root|test|user)',
                r'secret\s*[=:]\s*["\']?(secret|changeme|default)',
                r'api_key\s*[=:]\s*["\']?(test|demo|example)',
            ],
            "cwe": "CWE-1392",
            "owasp": "A02:2025 - Security Misconfiguration",
            "severity": "critical",
            "description": "Default or weak credentials detected. Easy target for attackers.",
            "remediation": "Use strong, unique credentials. Store secrets in environment variables or secret managers.",
            "remediation_code": """# Bad
DB_PASSWORD = 'admin'

# Good
import os
DB_PASSWORD = os.environ.get('DB_PASSWORD')
if not DB_PASSWORD:
    raise ValueError('DB_PASSWORD environment variable not set')"""
        },

        "Verbose Error Messages": {
            "patterns": [
                r'traceback\.print_exc\s*\(',
                r'console\.error\s*\(\s*\w+\.stack',
                r'print\s*\(\s*e\s*\)',
                r'print\s*\(\s*exception',
                r'Response\s*\([^)]*str\s*\(\s*e\s*\)',
                r'return.*?str\s*\(\s*exception',
                r'res\.send\s*\(\s*err\s*\)',
            ],
            "cwe": "CWE-209",
            "owasp": "A02:2025 - Security Misconfiguration",
            "severity": "medium",
            "description": "Detailed error messages exposed to users. May leak sensitive information.",
            "remediation": "Log errors server-side but return generic messages to users.",
            "remediation_code": """# Bad
except Exception as e:
    return str(e), 500

# Good
except Exception as e:
    logger.error(f"Error: {e}", exc_info=True)
    return {"error": "An internal error occurred"}, 500"""
        },

        # ==================== A03:2025 - SOFTWARE SUPPLY CHAIN FAILURES ====================
        "Vulnerable Dependency Installation": {
            "patterns": [
                # Insecure pip install
                r'pip\s+install\s+--trusted-host',
                r'pip\s+install\s+--index-url\s+http://',
                r'pip\s+install\s+[^-\s]+==',  # Pinned versions (flag for review)
                # npm insecure
                r'npm\s+install\s+--unsafe-perm',
                r'npm\s+config\s+set\s+strict-ssl\s+false',
                # Executing code from URLs
                r'curl.*?\|\s*bash',
                r'curl.*?\|\s*sh',
                r'wget.*?\|\s*bash',
                r'exec\s*\(\s*urllib',
            ],
            "cwe": "CWE-829",
            "owasp": "A03:2025 - Software Supply Chain Failures",
            "severity": "high",
            "description": "Insecure dependency installation method. May install compromised packages.",
            "remediation": "Use package lock files, verify checksums, use private registries.",
            "remediation_code": """# Bad
pip install --trusted-host pypi.example.com package

# Good
pip install --require-hashes -r requirements.txt
npm ci  # Uses package-lock.json"""
        },

        "Dependency Confusion": {
            "patterns": [
                r'--extra-index-url\s+http',
                r'--index-url\s+http[^s]',
                r'registry\s*[=:]\s*http[^s]',
                r'npm\s+config\s+set\s+registry\s+http[^s]',
            ],
            "cwe": "CWE-427",
            "owasp": "A03:2025 - Software Supply Chain Failures",
            "severity": "high",
            "description": "Mixed public/private package sources. Vulnerable to dependency confusion attacks.",
            "remediation": "Use only HTTPS registries. Namespace private packages properly.",
            "remediation_code": """# Bad - Mixed sources
pip install --extra-index-url http://internal.repo package

# Good
pip install --index-url https://secure.internal.repo package"""
        },

        # ==================== A06:2025 - INSECURE DESIGN ====================
        "Missing Input Validation": {
            "patterns": [
                # Direct use of request data without validation
                r'request\.(json|form|args)\[',
                r'req\.(body|query|params)\[',
                r'\$_(GET|POST|REQUEST)\[',
                # Missing length checks
                r'def\s+\w+\s*\([^)]*\):\s*\n\s+[^#]*request\.',
            ],
            "cwe": "CWE-20",
            "owasp": "A06:2025 - Insecure Design",
            "severity": "medium",
            "description": "User input used without validation. May lead to various injection attacks.",
            "remediation": "Validate all input using schemas, type checking, and length limits.",
            "remediation_code": """# Bad
name = request.json['name']

# Good
from pydantic import BaseModel, validator

class UserInput(BaseModel):
    name: str

    @validator('name')
    def validate_name(cls, v):
        if len(v) > 100:
            raise ValueError('Name too long')
        return v.strip()

data = UserInput(**request.json)"""
        },

        "Business Logic Flaw": {
            "patterns": [
                # Negative number vulnerabilities
                r'(amount|quantity|count|price)\s*=\s*int\s*\(',
                r'(amount|quantity|count|price)\s*<\s*0',
                # Race conditions
                r'if.*?balance.*?>=.*?:\s*\n.*?balance\s*-=',
                # Missing transaction locks
                r'SELECT.*?FOR UPDATE',
            ],
            "cwe": "CWE-840",
            "owasp": "A06:2025 - Insecure Design",
            "severity": "high",
            "description": "Potential business logic vulnerability. May allow manipulation of transactions.",
            "remediation": "Use database transactions, validate business rules server-side.",
            "remediation_code": """# Bad - Race condition
if user.balance >= amount:
    user.balance -= amount

# Good - Atomic operation
with db.session.begin():
    user = User.query.with_for_update().get(user_id)
    if user.balance < amount:
        raise InsufficientFunds()
    user.balance -= amount"""
        },

        # ==================== A07:2025 - AUTHENTICATION FAILURES ====================
        "Weak Password Requirements": {
            "patterns": [
                r'len\s*\(\s*password\s*\)\s*>=?\s*[1-7]\s*[^0-9]',
                r'password\.length\s*>=?\s*[1-7][^0-9]',
                r'minLength\s*[=:]\s*[1-7][^0-9]',
                r'MIN_PASSWORD_LENGTH\s*=\s*[1-7][^0-9]',
            ],
            "cwe": "CWE-521",
            "owasp": "A07:2025 - Authentication Failures",
            "severity": "high",
            "description": "Weak password length requirement. Makes brute-force attacks easier.",
            "remediation": "Require minimum 12 characters, check against breached passwords.",
            "remediation_code": """# Bad
if len(password) >= 6:
    pass

# Good
MIN_PASSWORD_LENGTH = 12
if len(password) < MIN_PASSWORD_LENGTH:
    raise ValueError('Password must be at least 12 characters')
# Also check against breached password databases"""
        },

        "Insecure Session Management": {
            "patterns": [
                # Session fixation
                r'session\s*\[\s*["\']session_id["\']\s*\]\s*=\s*request\.',
                r'PHPSESSID\s*=\s*\$_',
                # Missing session regeneration
                r'session\s*\[\s*["\']user["\']\s*\]\s*=.*?login',
                # Insecure cookie settings
                r'set_cookie\s*\([^)]*secure\s*=\s*(False|false)',
                r'cookie\s*\([^)]*httpOnly\s*:\s*false',
                r'SESSION_COOKIE_SECURE\s*=\s*(False|false)',
            ],
            "cwe": "CWE-384",
            "owasp": "A07:2025 - Authentication Failures",
            "severity": "high",
            "description": "Insecure session management. May allow session hijacking or fixation.",
            "remediation": "Regenerate session on login, use secure cookie flags.",
            "remediation_code": """# Bad
session['user'] = user_id

# Good
session.regenerate()  # Regenerate session ID on login
session['user'] = user_id
response.set_cookie('session', value=token, secure=True, httponly=True, samesite='Strict')"""
        },

        "JWT Security Issues": {
            "patterns": [
                # Algorithm none attack
                r'algorithm\s*[=:]\s*["\']?(none|None)["\']?',
                r'algorithms\s*[=:]\s*\[.*?["\']none["\']',
                # Weak secrets
                r'jwt\.encode\([^)]*,\s*["\'][^"\']{1,20}["\']',
                r'JWT_SECRET\s*=\s*["\'][^"\']{1,20}["\']',
                # Missing expiration
                r'jwt\.encode\([^)]*\)(?!.*?exp)',
            ],
            "cwe": "CWE-347",
            "owasp": "A07:2025 - Authentication Failures",
            "severity": "critical",
            "description": "JWT implementation vulnerability. May allow token forgery or replay attacks.",
            "remediation": "Use strong secrets, explicit algorithms, and short expiration times.",
            "remediation_code": """# Bad
token = jwt.encode(payload, 'secret', algorithm='none')

# Good
import os
SECRET_KEY = os.environ.get('JWT_SECRET')  # At least 256 bits
token = jwt.encode(
    {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(hours=1)},
    SECRET_KEY,
    algorithm='HS256'
)"""
        },

        # ==================== A09:2025 - SECURITY LOGGING AND ALERTING FAILURES ====================
        "Missing Security Logging": {
            "patterns": [
                # Login without logging
                r'def\s+login\s*\([^)]*\):\s*\n(?!.*?log)',
                r'authenticate\s*\([^)]*\)(?!.*?log)',
                # No audit trail
                r'def\s+(delete|update|create)\s*\([^)]*\):\s*\n(?!.*?log)',
            ],
            "cwe": "CWE-778",
            "owasp": "A09:2025 - Security Logging and Alerting Failures",
            "severity": "medium",
            "description": "Security-relevant operations not logged. Hinders incident response.",
            "remediation": "Log all authentication attempts, access control decisions, and data modifications.",
            "remediation_code": """# Bad
def login(username, password):
    user = authenticate(username, password)
    return user

# Good
def login(username, password):
    user = authenticate(username, password)
    if user:
        logger.info(f"Successful login for user {username}", extra={'ip': request.remote_addr})
    else:
        logger.warning(f"Failed login attempt for user {username}", extra={'ip': request.remote_addr})
    return user"""
        },

        "Log Injection": {
            "patterns": [
                r'logger\.(info|debug|warn|error)\s*\(\s*f["\']',
                r'logger\.(info|debug|warn|error)\s*\([^)]*\+',
                r'logging\.(info|debug|warn|error)\s*\(\s*f["\']',
                r'console\.log\s*\(\s*`',
                r'print\s*\(\s*f["\'].*?request\.',
            ],
            "cwe": "CWE-117",
            "owasp": "A09:2025 - Security Logging and Alerting Failures",
            "severity": "medium",
            "description": "User input in log messages without sanitization. May allow log forging.",
            "remediation": "Sanitize log inputs, use structured logging with separate fields.",
            "remediation_code": """# Bad
logger.info(f"User logged in: {username}")

# Good
logger.info("User logged in", extra={'username': sanitize(username)})"""
        },

        # ==================== A10:2025 - MISHANDLING OF EXCEPTIONAL CONDITIONS ====================
        "Empty Exception Handler": {
            "patterns": [
                r'except\s*:\s*\n\s+pass',
                r'except\s+\w+\s*:\s*\n\s+pass',
                r'catch\s*\([^)]*\)\s*\{\s*\}',
                r'catch\s*\([^)]*\)\s*\{\s*//.*?\}',
                r'rescue\s*\n\s+#',
            ],
            "cwe": "CWE-390",
            "owasp": "A10:2025 - Mishandling of Exceptional Conditions",
            "severity": "high",
            "description": "Exception silently ignored. May hide critical errors and security issues.",
            "remediation": "Always log exceptions. Handle specific exception types appropriately.",
            "remediation_code": """# Bad
try:
    risky_operation()
except:
    pass

# Good
try:
    risky_operation()
except SpecificError as e:
    logger.error(f"Operation failed: {e}")
    raise  # Or handle appropriately"""
        },

        "Fail-Open Logic": {
            "patterns": [
                # Authentication fail-open
                r'except.*?:\s*\n.*?return\s+True',
                r'catch.*?\{\s*\n.*?return\s+true',
                # Authorization fail-open
                r'except.*?:\s*\n.*?authorized\s*=\s*True',
                r'if.*?error.*?:\s*\n.*?allow',
                # Default to permissive
                r'except.*?:\s*\n.*?access\s*=\s*["\']?granted',
            ],
            "cwe": "CWE-636",
            "owasp": "A10:2025 - Mishandling of Exceptional Conditions",
            "severity": "critical",
            "description": "Security check fails open on error. Attackers can bypass security by causing errors.",
            "remediation": "Always fail secure. Deny access on any error condition.",
            "remediation_code": """# Bad - Fail open
def check_auth(token):
    try:
        return verify_token(token)
    except:
        return True  # DANGEROUS!

# Good - Fail closed
def check_auth(token):
    try:
        return verify_token(token)
    except Exception as e:
        logger.error(f"Auth check failed: {e}")
        return False  # Deny on error"""
        },

        "Unhandled Exception Exposure": {
            "patterns": [
                # Missing global error handler
                r'@app\.route.*?def\s+\w+\([^)]*\):\s*\n(?!.*?try)',
                # Stack trace in response
                r'traceback\.format_exc\s*\(\)',
                r'\.stack\s*\)',
                r'err\.stack',
            ],
            "cwe": "CWE-248",
            "owasp": "A10:2025 - Mishandling of Exceptional Conditions",
            "severity": "medium",
            "description": "Unhandled exceptions may expose sensitive information or crash the application.",
            "remediation": "Implement global error handlers. Never expose stack traces to users.",
            "remediation_code": """# Good - Global error handler
@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("Unhandled exception")
    return {"error": "Internal server error"}, 500"""
        },

        "Resource Exhaustion": {
            "patterns": [
                # Unbounded loops with user input
                r'while\s+True.*?request\.',
                r'for\s+\w+\s+in\s+range\s*\(\s*int\s*\(\s*request\.',
                # Missing timeouts
                r'requests\.(get|post)\s*\([^)]*\)(?!.*?timeout)',
                r'urllib\.request\.urlopen\s*\([^)]*\)(?!.*?timeout)',
                # Unbounded file reads
                r'\.read\s*\(\s*\)',
            ],
            "cwe": "CWE-400",
            "owasp": "A10:2025 - Mishandling of Exceptional Conditions",
            "severity": "medium",
            "description": "Resource usage not bounded. May lead to denial of service.",
            "remediation": "Set limits on iterations, timeouts on network calls, max sizes on reads.",
            "remediation_code": """# Bad
response = requests.get(url)
data = file.read()

# Good
response = requests.get(url, timeout=30)
data = file.read(MAX_FILE_SIZE)"""
        },
    }

    # Safe patterns that indicate code is likely not vulnerable (false positive reduction)
    SAFE_PATTERNS = {
        "sql_injection": [
            r'\.execute\s*\([^,]+,\s*[\(\[]',  # Parameterized query with tuple/list
            r'\.execute\s*\([^,]+,\s*\{',  # Named parameters
            r'session\.query\(',  # SQLAlchemy ORM
            r'Model\.objects\.',  # Django ORM
            r'\.filter\(',  # ORM filter method
        ],
        "xss": [
            r'DOMPurify\.sanitize',
            r'escape\s*\(',
            r'sanitize\s*\(',
            r'textContent\s*=',
            r'html\.escape\(',
            r'bleach\.clean',
        ],
        "command_injection": [
            r'subprocess\.run\s*\(\s*\[',  # List arguments (safe)
            r'subprocess\.call\s*\(\s*\[',
            r'shell\s*=\s*False',
            r'shlex\.quote',
        ],
        "path_traversal": [
            r'os\.path\.basename\s*\(',
            r'secure_filename\s*\(',
            r'os\.path\.realpath.*?startswith',
        ],
        "deserialization": [
            r'yaml\.safe_load',
            r'json\.loads?',
            r'Loader=yaml\.SafeLoader',
        ],
        "crypto": [
            r'bcrypt\.',
            r'argon2',
            r'sha256|sha384|sha512|sha3',
            r'pbkdf2',
            r'scrypt',
        ],
    }

    # Exclusion patterns for hardcoded credentials (common false positives)
    CREDENTIAL_EXCLUSIONS = [
        r'(example|test|sample|placeholder|xxx+|your[_-]?|dummy|fake)',
        r'os\.environ',
        r'getenv',
        r'config\[',
        r'settings\.',
        r'process\.env',
    ]

    def __init__(self, ai_impact_service=None, ai_impact_enabled: bool = True, use_v2_patterns: bool = True):
        """
        Initialize the scanner

        Args:
            ai_impact_service: Optional AI impact service for dynamic impact generation
            ai_impact_enabled: Whether to use AI for impact generation (default True)
            use_v2_patterns: Whether to use improved V2 patterns (default True)
        """
        self.scanned_files = 0
        self.skipped_files = 0
        self.errors = []
        self.custom_rules = []
        self._load_custom_rules()

        # AI Impact Service configuration
        self.ai_impact_service = ai_impact_service
        self.ai_impact_enabled = ai_impact_enabled
        self.use_v2_patterns = use_v2_patterns

        # Try to load V2 patterns for improved detection
        self._v2_patterns = None
        if use_v2_patterns:
            try:
                from services.sast_patterns_v2 import VULNERABILITY_PATTERNS_V2, SAFE_PATTERNS as V2_SAFE_PATTERNS
                self._v2_patterns = VULNERABILITY_PATTERNS_V2
                self.SAFE_PATTERNS.update(V2_SAFE_PATTERNS)
                logger.info("[SASTScanner] Using V2 patterns for improved detection")
            except ImportError:
                logger.warning("[SASTScanner] V2 patterns not available, using default patterns")

    def scan_code(self, code_content: str, file_path: str = "unknown", language: str = None) -> List[Dict[str, Any]]:
        """
        Scan code content for vulnerabilities

        Args:
            code_content: Source code to scan
            file_path: Path to the source file
            language: Programming language (auto-detected if not provided)

        Returns:
            List of vulnerability findings
        """
        findings = []
        lines = code_content.split('\n')

        if not language:
            language = self._detect_language(file_path)

        # Track unique findings to avoid duplicates
        seen_findings: Set[str] = set()

        for vuln_name, vuln_info in self.VULNERABILITY_PATTERNS.items():
            patterns = vuln_info.get('patterns', [vuln_info.get('pattern')])
            if not patterns:
                continue

            for pattern in patterns:
                if not pattern:
                    continue

                for line_num, line in enumerate(lines, start=1):
                    # Skip comments (basic comment detection)
                    if self._is_comment(line, language):
                        continue

                    try:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            # Create unique key for this finding
                            finding_key = f"{file_path}:{line_num}:{vuln_name}"
                            if finding_key in seen_findings:
                                continue
                            seen_findings.add(finding_key)

                            # Check if match is inside a string literal (potential false positive)
                            if self._is_in_string_literal(line, match.start()):
                                # Still report but with reduced confidence
                                pass

                            # Check if finding should be skipped entirely (very likely false positive)
                            if self._should_skip_finding(vuln_name, line, file_path):
                                continue

                            # Add category prefix for better organization
                            category = self._get_vulnerability_category(vuln_name)
                            formatted_title = f"{category}: {vuln_name}" if category != vuln_name else vuln_name

                            # Calculate confidence based on multiple factors
                            confidence = self._calculate_confidence(
                                vuln_name=vuln_name,
                                line=line,
                                file_path=file_path,
                                base_severity=vuln_info['severity']
                            )

                            # Generate AI-powered impact statement
                            impact_data = self._generate_impact(
                                title=formatted_title,
                                severity=vuln_info['severity'],
                                cwe_id=vuln_info['cwe'],
                                owasp_category=vuln_info['owasp'],
                                file_path=file_path,
                                language=language,
                                code_snippet=line.strip(),
                                fallback_impact=vuln_info.get('impact', ''),
                                fallback_remediation=vuln_info['remediation']
                            )

                            findings.append({
                                "title": formatted_title,
                                "description": vuln_info['description'],
                                "severity": vuln_info['severity'],
                                "cwe_id": vuln_info['cwe'],
                                "owasp_category": vuln_info['owasp'],
                                "file_path": file_path,
                                "line_number": line_num,
                                "code_snippet": line.strip(),
                                "business_impact": impact_data.get('business_impact', ''),
                                "technical_impact": impact_data.get('technical_impact', ''),
                                "recommendations": impact_data.get('recommendations', vuln_info['remediation']),
                                "remediation": vuln_info['remediation'],
                                "remediation_code": vuln_info.get('remediation_code', ''),
                                "cvss_score": self._calculate_cvss(vuln_info['severity']),
                                "stride_category": self._map_to_stride(vuln_name),
                                "mitre_attack_id": self._map_to_mitre(vuln_name),
                                "language": language,
                                "confidence": confidence,
                                "impact_generated_by": impact_data.get('generated_by', 'static')
                            })
                    except re.error as e:
                        self.errors.append(f"Regex error in pattern '{pattern}': {e}")

        # Scan with custom rules (user-defined and AI-generated)
        custom_findings = self._scan_with_custom_rules(code_content, file_path, language, lines)
        findings.extend(custom_findings)

        return findings

    def scan_code_v2(self, code_content: str, file_path: str = "unknown", language: str = None) -> List[Dict[str, Any]]:
        """
        Enhanced scan using V2 patterns with improved precision and reduced false positives.

        Features:
        - Per-pattern confidence scoring
        - Safe pattern exclusion
        - Better false positive reduction
        - Context-aware detection

        Args:
            code_content: Source code to scan
            file_path: Path to the source file
            language: Programming language (auto-detected if not provided)

        Returns:
            List of vulnerability findings with confidence scores
        """
        if not self._v2_patterns:
            logger.info("[SASTScanner] V2 patterns not available, falling back to standard scan")
            return self.scan_code(code_content, file_path, language)

        findings = []
        lines = code_content.split('\n')

        if not language:
            language = self._detect_language(file_path)

        # Track unique findings to avoid duplicates
        seen_findings: Set[str] = set()
        is_test = self._is_test_file(file_path)

        for vuln_name, vuln_info in self._v2_patterns.items():
            patterns = vuln_info.get('patterns', [])
            safe_category = vuln_info.get('safe_patterns')

            for pattern_obj in patterns:
                # V2 patterns are dicts with regex, confidence, description
                if isinstance(pattern_obj, dict):
                    pattern = pattern_obj.get('regex')
                    base_confidence = pattern_obj.get('confidence', 'medium')
                    pattern_desc = pattern_obj.get('description', '')
                else:
                    # Fallback for simple string patterns
                    pattern = pattern_obj
                    base_confidence = 'medium'
                    pattern_desc = ''

                if not pattern:
                    continue

                for line_num, line in enumerate(lines, start=1):
                    # Skip comments
                    if self._is_comment(line, language):
                        continue

                    try:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            finding_key = f"{file_path}:{line_num}:{vuln_name}"
                            if finding_key in seen_findings:
                                continue
                            seen_findings.add(finding_key)

                            # Check if finding should be skipped
                            if self._should_skip_finding(vuln_name, line, file_path):
                                continue

                            # Check for safe patterns (reduces confidence significantly)
                            has_safe_pattern = False
                            if safe_category:
                                has_safe_pattern = self._has_safe_pattern(line, vuln_name)

                            # Calculate adjusted confidence
                            confidence_levels = ['low', 'medium', 'high', 'critical']
                            conf_idx = confidence_levels.index(base_confidence) if base_confidence in confidence_levels else 1

                            if has_safe_pattern:
                                conf_idx = max(0, conf_idx - 2)
                            if is_test:
                                conf_idx = max(0, conf_idx - 1)
                            if self._is_in_string_literal(line, match.start()):
                                conf_idx = max(0, conf_idx - 1)

                            final_confidence = confidence_levels[conf_idx]

                            # Skip very low confidence findings in V2 mode
                            if final_confidence == 'low' and has_safe_pattern:
                                continue

                            category = self._get_vulnerability_category(vuln_name)
                            formatted_title = f"{category}: {vuln_name}" if category != vuln_name else vuln_name

                            # Generate impact
                            impact_data = self._generate_impact(
                                title=formatted_title,
                                severity=vuln_info['severity'],
                                cwe_id=vuln_info['cwe'],
                                owasp_category=vuln_info['owasp'],
                                file_path=file_path,
                                language=language,
                                code_snippet=line.strip(),
                                fallback_impact=vuln_info.get('impact', ''),
                                fallback_remediation=vuln_info.get('remediation', '')
                            )

                            findings.append({
                                "title": formatted_title,
                                "description": vuln_info['description'],
                                "severity": vuln_info['severity'],
                                "cwe_id": vuln_info['cwe'],
                                "owasp_category": vuln_info['owasp'],
                                "file_path": file_path,
                                "line_number": line_num,
                                "code_snippet": line.strip(),
                                "business_impact": impact_data.get('business_impact', ''),
                                "technical_impact": impact_data.get('technical_impact', ''),
                                "recommendations": impact_data.get('recommendations', vuln_info.get('remediation', '')),
                                "remediation": vuln_info.get('remediation', ''),
                                "remediation_code": vuln_info.get('remediation_code', ''),
                                "cvss_score": self._calculate_cvss(vuln_info['severity']),
                                "stride_category": self._map_to_stride(vuln_name),
                                "mitre_attack_id": self._map_to_mitre(vuln_name),
                                "language": language,
                                "confidence": final_confidence,
                                "pattern_description": pattern_desc,
                                "has_safe_pattern": has_safe_pattern,
                                "impact_generated_by": impact_data.get('generated_by', 'static'),
                                "scanner_version": "v2"
                            })
                    except re.error as e:
                        self.errors.append(f"V2 Regex error in pattern '{pattern}': {e}")

        # Also scan with custom rules
        custom_findings = self._scan_with_custom_rules(code_content, file_path, language, lines)
        findings.extend(custom_findings)

        return findings

    def _generate_impact(
        self,
        title: str,
        severity: str,
        cwe_id: str,
        owasp_category: str,
        file_path: str,
        language: str,
        code_snippet: str,
        fallback_impact: str,
        fallback_remediation: str
    ) -> Dict[str, str]:
        """
        Generate AI-powered impact statement for a SAST finding.

        Args:
            title: Vulnerability title
            severity: Severity level
            cwe_id: CWE identifier
            owasp_category: OWASP category
            file_path: Path to the affected file
            language: Programming language
            code_snippet: Affected code snippet
            fallback_impact: Fallback impact text
            fallback_remediation: Fallback remediation text

        Returns:
            Dictionary with 'impact', 'recommendations', and 'generated_by' keys
        """
        # If AI is enabled and service is available, use it
        if self.ai_impact_enabled and self.ai_impact_service:
            try:
                vuln_info = {
                    "title": title,
                    "severity": severity,
                    "cwe_id": cwe_id,
                    "owasp_category": owasp_category,
                    "file_path": file_path,
                    "language": language,
                    "code_snippet": code_snippet[:300] if code_snippet else ""  # Truncate for API limits
                }

                ai_result = self.ai_impact_service.generate_impact_statement(
                    finding_type="sast",
                    vulnerability_info=vuln_info,
                    fallback_impact=fallback_impact,
                    fallback_recommendations=fallback_remediation
                )

                return {
                    "business_impact": ai_result.get('business_impact', 'Impact assessment unavailable'),
                    "technical_impact": ai_result.get('technical_impact', 'Technical impact unavailable'),
                    "recommendations": ai_result.get('recommendations', fallback_remediation),
                    "generated_by": ai_result.get('generated_by', 'ai')
                }

            except Exception as e:
                logger.warning(f"[SASTScanner] AI impact generation failed: {e}")
                # Fall through to static fallback

        # Return static fallback - parse business/technical impact if formatted
        business_impact = fallback_impact
        technical_impact = ""

        if fallback_impact and "**Technical Impact:**" in fallback_impact:
            parts = fallback_impact.split("**Technical Impact:**")
            business_impact = parts[0].replace("**Business Impact:**", "").strip()
            technical_impact = parts[1].strip() if len(parts) > 1 else ""

        return {
            "business_impact": business_impact,
            "technical_impact": technical_impact,
            "recommendations": fallback_remediation,
            "generated_by": "static"
        }

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext = os.path.splitext(file_path)[1].lower()
        for language, extensions in self.LANGUAGE_EXTENSIONS.items():
            if ext in extensions:
                return language
        return "unknown"

    def _is_comment(self, line: str, language: str) -> bool:
        """Check if line is a comment (basic detection)"""
        stripped = line.strip()
        if not stripped:
            return False

        comment_markers = {
            'python': ['#'],
            'javascript': ['//', '/*', '*'],
            'typescript': ['//', '/*', '*'],
            'java': ['//', '/*', '*'],
            'php': ['//', '#', '/*', '*'],
            'ruby': ['#'],
            'go': ['//', '/*', '*'],
            'csharp': ['//', '/*', '*'],
            'c_cpp': ['//', '/*', '*'],
            'kotlin': ['//', '/*', '*'],
            'swift': ['//', '/*', '*'],
            'rust': ['//', '/*', '*'],
            'scala': ['//', '/*', '*'],
            'shell': ['#'],
        }

        markers = comment_markers.get(language, [])
        return any(stripped.startswith(marker) for marker in markers)

    def _is_in_string_literal(self, line: str, match_pos: int) -> bool:
        """Check if a match position is inside a string literal (potential false positive)."""
        if match_pos <= 0:
            return False

        # Count quotes before the match position
        prefix = line[:match_pos]
        single_quotes = prefix.count("'") - prefix.count("\\'")
        double_quotes = prefix.count('"') - prefix.count('\\"')

        # If odd number of quotes, we're inside a string
        return (single_quotes % 2 == 1) or (double_quotes % 2 == 1)

    def _has_safe_pattern(self, line: str, vuln_type: str) -> bool:
        """Check if line contains patterns that indicate safe usage."""
        # Map vulnerability names to safe pattern categories
        vuln_to_category = {
            "SQL Injection": "sql_injection",
            "XSS (Cross-Site Scripting)": "xss",
            "Command Injection": "command_injection",
            "Path Traversal": "path_traversal",
            "Insecure Deserialization": "deserialization",
            "Weak Cryptography": "crypto",
            "Weak Password Storage": "crypto",
        }

        category = vuln_to_category.get(vuln_type)
        if not category:
            return False

        safe_patterns = self.SAFE_PATTERNS.get(category, [])
        for pattern in safe_patterns:
            try:
                if re.search(pattern, line, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file (reduce confidence for test files)."""
        test_indicators = [
            'test_', '_test.', '.test.', 'tests/', '/test/',
            'spec_', '_spec.', '.spec.', 'specs/', '/spec/',
            '__tests__', 'mock_', '_mock.', '/mocks/',
            'fixture', 'conftest', 'pytest'
        ]
        lower_path = file_path.lower()
        return any(ind in lower_path for ind in test_indicators)

    def _calculate_confidence(self, vuln_name: str, line: str, file_path: str, base_severity: str) -> str:
        """
        Calculate finding confidence based on multiple factors.
        Returns: 'high', 'medium', or 'low'
        """
        # Start with base confidence from severity
        if base_severity == 'critical':
            confidence_score = 3  # high
        elif base_severity == 'high':
            confidence_score = 2  # medium
        else:
            confidence_score = 1  # low

        # Reduce confidence if safe patterns detected
        if self._has_safe_pattern(line, vuln_name):
            confidence_score -= 2

        # Reduce confidence for test files
        if self._is_test_file(file_path):
            confidence_score -= 1

        # Check for hardcoded credential false positives
        if vuln_name == "Hardcoded Credentials":
            for exclusion in self.CREDENTIAL_EXCLUSIONS:
                if re.search(exclusion, line, re.IGNORECASE):
                    confidence_score -= 2
                    break

        # Map score to confidence level
        if confidence_score >= 3:
            return "high"
        elif confidence_score >= 1:
            return "medium"
        else:
            return "low"

    def _should_skip_finding(self, vuln_name: str, line: str, file_path: str) -> bool:
        """
        Determine if a finding should be skipped entirely (very likely false positive).
        Returns True to skip the finding.
        """
        # Skip if line is likely documentation/example
        doc_indicators = [
            r'^["\'].*?(example|documentation|usage|sample).*?["\']$',
            r'^#.*?(example|todo|note|fixme)',
            r'^//.*?(example|todo|note)',
            r'""".*?"""',
            r"'''.*?'''",
        ]

        stripped = line.strip().lower()
        for pattern in doc_indicators:
            try:
                if re.search(pattern, stripped, re.IGNORECASE):
                    return True
            except re.error:
                continue

        # Skip hardcoded credentials if they look like placeholders
        if vuln_name == "Hardcoded Credentials":
            placeholder_patterns = [
                r'["\']<.*?>["\']',  # <your_password>
                r'["\']xxx+["\']',  # "xxx" or "xxxxxxxx"
                r'["\']your[_-]?\w+["\']',  # "your_password"
                r'["\']changeme["\']',
                r'["\']placeholder["\']',
            ]
            for pattern in placeholder_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return True

        return False

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        cvss_map = {
            "critical": 9.5,
            "high": 7.8,
            "medium": 5.5,
            "low": 3.2,
            "info": 0.0
        }
        return cvss_map.get(severity.lower(), 5.0)

    def _get_vulnerability_category(self, vuln_name: str) -> str:
        """Get high-level category for vulnerability"""
        category_mapping = {
            # Injection vulnerabilities
            "SQL Injection": "Injection",
            "NoSQL Injection": "Injection",
            "Command Injection": "Injection",
            "LDAP Injection": "Injection",
            "XML Injection": "Injection",
            "XSS (Cross-Site Scripting)": "Injection",
            "Server-Side Template Injection (SSTI)": "Injection",
            "Expression Language Injection": "Injection",

            # Authentication & Access Control
            "Hardcoded Credentials": "Authentication",
            "Weak Password Storage": "Authentication",
            "Insecure JWT": "Authentication",
            "Broken Authentication": "Authentication",
            "Broken Access Control": "Access Control",
            "Insufficient Authorization": "Access Control",
            "Missing Authentication": "Authentication",

            # Cryptography
            "Weak Cryptography": "Cryptography",
            "Hardcoded Cryptographic Key": "Cryptography",
            "Insecure Random": "Cryptography",
            "SSL/TLS Verification Disabled": "Cryptography",
            "Weak Hash Algorithm": "Cryptography",

            # File Operations
            "Path Traversal": "File Security",
            "Unrestricted File Upload": "File Security",
            "Arbitrary File Write": "File Security",
            "Local File Inclusion (LFI)": "File Security",
            "Remote File Inclusion (RFI)": "File Security",

            # Data Handling
            "Insecure Deserialization": "Data Handling",
            "Mass Assignment": "Data Handling",
            "Insufficient Input Validation": "Data Handling",
            "XML External Entity (XXE)": "Data Handling",
            "Insecure Data Storage": "Data Handling",

            # Configuration
            "Debug Mode Enabled": "Configuration",
            "CORS Misconfiguration": "Configuration",
            "Security Misconfiguration": "Configuration",
            "Missing Security Headers": "Configuration",

            # Information Disclosure
            "Information Disclosure": "Information Disclosure",
            "Sensitive Data in URL": "Information Disclosure",
            "Sensitive Data Exposure": "Information Disclosure",
            "Stack Trace Disclosure": "Information Disclosure",

            # Denial of Service
            "Regular Expression DoS (ReDoS)": "Denial of Service",
            "Missing Rate Limiting": "Denial of Service",
            "Resource Exhaustion": "Denial of Service",

            # Other
            "Time-of-Check Time-of-Use (TOCTOU)": "Race Condition",
            "Use After Free": "Memory Safety",
            "Buffer Overflow": "Memory Safety",
            "Null Pointer Dereference": "Memory Safety",
        }
        return category_mapping.get(vuln_name, vuln_name)

    def _map_to_stride(self, vuln_name: str) -> str:
        """Map vulnerability to STRIDE threat category"""
        stride_mapping = {
            "SQL Injection": "Tampering",
            "NoSQL Injection": "Tampering",
            "XSS (Cross-Site Scripting)": "Tampering",
            "Command Injection": "Elevation of Privilege",
            "LDAP Injection": "Tampering",
            "XML Injection": "Tampering",
            "Hardcoded Credentials": "Information Disclosure",
            "Weak Password Storage": "Information Disclosure",
            "Insecure JWT": "Spoofing",
            "Insecure Deserialization": "Elevation of Privilege",
            "Path Traversal": "Information Disclosure",
            "Unrestricted File Upload": "Elevation of Privilege",
            "Weak Cryptography": "Information Disclosure",
            "Hardcoded Cryptographic Key": "Information Disclosure",
            "Insecure Random": "Information Disclosure",
            "Insufficient Input Validation": "Tampering",
            "Mass Assignment": "Tampering",
            "Debug Mode Enabled": "Information Disclosure",
            "CORS Misconfiguration": "Information Disclosure",
            "SSL/TLS Verification Disabled": "Information Disclosure",
            "Broken Access Control": "Elevation of Privilege",
            "Information Disclosure": "Information Disclosure",
            "Time-of-Check Time-of-Use (TOCTOU)": "Tampering",
            "Insecure Data Storage": "Information Disclosure",
            "Missing Rate Limiting": "Denial of Service",
            "Sensitive Data in URL": "Information Disclosure",
            "Regular Expression DoS (ReDoS)": "Denial of Service",
        }
        return stride_mapping.get(vuln_name, "Unknown")

    def _map_to_mitre(self, vuln_name: str) -> str:
        """Map vulnerability to MITRE ATT&CK technique"""
        mitre_mapping = {
            "SQL Injection": "T1190",  # Exploit Public-Facing Application
            "NoSQL Injection": "T1190",
            "XSS (Cross-Site Scripting)": "T1189",  # Drive-by Compromise
            "Command Injection": "T1059",  # Command and Scripting Interpreter
            "LDAP Injection": "T1190",
            "XML Injection": "T1190",
            "Hardcoded Credentials": "T1552.001",  # Unsecured Credentials: Credentials In Files
            "Weak Password Storage": "T1552",
            "Insecure JWT": "T1550",  # Use Alternate Authentication Material
            "Insecure Deserialization": "T1203",  # Exploitation for Client Execution
            "Path Traversal": "T1083",  # File and Directory Discovery
            "Unrestricted File Upload": "T1105",  # Ingress Tool Transfer
            "Weak Cryptography": "T1557",  # Man-in-the-Middle
            "Hardcoded Cryptographic Key": "T1552",
            "Insecure Random": "T1552",
            "Insufficient Input Validation": "T1190",
            "Mass Assignment": "T1190",
            "Debug Mode Enabled": "T1592",  # Gather Victim Host Information
            "CORS Misconfiguration": "T1190",
            "SSL/TLS Verification Disabled": "T1557",
            "Broken Access Control": "T1548",  # Abuse Elevation Control Mechanism
            "Information Disclosure": "T1592",
            "Time-of-Check Time-of-Use (TOCTOU)": "T1083",
            "Insecure Data Storage": "T1005",  # Data from Local System
            "Missing Rate Limiting": "T1499",  # Endpoint Denial of Service
            "Sensitive Data in URL": "T1552",
            "Regular Expression DoS (ReDoS)": "T1499",
        }
        return mitre_mapping.get(vuln_name, "T1190")

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file for vulnerabilities

        Args:
            file_path: Path to file to scan

        Returns:
            Dictionary containing scan results
        """
        import os

        if not os.path.exists(file_path):
            return {'findings': [], 'error': 'File not found'}

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

            findings = self.scan_code(code_content, file_path)

            return {
                'findings': findings,
                'file_path': file_path,
                'total_findings': len(findings)
            }
        except Exception as e:
            return {'findings': [], 'error': str(e)}

    def scan_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        Scan entire directory for vulnerabilities

        Args:
            directory_path: Path to directory to scan

        Returns:
            Dictionary containing scan results and statistics
        """
        all_findings = []
        self.scanned_files = 0
        self.skipped_files = 0
        self.errors = []

        # Get all supported extensions
        supported_extensions = []
        for exts in self.LANGUAGE_EXTENSIONS.values():
            supported_extensions.extend(exts)
        supported_extensions = list(set(supported_extensions))

        # Walk directory tree
        for root, dirs, files in os.walk(directory_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['node_modules', 'venv', '.git', '__pycache__', 'dist', 'build']]

            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in supported_extensions:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # Skip very large files (>1MB)
                            if len(content) > 1024 * 1024:
                                self.skipped_files += 1
                                continue

                            findings = self.scan_code(content, file_path)
                            all_findings.extend(findings)
                            self.scanned_files += 1
                    except Exception as e:
                        self.errors.append(f"Error scanning {file_path}: {str(e)}")
                        self.skipped_files += 1

        # Aggregate results
        severity_counts = {
            "critical": len([f for f in all_findings if f['severity'] == 'critical']),
            "high": len([f for f in all_findings if f['severity'] == 'high']),
            "medium": len([f for f in all_findings if f['severity'] == 'medium']),
            "low": len([f for f in all_findings if f['severity'] == 'low']),
            "info": len([f for f in all_findings if f['severity'] == 'info'])
        }

        # Count by language
        language_counts = {}
        for finding in all_findings:
            lang = finding.get('language', 'unknown')
            language_counts[lang] = language_counts.get(lang, 0) + 1

        return {
            "total_findings": len(all_findings),
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "errors": len(self.errors),
            "severity_counts": severity_counts,
            "language_counts": language_counts,
            "findings": all_findings,
            "scan_errors": self.errors
        }

    def generate_sample_findings(self) -> List[Dict[str, Any]]:
        """Generate realistic sample findings for demo purposes"""
        sample_code_snippets = [
            {
                "code": "query = \"SELECT * FROM users WHERE id = \" + user_id",
                "file": "app/models/user.py",
                "line": 45,
                "language": "python"
            },
            {
                "code": "element.innerHTML = userInput;",
                "file": "frontend/src/components/Dashboard.tsx",
                "line": 127,
                "language": "typescript"
            },
            {
                "code": "password = \"admin123\"",
                "file": "config/database.py",
                "line": 12,
                "language": "python"
            },
            {
                "code": "data = pickle.loads(request.body)",
                "file": "api/serializers.py",
                "line": 89,
                "language": "python"
            },
            {
                "code": "hashlib.md5(password.encode())",
                "file": "auth/utils.py",
                "line": 67,
                "language": "python"
            },
            {
                "code": "subprocess.call('ping ' + user_input, shell=True)",
                "file": "api/network.py",
                "line": 34,
                "language": "python"
            },
            {
                "code": "const token = jwt.encode(payload, '', algorithm='none')",
                "file": "auth/jwt_handler.js",
                "line": 22,
                "language": "javascript"
            },
        ]

        findings = []
        for snippet in sample_code_snippets:
            results = self.scan_code(snippet['code'], snippet['file'], snippet.get('language'))
            for result in results:
                result['line_number'] = snippet['line']
                findings.append(result)

        return findings

    def _load_custom_rules(self):
        """Load enabled custom rules from database"""
        import sqlite3
        from utils.db_path import get_db_path
        try:
            conn = sqlite3.connect(get_db_path())
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, name, pattern, severity, description, language, cwe, owasp, remediation, remediation_code
                FROM custom_rules
                WHERE enabled = 1
            ''')

            self.custom_rules = [dict(row) for row in cursor.fetchall()]
            conn.close()
        except Exception as e:
            print(f"Warning: Could not load custom rules: {e}")
            self.custom_rules = []

    def reload_custom_rules(self):
        """Reload custom rules from database (call after rule updates)"""
        self._load_custom_rules()

    def _scan_with_custom_rules(self, code_content: str, file_path: str, language: str, lines: List[str]) -> List[Dict[str, Any]]:
        """
        Scan code with custom user-defined and AI-generated rules

        Args:
            code_content: Full code content
            file_path: Path to the file
            language: Detected programming language
            lines: Lines of code

        Returns:
            List of findings from custom rules
        """
        findings = []
        seen_findings: Set[str] = set()

        for rule in self.custom_rules:
            # Check if rule applies to this language
            rule_language = rule.get('language', '*')
            if rule_language != '*' and rule_language.lower() != language.lower():
                continue

            pattern_str = rule['pattern']

            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)

                for line_num, line in enumerate(lines, start=1):
                    # Skip comments
                    if self._is_comment(line, language):
                        continue

                    match = pattern.search(line)
                    if match:
                        # Create unique key to avoid duplicates
                        finding_key = f"{file_path}:{line_num}:{rule['name']}"
                        if finding_key in seen_findings:
                            continue

                        seen_findings.add(finding_key)

                        # Extract code snippet (±2 lines context)
                        start_line = max(0, line_num - 3)
                        end_line = min(len(lines), line_num + 2)
                        code_snippet = '\n'.join(lines[start_line:end_line])

                        findings.append({
                            "title": rule['name'],
                            "category": rule.get('owasp', 'Custom Rule'),
                            "severity": rule['severity'],
                            "confidence": "medium",
                            "file_path": file_path,
                            "line_number": line_num,
                            "column": match.start() + 1,
                            "code_snippet": code_snippet,
                            "vulnerable_code": line.strip(),
                            "description": rule['description'],
                            "impact": f"This {rule['severity']} severity vulnerability was detected by custom rule: {rule['name']}",
                            "remediation": rule.get('remediation', 'Review and fix this security issue'),
                            "remediation_code": rule.get('remediation_code'),
                            "cwe_id": rule.get('cwe'),
                            "owasp_category": rule.get('owasp'),
                            "rule_id": rule['id'],  # Track which rule found this
                            "rule_source": rule.get('generated_by', 'user'),  # 'ai', 'user', 'cve'
                        })

            except re.error as e:
                print(f"Warning: Invalid regex pattern in custom rule '{rule['name']}': {e}")
                continue

        return findings
