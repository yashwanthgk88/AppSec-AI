"""
SAST Scanner Patterns V2 - Improved patterns with better precision and reduced false positives.

Key improvements:
1. Consolidated duplicate rules (CWE-20, CWE-347, CWE-489, CWE-942)
2. Context-aware patterns that reduce false positives
3. Confidence scoring based on pattern precision (not just severity)
4. Safe pattern detection to exclude sanitized/validated code
5. Better language-specific patterns
"""

from typing import Dict, List, Any, Optional
import re


# =============================================================================
# SAFE PATTERNS - Used to exclude false positives
# =============================================================================

SAFE_PATTERNS = {
    "sql_injection": [
        r'\.execute\s*\([^,]+,\s*[\(\[]',  # Parameterized query with tuple/list
        r'\.execute\s*\([^,]+,\s*\{',  # Named parameters
        r'text\s*\([^)]+\)\.bindparams',  # SQLAlchemy text with bindparams
        r'session\.query\(',  # SQLAlchemy ORM
        r'Model\.objects\.',  # Django ORM
        r'\.filter\(',  # ORM filter method
        r'\.where\(\w+\s*==',  # SQLAlchemy where with comparison
    ],
    "xss": [
        r'DOMPurify\.sanitize',  # DOMPurify sanitization
        r'escape\s*\(',  # escape function
        r'sanitize\s*\(',  # sanitize function
        r'textContent\s*=',  # Safe textContent assignment
        r'createTextNode\s*\(',  # Safe text node creation
        r'\{\s*\w+\s*\}',  # React auto-escaped JSX
        r'html\.escape\(',  # Python html.escape
        r'markupsafe\.escape',  # MarkupSafe
        r'bleach\.clean',  # Bleach sanitizer
    ],
    "command_injection": [
        r'subprocess\.run\s*\(\s*\[',  # List arguments (safe)
        r'subprocess\.call\s*\(\s*\[',  # List arguments (safe)
        r'execFile\s*\(',  # Node execFile (safe)
        r'shell\s*=\s*False',  # Explicit shell=False
        r'shlex\.quote',  # Shell quoting
        r'shlex\.split',  # Shell argument splitting
    ],
    "path_traversal": [
        r'os\.path\.basename\s*\(',  # Basename strips path
        r'secure_filename\s*\(',  # Werkzeug secure_filename
        r'os\.path\.realpath.*?startswith',  # Path validation
        r'\.resolve\(\).*?is_relative_to',  # Pathlib validation
        r'path\.normalize',  # Node path normalize
    ],
    "deserialization": [
        r'yaml\.safe_load',  # Safe YAML loading
        r'json\.loads?',  # JSON is safe
        r'Loader=yaml\.SafeLoader',  # Explicit safe loader
    ],
    "crypto": [
        r'bcrypt\.',  # bcrypt is safe
        r'argon2',  # Argon2 is safe
        r'sha256|sha384|sha512|sha3',  # Strong hashes
        r'AES|ChaCha|Salsa',  # Strong ciphers
        r'pbkdf2',  # Key derivation
        r'scrypt',  # Memory-hard KDF
    ],
}


# =============================================================================
# COMMENT AND STRING DETECTION
# =============================================================================

def is_in_comment_or_string(line: str, language: str, position: int = 0) -> bool:
    """
    Enhanced detection of whether a position in a line is within a comment or string.
    Returns True if the position is in a comment or string literal (should skip).
    """
    stripped = line.strip()

    # Full-line comments
    comment_starts = {
        'python': ['#'],
        'javascript': ['//', '/*'],
        'typescript': ['//', '/*'],
        'java': ['//', '/*'],
        'php': ['//', '#', '/*'],
        'ruby': ['#'],
        'go': ['//', '/*'],
        'csharp': ['//', '/*'],
        'c_cpp': ['//', '/*'],
        'kotlin': ['//', '/*'],
        'swift': ['//', '/*'],
        'rust': ['//', '/*'],
        'scala': ['//', '/*'],
        'shell': ['#'],
    }

    markers = comment_starts.get(language, ['#', '//'])

    # Check if line starts with comment marker
    for marker in markers:
        if stripped.startswith(marker):
            return True

    # Check for inline comments (everything after // or # is a comment)
    # This is a simplified check - real implementation would track quote state
    line_before_position = line[:position] if position > 0 else line

    # Track string state
    in_single_quote = False
    in_double_quote = False

    for i, char in enumerate(line_before_position):
        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
        elif char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
        elif not in_single_quote and not in_double_quote:
            # Check for comment markers
            remainder = line[i:]
            if language in ['python', 'ruby', 'shell', 'php']:
                if remainder.startswith('#') and i < position:
                    return True
            if language in ['javascript', 'typescript', 'java', 'csharp', 'go', 'kotlin', 'swift', 'rust', 'scala', 'c_cpp', 'php']:
                if remainder.startswith('//') and i < position:
                    return True

    return False


def check_safe_patterns(line: str, vuln_type: str) -> bool:
    """
    Check if the line contains patterns that indicate safe usage.
    Returns True if the code appears to be safe (should reduce confidence or skip).
    """
    safe_patterns = SAFE_PATTERNS.get(vuln_type, [])
    for pattern in safe_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False


# =============================================================================
# IMPROVED VULNERABILITY PATTERNS
# =============================================================================

VULNERABILITY_PATTERNS_V2 = {
    # ==================== INJECTION VULNERABILITIES ====================
    "SQL Injection": {
        "patterns": [
            # High confidence - F-string with SQL keywords
            {
                "regex": r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE).*?FROM\s+\w+.*?\{',
                "confidence": "high",
                "description": "F-string SQL query with variable interpolation"
            },
            {
                "regex": r'f["\'].*?WHERE\s+\w+\s*=\s*\{',
                "confidence": "high",
                "description": "F-string SQL WHERE clause with variable"
            },
            # High confidence - String concatenation in execute
            {
                "regex": r'\.execute\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']?\s*\+',
                "confidence": "high",
                "description": "String concatenation in SQL execute"
            },
            # Medium confidence - format() with SQL
            {
                "regex": r'["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']\.format\s*\(',
                "confidence": "medium",
                "description": "String format with SQL query"
            },
            # Medium confidence - % formatting
            {
                "regex": r'["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?%s.*?["\'].*?%\s*\(',
                "confidence": "medium",
                "description": "Percent formatting with SQL query"
            },
            # Template literal SQL (JavaScript)
            {
                "regex": r'`.*?(SELECT|INSERT|UPDATE|DELETE).*?FROM.*?\$\{',
                "confidence": "high",
                "description": "Template literal SQL injection"
            },
            # Raw queries with variables (Python ORMs)
            {
                "regex": r'\.raw\s*\(\s*f["\']',
                "confidence": "high",
                "description": "Raw query with f-string"
            },
            # createQuery with concatenation (Java JPA)
            {
                "regex": r'createQuery\s*\(\s*["\'][^"\']*["\']?\s*\+',
                "confidence": "high",
                "description": "JPA createQuery with concatenation"
            },
        ],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "severity": "critical",
        "safe_patterns": "sql_injection",
        "description": "SQL query constructed using string concatenation or formatting with user input. Attackers can modify the query to access or modify unauthorized data.",
        "impact": """**Business Impact:**
- Complete database compromise enabling unauthorized access to all stored data
- Data breach exposing PII, financial records, and credentials
- Regulatory violations (GDPR, PCI-DSS, HIPAA) with fines up to 4% annual revenue
- Reputational damage and loss of customer trust

**Technical Impact:**
- Authentication bypass allowing login as any user including administrators
- Data exfiltration of entire database contents
- Data modification enabling privilege escalation and persistent backdoors
- Server compromise through database features (xp_cmdshell, INTO OUTFILE)""",
        "remediation": """**Immediate Actions:**
1. Use parameterized queries (prepared statements) for ALL database operations
2. Use ORM methods instead of raw SQL queries
3. Implement input validation with allowlists for expected formats

**Long-term Remediation:**
1. Adopt an ORM framework (SQLAlchemy, Django ORM, Hibernate)
2. Enable SQL query logging for anomaly detection
3. Apply principle of least privilege for database accounts""",
        "remediation_code": """# VULNERABLE
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# SECURE - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# SECURE - SQLAlchemy ORM
user = session.query(User).filter(User.id == user_id).first()

// Java - SECURE
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);"""
    },

    "NoSQL Injection": {
        "patterns": [
            {
                "regex": r'(find|findOne|aggregate)\s*\(\s*\{[^}]*\$\w+',
                "confidence": "high",
                "description": "NoSQL query with MongoDB operator from user input"
            },
            {
                "regex": r'\$where\s*:\s*["\'].*?\+',
                "confidence": "critical",
                "description": "$where operator with string concatenation"
            },
            {
                "regex": r'ObjectId\s*\(\s*(req\.|request\.|params\.)',
                "confidence": "high",
                "description": "ObjectId created from request parameter"
            },
            {
                "regex": r'\.find\s*\(\s*JSON\.parse\s*\(',
                "confidence": "high",
                "description": "JSON.parse in find query"
            },
        ],
        "cwe": "CWE-943",
        "owasp": "A03:2021 - Injection",
        "severity": "high",
        "description": "NoSQL query constructed with unsanitized user input, allowing injection of query operators.",
        "impact": """**Business Impact:**
- Unauthorized access to database bypassing authentication
- Data exfiltration of sensitive documents
- Authentication bypass using operator injection

**Technical Impact:**
- Query manipulation using $ne, $gt, $regex operators
- Server-side JavaScript execution via $where operator
- Database enumeration through error messages""",
        "remediation": """1. Validate and sanitize all user inputs before queries
2. Cast expected data types explicitly (String, Number, ObjectId)
3. Disable $where operator in production
4. Use ODM libraries (Mongoose) with schema validation""",
        "remediation_code": """// VULNERABLE
db.users.find({ name: req.query.name })

// SECURE - Type validation
const name = String(req.query.name).substring(0, 100);
db.users.find({ name })

// SECURE - Mongoose with validation
User.findOne({ name: validator.escape(req.query.name) });"""
    },

    "XSS (Cross-Site Scripting)": {
        "patterns": [
            # High confidence - Direct innerHTML/outerHTML assignment with variable
            {
                "regex": r'\.innerHTML\s*=\s*\w+(?!\s*;)',
                "confidence": "high",
                "description": "innerHTML assignment with variable"
            },
            {
                "regex": r'\.innerHTML\s*=\s*["\'].*?\$\{',
                "confidence": "high",
                "description": "innerHTML with template literal"
            },
            {
                "regex": r'\.innerHTML\s*=.*?\+',
                "confidence": "high",
                "description": "innerHTML with string concatenation"
            },
            # document.write
            {
                "regex": r'document\.write\s*\(\s*[^)]*(\+|\$\{)',
                "confidence": "high",
                "description": "document.write with dynamic content"
            },
            # jQuery html()
            {
                "regex": r'\.html\s*\(\s*\w+\s*\)(?!\s*;.*?(sanitize|escape|DOMPurify))',
                "confidence": "medium",
                "description": "jQuery .html() with variable"
            },
            # React dangerouslySetInnerHTML
            {
                "regex": r'dangerouslySetInnerHTML\s*=\s*\{\{.*?__html\s*:',
                "confidence": "medium",
                "description": "React dangerouslySetInnerHTML"
            },
            # eval/Function with request
            {
                "regex": r'(eval|Function)\s*\(\s*(req\.|request\.|params\.|query\.)',
                "confidence": "critical",
                "description": "eval/Function with user input"
            },
            # PHP echo without escaping
            {
                "regex": r'echo\s+\$_(GET|POST|REQUEST)\[',
                "confidence": "high",
                "description": "PHP echo with superglobal"
            },
            # Server-side template injection
            {
                "regex": r'render_template_string\s*\([^)]*(\+|\{)',
                "confidence": "critical",
                "description": "Flask render_template_string with dynamic content"
            },
        ],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "severity": "high",
        "safe_patterns": "xss",
        "description": "User input rendered in HTML without proper encoding, allowing script injection.",
        "impact": """**Business Impact:**
- Session hijacking enabling account takeover
- Credential theft through fake login forms
- Malware distribution to application users

**Technical Impact:**
- JavaScript execution in user's browser context
- Cookie theft bypassing HttpOnly flag via DOM access
- Keylogging and form data interception""",
        "remediation": """**Immediate Actions:**
1. Use textContent instead of innerHTML for text
2. Implement Content Security Policy (CSP) headers
3. Use DOMPurify or similar library for HTML sanitization

**Long-term Remediation:**
1. Use frameworks with auto-escaping (React, Vue, Angular)
2. Set HttpOnly and Secure flags on session cookies""",
        "remediation_code": """// VULNERABLE
element.innerHTML = userInput;

// SECURE - Use textContent
element.textContent = userInput;

// SECURE - Sanitize HTML
element.innerHTML = DOMPurify.sanitize(userInput);

// React - SECURE (auto-escaped)
<div>{userInput}</div>"""
    },

    "Command Injection": {
        "patterns": [
            # Python subprocess with shell=True and dynamic input
            {
                "regex": r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*(\+|f["\']|\{)',
                "confidence": "critical",
                "description": "subprocess with shell=True and dynamic input"
            },
            {
                "regex": r'subprocess\.(call|run|Popen)\s*\(\s*f["\'].*?shell\s*=\s*True',
                "confidence": "critical",
                "description": "subprocess f-string with shell=True"
            },
            # os.system with dynamic input
            {
                "regex": r'os\.system\s*\(\s*f["\']',
                "confidence": "critical",
                "description": "os.system with f-string"
            },
            {
                "regex": r'os\.system\s*\([^)]*\+',
                "confidence": "critical",
                "description": "os.system with concatenation"
            },
            # os.popen
            {
                "regex": r'os\.popen\s*\([^)]*(\+|f["\'])',
                "confidence": "critical",
                "description": "os.popen with dynamic input"
            },
            # PHP exec functions
            {
                "regex": r'(exec|system|passthru|shell_exec|popen)\s*\([^)]*\$',
                "confidence": "critical",
                "description": "PHP command execution with variable"
            },
            # Node.js child_process exec
            {
                "regex": r'exec\s*\([^)]*(\+|`\$\{)',
                "confidence": "high",
                "description": "Node exec with dynamic input"
            },
            # Java Runtime.exec with concatenation
            {
                "regex": r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',
                "confidence": "critical",
                "description": "Java Runtime.exec with concatenation"
            },
        ],
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "severity": "critical",
        "safe_patterns": "command_injection",
        "description": "System command executed with user-controlled input, allowing arbitrary command execution.",
        "impact": """**Business Impact:**
- Complete server compromise with potential lateral movement
- Data breach affecting all accessible data
- Ransomware deployment and business disruption

**Technical Impact:**
- Remote Code Execution with application privileges
- File system access for data theft or destruction
- Installation of persistent backdoors""",
        "remediation": """**Immediate Actions:**
1. NEVER use shell=True with user input
2. Use argument lists instead of string commands
3. Implement strict allowlist validation for inputs

**Long-term Remediation:**
1. Use language-native libraries instead of shell commands
2. Run services with minimal privileges
3. Implement sandbox environments for command execution""",
        "remediation_code": """# VULNERABLE
os.system(f"ping {user_host}")
subprocess.run("ls " + directory, shell=True)

# SECURE - Argument list, no shell
subprocess.run(["ping", "-c", "4", validated_host], shell=False)

# SECURE - Validation
allowed_hosts = ['google.com', 'github.com']
if user_host not in allowed_hosts:
    raise ValueError("Invalid host")"""
    },

    # ==================== CONSOLIDATED: Input Validation (was duplicate) ====================
    "Input Validation Bypass": {
        "patterns": [
            # Request parameter access without apparent validation
            {
                "regex": r'request\.(args|form|json|data)\[.*?\].*?(execute|query|open|system|eval)',
                "confidence": "high",
                "description": "Request data used directly in sensitive operation"
            },
            # URL parameters in SQL
            {
                "regex": r'params\[.*?\].*?(SELECT|INSERT|UPDATE|DELETE)',
                "confidence": "high",
                "description": "URL parameters in SQL query"
            },
            # Direct assignment from request
            {
                "regex": r'=\s*(req\.|request\.)(body|query|params)\[',
                "confidence": "low",
                "description": "Assignment from request (verify validation)"
            },
        ],
        "cwe": "CWE-20",
        "owasp": "A03:2021 - Injection",
        "severity": "medium",
        "description": "User input accessed without visible validation before use in sensitive operations.",
        "impact": """**Business Impact:**
- Various injection attacks depending on context
- Data integrity issues from malformed input

**Technical Impact:**
- SQL, command, or path injection if input reaches sensitive sinks
- Application crashes from unexpected input formats""",
        "remediation": """1. Validate all input against expected formats (type, length, pattern)
2. Use schema validation libraries (Pydantic, Joi, Zod)
3. Apply allowlist validation where possible
4. Sanitize input appropriate to context (SQL, HTML, command)""",
        "remediation_code": """# VULNERABLE
user_id = request.args['id']
query = f"SELECT * FROM users WHERE id = {user_id}"

# SECURE - Validate and parameterize
from pydantic import BaseModel, conint

class UserQuery(BaseModel):
    id: conint(gt=0, lt=1000000)

validated = UserQuery(id=request.args['id'])
cursor.execute("SELECT * FROM users WHERE id = ?", (validated.id,))"""
    },

    # ==================== AUTHENTICATION ====================
    "Hardcoded Credentials": {
        "patterns": [
            # Password/secret assignment with substantial value
            {
                "regex": r'(password|passwd|pwd|secret)\s*=\s*["\'][A-Za-z0-9!@#$%^&*]{8,}["\']',
                "confidence": "high",
                "description": "Hardcoded password/secret"
            },
            # API key patterns
            {
                "regex": r'(api[_-]?key|apikey)\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
                "confidence": "high",
                "description": "Hardcoded API key"
            },
            # AWS/Cloud credentials
            {
                "regex": r'(AWS_SECRET|aws_secret_access_key)\s*=\s*["\'][^"\']{20,}["\']',
                "confidence": "critical",
                "description": "Hardcoded AWS credentials"
            },
            # Database connection strings
            {
                "regex": r'(postgresql|mysql|mongodb)://\w+:[^@]+@',
                "confidence": "high",
                "description": "Database connection string with password"
            },
        ],
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "severity": "critical",
        "exclude_patterns": [
            r'(example|test|sample|placeholder|xxx+|your[_-]?)',
            r'os\.environ',
            r'getenv',
            r'config\[',
        ],
        "description": "Credentials hardcoded in source code. Exposes sensitive authentication data to anyone with code access.",
        "impact": """**Business Impact:**
- Immediate unauthorized access if code is exposed
- Cannot rotate credentials without code changes
- Supply chain risk if in shared/open-source code

**Technical Impact:**
- Direct access to databases, APIs, cloud services
- Persistent access even after incident detection""",
        "remediation": """**Immediate Actions:**
1. Remove hardcoded credentials and rotate ALL exposed secrets
2. Scan git history for previously committed secrets
3. Enable secret scanning in repository settings

**Long-term Remediation:**
1. Use secrets manager (Vault, AWS Secrets Manager)
2. Use environment variables for configuration
3. Implement pre-commit hooks to prevent secret commits""",
        "remediation_code": """# VULNERABLE
PASSWORD = "MySecretPassword123"
API_KEY = "sk-1234567890abcdefghij"

# SECURE - Environment variables
import os
password = os.environ.get('DB_PASSWORD')
api_key = os.environ.get('API_KEY')

# SECURE - Secrets manager
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='prod/db/password')"""
    },

    "Weak Password Storage": {
        "patterns": [
            {
                "regex": r'hashlib\.(md5|sha1)\s*\([^)]*password',
                "confidence": "critical",
                "description": "MD5/SHA1 hashing of password"
            },
            {
                "regex": r'(md5|sha1)\s*\(\s*\$?password',
                "confidence": "critical",
                "description": "Weak hash for password"
            },
            {
                "regex": r'base64\.(b64encode|encode)\s*\([^)]*password',
                "confidence": "critical",
                "description": "Base64 encoding of password (NOT hashing)"
            },
            {
                "regex": r'MessageDigest\.getInstance\s*\(["\']MD5["\']',
                "confidence": "high",
                "description": "Java MD5 MessageDigest"
            },
        ],
        "cwe": "CWE-916",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "critical",
        "safe_patterns": "crypto",
        "description": "Password stored using weak hashing algorithm. MD5/SHA1 can be cracked in seconds with modern hardware.",
        "impact": """**Business Impact:**
- Mass credential compromise if database breached
- Account takeover for all affected users
- Regulatory non-compliance (NIST, PCI-DSS)

**Technical Impact:**
- Rainbow table attacks reverse hashes instantly
- GPU cracking tests billions of hashes per second
- Credential stuffing on other services""",
        "remediation": """1. Use Argon2id (recommended) or bcrypt with cost >= 12
2. Plan migration to rehash on next user login
3. Force password reset if breach suspected""",
        "remediation_code": """# VULNERABLE
hash = hashlib.md5(password.encode()).hexdigest()

# SECURE - bcrypt
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# SECURE - Argon2id
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)"""
    },

    # ==================== CONSOLIDATED: JWT (was duplicate) ====================
    "JWT Security Issues": {
        "patterns": [
            {
                "regex": r'jwt\.(encode|sign).*?algorithm\s*=\s*["\']none["\']',
                "confidence": "critical",
                "description": "JWT with 'none' algorithm"
            },
            {
                "regex": r'jwt\.decode.*?verify\s*=\s*False',
                "confidence": "critical",
                "description": "JWT decode without verification"
            },
            {
                "regex": r'jwt\.decode.*?options\s*=\s*\{[^}]*verify_signature["\']?\s*:\s*False',
                "confidence": "critical",
                "description": "JWT signature verification disabled"
            },
            {
                "regex": r'(sign|verify)\s*\([^,]+,\s*["\']["\']',
                "confidence": "high",
                "description": "JWT with empty secret"
            },
            {
                "regex": r'algorithms\s*=\s*\[[^\]]*["\']HS256["\'][^\]]*["\']RS256["\']',
                "confidence": "high",
                "description": "JWT algorithm confusion vulnerability"
            },
        ],
        "cwe": "CWE-347",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "critical",
        "description": "Insecure JWT configuration allowing token forgery or signature bypass.",
        "impact": """**Business Impact:**
- Complete authentication bypass
- Impersonation of any user including admins
- Unauthorized access to protected resources

**Technical Impact:**
- Token forgery using 'none' algorithm
- Algorithm confusion attacks (RS256 to HS256)
- Privilege escalation via claim modification""",
        "remediation": """1. Explicitly specify allowed algorithms in verify
2. Use strong secrets (256+ bits) for HS256
3. Never accept 'none' algorithm
4. Use asymmetric algorithms (RS256) for distributed systems""",
        "remediation_code": """# VULNERABLE
token = jwt.encode(payload, '', algorithm='none')
data = jwt.decode(token, verify=False)

# SECURE
SECRET = os.environ.get('JWT_SECRET')  # 256+ bit secret
token = jwt.encode(payload, SECRET, algorithm='HS256')
data = jwt.decode(token, SECRET, algorithms=['HS256'])"""
    },

    # ==================== FILE SECURITY ====================
    "Path Traversal": {
        "patterns": [
            # open() with f-string
            {
                "regex": r'open\s*\(\s*f["\'][^"\']*\{[^}]+\}',
                "confidence": "high",
                "description": "open() with f-string path"
            },
            # open() with concatenation
            {
                "regex": r'open\s*\(\s*[^)]*\+[^)]*\)',
                "confidence": "medium",
                "description": "open() with path concatenation"
            },
            # Direct ../ pattern in path operations
            {
                "regex": r'\.\./.*?(open|read|write|File)',
                "confidence": "medium",
                "description": "Relative path in file operation"
            },
            # File operations with request input
            {
                "regex": r'(open|readFile|writeFile)\s*\([^)]*req\.(params|query|body)',
                "confidence": "high",
                "description": "File operation with request input"
            },
            # PHP include/require with variable
            {
                "regex": r'(include|require)(_once)?\s*\([^)]*\$',
                "confidence": "high",
                "description": "PHP include with variable"
            },
            # Java File with concatenation
            {
                "regex": r'new\s+File\s*\([^)]*\+',
                "confidence": "medium",
                "description": "Java File with concatenation"
            },
        ],
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": "high",
        "safe_patterns": "path_traversal",
        "description": "File path constructed with unsanitized input, allowing access to files outside intended directory.",
        "impact": """**Business Impact:**
- Access to sensitive configuration files
- Source code exposure revealing business logic
- Credential theft from config files

**Technical Impact:**
- Reading /etc/passwd, application configs
- Accessing private keys and certificates
- Log files with sensitive data""",
        "remediation": """1. Use os.path.basename() to strip directory components
2. Validate resolved paths stay within allowed directory
3. Use allowlist of permitted filenames
4. Store files with random UUIDs instead of user names""",
        "remediation_code": """# VULNERABLE
with open(f"/uploads/{user_filename}", 'r') as f:
    data = f.read()

# SECURE
import os
safe_name = os.path.basename(user_filename)
full_path = os.path.join('/uploads', safe_name)
abs_path = os.path.realpath(full_path)
if not abs_path.startswith('/uploads/'):
    raise ValueError("Invalid path")
with open(abs_path, 'r') as f:
    data = f.read()"""
    },

    # ==================== CRYPTOGRAPHY ====================
    "Weak Cryptography": {
        "patterns": [
            {
                "regex": r'hashlib\.(md5|sha1)\s*\(',
                "confidence": "medium",
                "description": "MD5/SHA1 hash usage"
            },
            {
                "regex": r'Cipher\.getInstance\s*\(["\']DES',
                "confidence": "high",
                "description": "DES encryption (weak)"
            },
            {
                "regex": r'createCipher(iv)?\s*\(["\']?(des|rc4)',
                "confidence": "high",
                "description": "Weak cipher (DES/RC4)"
            },
            {
                "regex": r'(MD5|SHA1)DigestUtils',
                "confidence": "medium",
                "description": "Weak hash utility"
            },
        ],
        "cwe": "CWE-327",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "high",
        "safe_patterns": "crypto",
        "context_note": "MD5/SHA1 acceptable for non-security checksums (file integrity, caching)",
        "description": "Use of cryptographically weak algorithms that can be broken with modern computing resources.",
        "impact": """**Business Impact:**
- Encrypted data vulnerable to decryption
- Compliance violations (PCI-DSS, HIPAA)
- False sense of security

**Technical Impact:**
- MD5/SHA1 collision attacks enable forgery
- DES brute-forceable with modern hardware""",
        "remediation": """1. Replace MD5/SHA1 with SHA-256/SHA-3
2. Replace DES/RC4 with AES-256-GCM
3. Use cryptography libraries with secure defaults""",
        "remediation_code": """# VULNERABLE
hash = hashlib.md5(data).hexdigest()

# SECURE
hash = hashlib.sha256(data).hexdigest()

# SECURE - AES-GCM encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = os.urandom(32)
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)"""
    },

    "Insecure Random": {
        "patterns": [
            {
                "regex": r'random\.(random|randint|choice|shuffle)\s*\(',
                "confidence": "medium",
                "description": "Non-cryptographic random for security use"
            },
            {
                "regex": r'Math\.random\s*\(\)',
                "confidence": "medium",
                "description": "JavaScript Math.random (not cryptographic)"
            },
            {
                "regex": r'rand\s*\(\s*\)',
                "confidence": "medium",
                "description": "rand() function (predictable)"
            },
        ],
        "cwe": "CWE-330",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "medium",
        "context_note": "Only a concern when used for tokens, passwords, keys, or security decisions",
        "description": "Non-cryptographic random number generator used where cryptographic randomness is required.",
        "impact": """**Business Impact:**
- Predictable tokens/passwords enabling account takeover
- Session hijacking through token prediction

**Technical Impact:**
- Random state can be recovered from outputs
- Predictable seeds reduce entropy""",
        "remediation": "Use secrets module (Python) or crypto.randomBytes (Node.js) for security-sensitive random values.",
        "remediation_code": """# VULNERABLE
token = ''.join(random.choice(string.ascii_letters) for _ in range(32))

# SECURE
import secrets
token = secrets.token_urlsafe(32)

// Node.js - SECURE
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');"""
    },

    # ==================== DESERIALIZATION ====================
    "Insecure Deserialization": {
        "patterns": [
            {
                "regex": r'pickle\.(load|loads)\s*\(',
                "confidence": "high",
                "description": "Pickle deserialization (allows code execution)"
            },
            {
                "regex": r'yaml\.load\s*\([^)]*\)(?!.*?(safe_?load|Loader\s*=\s*\w*Safe))',
                "confidence": "high",
                "description": "Unsafe YAML load"
            },
            {
                "regex": r'eval\s*\(\s*(request|req|input|data)',
                "confidence": "critical",
                "description": "eval() with user input"
            },
            {
                "regex": r'exec\s*\(\s*(request|req|input|data)',
                "confidence": "critical",
                "description": "exec() with user input"
            },
            {
                "regex": r'unserialize\s*\(\s*\$',
                "confidence": "high",
                "description": "PHP unserialize with user input"
            },
            {
                "regex": r'ObjectInputStream.*?readObject',
                "confidence": "high",
                "description": "Java deserialization"
            },
        ],
        "cwe": "CWE-502",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "severity": "critical",
        "safe_patterns": "deserialization",
        "description": "Deserialization of untrusted data can lead to remote code execution.",
        "impact": """**Business Impact:**
- Remote Code Execution leading to complete compromise
- Data breach through server access
- Ransomware deployment

**Technical Impact:**
- Arbitrary code execution in application context
- Object injection manipulating application logic""",
        "remediation": """1. Replace pickle with JSON for data serialization
2. Use yaml.safe_load() instead of yaml.load()
3. Never use eval/exec with user input
4. Use schema validation for deserialized data""",
        "remediation_code": """# VULNERABLE
data = pickle.loads(user_input)
data = yaml.load(user_input)
result = eval(user_input)

# SECURE
data = json.loads(user_input)
data = yaml.safe_load(user_input)
# Never eval user input"""
    },

    # ==================== CONSOLIDATED: Debug Mode (was duplicate) ====================
    "Debug Mode in Production": {
        "patterns": [
            {
                "regex": r'DEBUG\s*=\s*True',
                "confidence": "high",
                "description": "DEBUG set to True"
            },
            {
                "regex": r'app\.run\s*\([^)]*debug\s*=\s*True',
                "confidence": "high",
                "description": "Flask debug mode"
            },
            {
                "regex": r'FLASK_DEBUG\s*=\s*["\']?1',
                "confidence": "high",
                "description": "Flask debug environment"
            },
            {
                "regex": r'app\.debug\s*=\s*True',
                "confidence": "high",
                "description": "Application debug mode enabled"
            },
            {
                "regex": r'NODE_ENV\s*[!=]=\s*["\']?production',
                "confidence": "medium",
                "description": "Node not in production mode"
            },
        ],
        "cwe": "CWE-489",
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity": "high",
        "description": "Debug mode enabled in code. In production, this exposes sensitive information and enables code execution.",
        "impact": """**Business Impact:**
- Information disclosure revealing application internals
- Potential code execution through debug consoles
- Verbose errors aiding attacker reconnaissance

**Technical Impact:**
- Stack traces expose file paths and code
- Flask/Django debug consoles allow code execution
- Detailed error messages reveal architecture""",
        "remediation": """1. Set DEBUG=False in production
2. Use environment variables for configuration
3. Never commit debug settings to version control
4. Implement proper error handling that hides internals""",
        "remediation_code": """# VULNERABLE
DEBUG = True
app.run(debug=True)

# SECURE - Use environment variable
import os
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
app.run(debug=False)"""
    },

    # ==================== CONSOLIDATED: CORS (was duplicate) ====================
    "CORS Misconfiguration": {
        "patterns": [
            {
                "regex": r'Access-Control-Allow-Origin["\']?\s*[,:=]\s*["\']?\*',
                "confidence": "high",
                "description": "CORS allows all origins"
            },
            {
                "regex": r'allow_origins\s*=\s*\[["\']?\*["\']?\]',
                "confidence": "high",
                "description": "CORS middleware allows all origins"
            },
            {
                "regex": r'cors\s*\(\s*\*\s*\)',
                "confidence": "high",
                "description": "CORS function with wildcard"
            },
            {
                "regex": r'Access-Control-Allow-Credentials.*?true.*?Allow-Origin.*?\*',
                "confidence": "critical",
                "description": "CORS wildcard with credentials"
            },
        ],
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity": "medium",
        "description": "CORS configured to allow all origins, potentially exposing APIs to unauthorized cross-origin requests.",
        "impact": """**Business Impact:**
- Cross-origin data theft from authenticated users
- CSRF-like attacks from malicious websites
- API abuse from unauthorized domains

**Technical Impact:**
- Browser same-origin policy bypassed
- Authenticated requests from any origin
- Data exfiltration through malicious sites""",
        "remediation": """1. Specify allowed origins explicitly
2. Never combine wildcard (*) with credentials
3. Validate Origin header on sensitive endpoints""",
        "remediation_code": """# VULNERABLE
CORS(app, resources={r"/*": {"origins": "*"}})

# SECURE - Explicit origins
ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com"
]
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})"""
    },

    # ==================== SSRF ====================
    "Server-Side Request Forgery (SSRF)": {
        "patterns": [
            {
                "regex": r'requests\.(get|post|put|delete)\s*\(\s*(f["\']|.*?\+)',
                "confidence": "high",
                "description": "HTTP request with dynamic URL"
            },
            {
                "regex": r'urllib\.request\.urlopen\s*\([^)]*\+',
                "confidence": "high",
                "description": "urllib with dynamic URL"
            },
            {
                "regex": r'fetch\s*\(\s*`[^`]*\$\{',
                "confidence": "high",
                "description": "fetch() with template literal URL"
            },
            {
                "regex": r'axios\.(get|post)\s*\([^)]*\+',
                "confidence": "medium",
                "description": "axios request with dynamic URL"
            },
            {
                "regex": r'http\.get\s*\([^)]*\+',
                "confidence": "medium",
                "description": "Node http with dynamic URL"
            },
        ],
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "severity": "high",
        "description": "Server makes HTTP requests with user-controlled URLs, allowing attacks on internal services.",
        "impact": """**Business Impact:**
- Access to internal services and cloud metadata
- Port scanning of internal network
- Data exfiltration from internal APIs

**Technical Impact:**
- AWS/GCP/Azure metadata endpoint access
- Internal service enumeration
- Bypass of network segmentation""",
        "remediation": """1. Validate and allowlist permitted URL schemes and domains
2. Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x)
3. Block cloud metadata endpoints (169.254.169.254)
4. Use URL parsing to validate before requesting""",
        "remediation_code": """# VULNERABLE
response = requests.get(user_url)

# SECURE - URL validation
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            return False
    except ValueError:
        pass  # Not an IP address
    # Check allowlist
    allowed_domains = ['api.example.com', 'cdn.example.com']
    return parsed.hostname in allowed_domains"""
    },

    # ==================== LOGGING ====================
    "Sensitive Data Logging": {
        "patterns": [
            {
                "regex": r'(log|logger|console\.log|print)\s*\([^)]*password',
                "confidence": "high",
                "description": "Password in log statement"
            },
            {
                "regex": r'(log|logger)\.(debug|info|warning|error)\s*\([^)]*token',
                "confidence": "medium",
                "description": "Token in log statement"
            },
            {
                "regex": r'console\.log\s*\([^)]*secret',
                "confidence": "medium",
                "description": "Secret in console.log"
            },
            {
                "regex": r'(log|print)\s*\([^)]*credit.?card',
                "confidence": "high",
                "description": "Credit card data in logs"
            },
        ],
        "cwe": "CWE-532",
        "owasp": "A09:2021 - Security Logging and Monitoring Failures",
        "severity": "medium",
        "description": "Sensitive data written to logs where it may be exposed to unauthorized parties.",
        "impact": """**Business Impact:**
- Credential exposure in log aggregators
- PCI-DSS violation for card data
- Privacy regulation violations

**Technical Impact:**
- Passwords readable in log files
- Tokens enabling session hijacking
- PII exposure in centralized logging""",
        "remediation": """1. Never log passwords, tokens, or secrets
2. Mask sensitive data before logging
3. Use structured logging with field redaction
4. Implement log data classification""",
        "remediation_code": """# VULNERABLE
logger.info(f"User login: {username}, password: {password}")

# SECURE - Mask sensitive data
logger.info(f"User login: {username}")
# Or use masking
def mask_sensitive(data):
    return data[:2] + '***' + data[-2:] if len(data) > 4 else '***'"""
    },
}


# =============================================================================
# GO-SPECIFIC VULNERABILITY PATTERNS
# =============================================================================

GO_VULNERABILITY_PATTERNS = {
    "Go SQL Injection": {
        "patterns": [
            # String concatenation in SQL
            {
                "regex": r'db\.(Query|QueryRow|Exec)\s*\([^)]*\+',
                "confidence": "critical",
                "description": "SQL query with string concatenation"
            },
            {
                "regex": r'db\.(Query|QueryRow|Exec)\s*\(\s*fmt\.Sprintf',
                "confidence": "critical",
                "description": "SQL query using fmt.Sprintf"
            },
            {
                "regex": r'db\.(Query|QueryRow|Exec)\s*\([^)]*\%[svdqx]',
                "confidence": "high",
                "description": "SQL with format verb"
            },
            # GORM raw queries
            {
                "regex": r'\.Raw\s*\(\s*fmt\.Sprintf',
                "confidence": "critical",
                "description": "GORM Raw with fmt.Sprintf"
            },
            {
                "regex": r'\.Raw\s*\([^)]*\+',
                "confidence": "critical",
                "description": "GORM Raw with concatenation"
            },
            # sqlx queries
            {
                "regex": r'sqlx\.(Get|Select|NamedExec)\s*\([^)]*\+',
                "confidence": "high",
                "description": "sqlx query with concatenation"
            },
            # String interpolation in query
            {
                "regex": r'(Query|Exec)\s*\(\s*`[^`]*\$\{',
                "confidence": "high",
                "description": "SQL with template literal interpolation"
            },
        ],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "severity": "critical",
        "safe_patterns": ["sql_injection"],
        "description": "SQL query constructed with user input in Go, allowing SQL injection attacks.",
        "impact": """**Business Impact:**
- Complete database compromise and data exfiltration
- Authentication bypass and privilege escalation
- Regulatory violations (GDPR, PCI-DSS)

**Technical Impact:**
- Direct SQL modification enabling data theft
- Server compromise via database features
- Lateral movement through database links""",
        "remediation": """**Immediate Actions:**
1. Use parameterized queries with $1, $2 placeholders
2. Use GORM's built-in query builder methods
3. Validate and sanitize all user inputs

**Example Fix:**
```go
// VULNERABLE
db.Query("SELECT * FROM users WHERE id = " + userID)

// SECURE - Parameterized
db.Query("SELECT * FROM users WHERE id = $1", userID)

// SECURE - GORM
db.Where("id = ?", userID).First(&user)
```""",
    },

    "Go Command Injection": {
        "patterns": [
            # exec.Command with user input
            {
                "regex": r'exec\.Command\s*\([^)]*\+',
                "confidence": "critical",
                "description": "exec.Command with string concatenation"
            },
            {
                "regex": r'exec\.Command\s*\(\s*fmt\.Sprintf',
                "confidence": "critical",
                "description": "exec.Command with fmt.Sprintf"
            },
            {
                "regex": r'exec\.Command\s*\([^)]*r\.(FormValue|URL\.Query|Body)',
                "confidence": "critical",
                "description": "exec.Command with HTTP request input"
            },
            # CommandContext
            {
                "regex": r'exec\.CommandContext\s*\([^)]*\+',
                "confidence": "critical",
                "description": "exec.CommandContext with concatenation"
            },
            # os.StartProcess
            {
                "regex": r'os\.StartProcess\s*\([^)]*\+',
                "confidence": "critical",
                "description": "os.StartProcess with concatenation"
            },
            # Shell execution patterns
            {
                "regex": r'exec\.Command\s*\(\s*["\'](?:sh|bash|cmd)["\'].*?-c',
                "confidence": "high",
                "description": "Shell command execution"
            },
        ],
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "severity": "critical",
        "description": "OS command executed with user-controlled input in Go, enabling arbitrary command execution.",
        "impact": """**Business Impact:**
- Complete server compromise
- Data breach and ransomware deployment
- Supply chain attacks

**Technical Impact:**
- Remote Code Execution (RCE)
- File system access and modification
- Privilege escalation""",
        "remediation": """**Immediate Actions:**
1. Pass arguments as separate elements to exec.Command
2. Validate inputs against allowlists
3. Never use shell interpreters (sh -c) with user input

**Example Fix:**
```go
// VULNERABLE
exec.Command("sh", "-c", "ping " + userHost).Run()

// SECURE - Separate arguments
cmd := exec.Command("ping", "-c", "4", validatedHost)
```""",
    },

    "Go Path Traversal": {
        "patterns": [
            # os.Open with user input
            {
                "regex": r'os\.Open\s*\([^)]*\+',
                "confidence": "high",
                "description": "os.Open with path concatenation"
            },
            {
                "regex": r'os\.Open\s*\(\s*filepath\.Join[^)]*r\.',
                "confidence": "high",
                "description": "os.Open with filepath.Join from request"
            },
            # ioutil/os file reading
            {
                "regex": r'(ioutil|os)\.(ReadFile|WriteFile)\s*\([^)]*\+',
                "confidence": "high",
                "description": "File operation with path concatenation"
            },
            # http.ServeFile
            {
                "regex": r'http\.ServeFile\s*\([^)]*r\.(FormValue|URL)',
                "confidence": "critical",
                "description": "http.ServeFile with request input"
            },
            # filepath.Join with user input (without validation)
            {
                "regex": r'filepath\.Join\s*\([^)]*r\.(FormValue|URL\.Query)',
                "confidence": "medium",
                "description": "filepath.Join with user input"
            },
        ],
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": "high",
        "safe_patterns": ["path_traversal"],
        "description": "File path constructed with user input allowing access to arbitrary files.",
        "impact": """**Business Impact:**
- Access to sensitive configuration files
- Source code and secret exposure
- Data breach

**Technical Impact:**
- Reading /etc/passwd, credentials
- Accessing private keys
- Log file exposure""",
        "remediation": """**Immediate Actions:**
1. Use filepath.Clean and validate paths stay within allowed directory
2. Use filepath.Base to strip directory components
3. Implement allowlist of permitted files

**Example Fix:**
```go
// VULNERABLE
filePath := filepath.Join(baseDir, userInput)
os.Open(filePath)

// SECURE - Validate path
cleanPath := filepath.Clean(userInput)
if strings.HasPrefix(cleanPath, "..") {
    return errors.New("invalid path")
}
fullPath := filepath.Join(baseDir, filepath.Base(cleanPath))
```""",
    },

    "Go XSS via Templates": {
        "patterns": [
            # text/template (not HTML-safe)
            {
                "regex": r'text/template.*?Execute',
                "confidence": "medium",
                "description": "text/template used (not HTML-safe)"
            },
            # template.HTML() wrapping user input
            {
                "regex": r'template\.HTML\s*\([^)]*r\.',
                "confidence": "critical",
                "description": "template.HTML with request input"
            },
            {
                "regex": r'template\.HTML\s*\([^)]*\+',
                "confidence": "high",
                "description": "template.HTML with concatenation"
            },
            # Direct response write without encoding
            {
                "regex": r'w\.Write\s*\(\s*\[\]byte\s*\([^)]*r\.',
                "confidence": "high",
                "description": "Direct response write with request data"
            },
            # Gin HTML without escaping
            {
                "regex": r'c\.Header\s*\([^)]*Content-Type.*?text/html',
                "confidence": "medium",
                "description": "HTML content type response"
            },
        ],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "severity": "high",
        "description": "User input rendered in HTML response without proper encoding.",
        "impact": """**Business Impact:**
- Session hijacking and account takeover
- Credential theft and phishing
- Malware distribution

**Technical Impact:**
- JavaScript execution in user's browser
- Cookie theft and keylogging
- DOM manipulation""",
        "remediation": """**Immediate Actions:**
1. Use html/template (auto-escapes) instead of text/template
2. Never wrap user input in template.HTML
3. Use framework-provided escaping functions

**Example Fix:**
```go
// VULNERABLE - text/template doesn't escape
import "text/template"
t.Execute(w, userInput)

// SECURE - html/template auto-escapes
import "html/template"
t.Execute(w, userInput)
```""",
    },

    "Go SSRF": {
        "patterns": [
            # http.Get with user URL
            {
                "regex": r'http\.Get\s*\([^)]*\+',
                "confidence": "high",
                "description": "http.Get with dynamic URL"
            },
            {
                "regex": r'http\.Get\s*\(\s*r\.(FormValue|URL\.Query)',
                "confidence": "critical",
                "description": "http.Get with request input"
            },
            # http.NewRequest with user URL
            {
                "regex": r'http\.NewRequest\s*\([^)]*\+',
                "confidence": "high",
                "description": "http.NewRequest with dynamic URL"
            },
            # client.Do with user-controlled request
            {
                "regex": r'client\.Do\s*\([^)]*\+',
                "confidence": "medium",
                "description": "HTTP client request with dynamic data"
            },
            # url.Parse with user input
            {
                "regex": r'url\.Parse\s*\(\s*r\.',
                "confidence": "medium",
                "description": "URL parsing of request input"
            },
        ],
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "severity": "high",
        "description": "Server makes HTTP requests with user-controlled URLs.",
        "impact": """**Business Impact:**
- Access to internal services and metadata
- Cloud credential theft
- Internal network scanning

**Technical Impact:**
- AWS/GCP metadata access (169.254.169.254)
- Internal API access
- Port scanning""",
        "remediation": """**Immediate Actions:**
1. Validate URLs against allowlist of domains
2. Block internal IP ranges and metadata endpoints
3. Use URL parsing to validate before making requests

**Example Fix:**
```go
func isValidURL(inputURL string) bool {
    u, err := url.Parse(inputURL)
    if err != nil || u.Scheme != "https" {
        return false
    }
    allowedHosts := []string{"api.example.com"}
    return contains(allowedHosts, u.Host)
}
```""",
    },

    "Go Weak Cryptography": {
        "patterns": [
            # MD5 usage
            {
                "regex": r'crypto/md5',
                "confidence": "medium",
                "description": "MD5 import detected"
            },
            {
                "regex": r'md5\.New\s*\(\)',
                "confidence": "medium",
                "description": "MD5 hash creation"
            },
            # SHA1 usage
            {
                "regex": r'sha1\.New\s*\(\)',
                "confidence": "medium",
                "description": "SHA1 hash creation"
            },
            # DES encryption
            {
                "regex": r'des\.NewCipher',
                "confidence": "high",
                "description": "DES cipher (weak)"
            },
            # RC4
            {
                "regex": r'rc4\.NewCipher',
                "confidence": "high",
                "description": "RC4 cipher (weak)"
            },
            # Weak key sizes
            {
                "regex": r'rsa\.GenerateKey\s*\([^)]*,\s*(512|1024)\s*\)',
                "confidence": "high",
                "description": "Weak RSA key size"
            },
        ],
        "cwe": "CWE-327",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "high",
        "context_note": "MD5/SHA1 acceptable for non-security checksums",
        "description": "Use of weak cryptographic algorithms in Go.",
        "impact": """**Business Impact:**
- Encrypted data vulnerable to decryption
- Compliance violations
- False sense of security

**Technical Impact:**
- Hash collision attacks
- Brute-force attacks on weak keys""",
        "remediation": """**Immediate Actions:**
1. Use SHA-256 or SHA-3 for hashing
2. Use AES-GCM for symmetric encryption
3. Use RSA with minimum 2048-bit keys

**Example Fix:**
```go
// VULNERABLE
import "crypto/md5"
hash := md5.Sum(data)

// SECURE
import "crypto/sha256"
hash := sha256.Sum256(data)
```""",
    },

    "Go Insecure TLS": {
        "patterns": [
            # InsecureSkipVerify
            {
                "regex": r'InsecureSkipVerify\s*:\s*true',
                "confidence": "critical",
                "description": "TLS certificate verification disabled"
            },
            # MinVersion too low
            {
                "regex": r'MinVersion\s*:\s*tls\.(VersionSSL30|VersionTLS10|VersionTLS11)',
                "confidence": "high",
                "description": "Weak TLS version allowed"
            },
            # Weak cipher suites
            {
                "regex": r'CipherSuites.*?(TLS_RSA_|RC4|3DES|NULL)',
                "confidence": "high",
                "description": "Weak cipher suite"
            },
        ],
        "cwe": "CWE-295",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "severity": "high",
        "description": "Insecure TLS configuration allowing man-in-the-middle attacks.",
        "impact": """**Business Impact:**
- Man-in-the-middle attacks possible
- Data interception
- Credential theft

**Technical Impact:**
- Certificate validation bypass
- Downgrade attacks
- Traffic decryption""",
        "remediation": """**Immediate Actions:**
1. Remove InsecureSkipVerify: true
2. Set MinVersion to tls.VersionTLS12 or higher
3. Use recommended cipher suites

**Example Fix:**
```go
// VULNERABLE
transport := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

// SECURE
transport := &http.Transport{
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
}
```""",
    },

    "Go Race Condition": {
        "patterns": [
            # Shared map without mutex
            {
                "regex": r'var\s+\w+\s*=\s*make\s*\(\s*map\[',
                "confidence": "low",
                "description": "Global map (potential race condition)"
            },
            # goroutine accessing shared variable
            {
                "regex": r'go\s+func\s*\([^)]*\)\s*\{[^}]*\w+\s*=',
                "confidence": "low",
                "description": "Goroutine modifying variable"
            },
        ],
        "cwe": "CWE-362",
        "owasp": "A04:2021 - Insecure Design",
        "severity": "medium",
        "context_note": "Requires manual verification; use go race detector",
        "description": "Potential race condition in concurrent Go code.",
        "impact": """**Business Impact:**
- Data corruption and inconsistency
- Authentication bypass possible
- Unpredictable application behavior

**Technical Impact:**
- Memory corruption
- Time-of-check to time-of-use (TOCTOU)
- Deadlocks""",
        "remediation": """**Immediate Actions:**
1. Use sync.Mutex or sync.RWMutex for shared data
2. Use sync.Map for concurrent map access
3. Run tests with -race flag

**Example Fix:**
```go
// VULNERABLE
var cache = make(map[string]string)

// SECURE - Using sync.Map
var cache sync.Map
cache.Store(key, value)
```""",
    },

    "Go Error Not Checked": {
        "patterns": [
            # Ignored error return
            {
                "regex": r'[^,]\s*,\s*_\s*[=:]=\s*\w+\s*\(',
                "confidence": "low",
                "description": "Error return value ignored"
            },
            # Single value from multi-return
            {
                "regex": r'^\s*\w+\s*\(\s*[^)]*\)\s*$',
                "confidence": "low",
                "description": "Possible ignored error return"
            },
        ],
        "cwe": "CWE-754",
        "owasp": "A04:2021 - Insecure Design",
        "severity": "low",
        "description": "Error return value not checked, potentially hiding security issues.",
        "impact": """**Technical Impact:**
- Security checks may silently fail
- Undefined behavior on errors
- Difficult debugging""",
        "remediation": """1. Always check error return values
2. Use linters like errcheck or golangci-lint
3. Handle errors appropriately""",
    },

    "Go Hardcoded Credentials": {
        "patterns": [
            # Password assignment
            {
                "regex": r'(password|passwd|pwd|secret)\s*[=:]+\s*["`][A-Za-z0-9!@#$%^&*]{8,}["`]',
                "confidence": "high",
                "description": "Hardcoded password/secret"
            },
            # API key patterns
            {
                "regex": r'(apiKey|apiSecret|api_key)\s*[=:]+\s*["`][a-zA-Z0-9_\-]{20,}["`]',
                "confidence": "high",
                "description": "Hardcoded API key"
            },
            # Database DSN with password
            {
                "regex": r'(postgres|mysql|mongodb)://\w+:[^@]+@',
                "confidence": "high",
                "description": "Database connection string with password"
            },
        ],
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "severity": "critical",
        "description": "Credentials hardcoded in Go source code.",
        "impact": """**Business Impact:**
- Immediate unauthorized access if code exposed
- Cannot rotate without code changes
- Supply chain risk

**Technical Impact:**
- Direct access to databases/APIs
- Persistent access""",
        "remediation": """**Immediate Actions:**
1. Remove hardcoded credentials
2. Use environment variables or config files
3. Scan git history for leaked secrets

**Example Fix:**
```go
// VULNERABLE
dbPassword := "MySecretPass123"

// SECURE
dbPassword := os.Getenv("DB_PASSWORD")
```""",
    },

    "Go JWT Security Issues": {
        "patterns": [
            # None algorithm
            {
                "regex": r'SigningMethod.*?None',
                "confidence": "critical",
                "description": "JWT none algorithm"
            },
            # Skip claims validation
            {
                "regex": r'SkipClaimsValidation\s*:\s*true',
                "confidence": "high",
                "description": "JWT claims validation skipped"
            },
            # Weak secret
            {
                "regex": r'\.Parse\s*\([^)]*,\s*func.*?return\s*\[\]byte\s*\(["`][^`"]{0,15}["`]\)',
                "confidence": "high",
                "description": "Short JWT secret"
            },
        ],
        "cwe": "CWE-347",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "critical",
        "description": "Insecure JWT configuration in Go allowing token forgery.",
        "impact": """**Business Impact:**
- Authentication bypass
- User impersonation
- Privilege escalation

**Technical Impact:**
- Token forgery
- Algorithm confusion attacks""",
        "remediation": """1. Always verify signature with specific algorithm
2. Use strong secrets (256+ bits)
3. Validate all claims including exp, iss, aud""",
    },
}


def get_patterns_for_language(language: str) -> Dict[str, Any]:
    """
    Get vulnerability patterns applicable to a specific language.
    This reduces false positives by only checking relevant patterns.
    """
    language_patterns = {}

    # Language-specific pattern applicability
    language_filter = {
        'python': ['SQL Injection', 'Command Injection', 'Path Traversal', 'Insecure Deserialization',
                   'Hardcoded Credentials', 'Weak Password Storage', 'SSRF', 'Debug Mode in Production',
                   'Sensitive Data Logging', 'JWT Security Issues', 'CORS Misconfiguration'],
        'javascript': ['SQL Injection', 'XSS (Cross-Site Scripting)', 'Command Injection', 'NoSQL Injection',
                       'JWT Security Issues', 'CORS Misconfiguration', 'Insecure Random', 'Sensitive Data Logging'],
        'typescript': ['SQL Injection', 'XSS (Cross-Site Scripting)', 'Command Injection', 'NoSQL Injection',
                       'JWT Security Issues', 'CORS Misconfiguration', 'Sensitive Data Logging'],
        'java': ['SQL Injection', 'Command Injection', 'Path Traversal', 'Insecure Deserialization',
                 'Weak Cryptography', 'JWT Security Issues', 'Hardcoded Credentials'],
        'php': ['SQL Injection', 'XSS (Cross-Site Scripting)', 'Command Injection', 'Path Traversal',
                'Insecure Deserialization', 'Hardcoded Credentials'],
        'go': [],  # Will use GO_VULNERABILITY_PATTERNS
        'ruby': ['SQL Injection', 'Command Injection', 'Path Traversal', 'Insecure Deserialization'],
        'csharp': ['SQL Injection', 'Command Injection', 'Path Traversal', 'Insecure Deserialization',
                   'Hardcoded Credentials'],
    }

    # For Go, use dedicated Go patterns
    if language == 'go':
        return GO_VULNERABILITY_PATTERNS

    applicable_vulns = language_filter.get(language, list(VULNERABILITY_PATTERNS_V2.keys()))

    for vuln_name in applicable_vulns:
        if vuln_name in VULNERABILITY_PATTERNS_V2:
            language_patterns[vuln_name] = VULNERABILITY_PATTERNS_V2[vuln_name]

    return language_patterns


# =============================================================================
# GO-SPECIFIC SAFE PATTERNS
# =============================================================================

GO_SAFE_PATTERNS = {
    "sql_injection": [
        r'\$\d',  # Parameterized placeholder
        r'\?\s*,',  # Question mark placeholder
        r'\.Where\s*\([^)]*,\s*\w+\)',  # GORM Where with param
        r'\.First\s*\(&\w+,\s*\w+\)',  # GORM First with param
        r'sqlx\.Named',  # sqlx named queries
    ],
    "command_injection": [
        r'exec\.Command\s*\(\s*"[^"]+"\s*,\s*"[^"]*"\s*\)',  # Static command
        r'exec\.Command\s*\(\s*\w+\s*,\s*\.\.\.\w+\)',  # Variable arguments
    ],
    "path_traversal": [
        r'filepath\.Clean',  # Path cleaning
        r'filepath\.Base',  # Base name only
        r'strings\.HasPrefix.*?baseDir',  # Path validation
    ],
}


def calculate_finding_confidence(
    base_confidence: str,
    has_safe_pattern: bool,
    is_in_test_file: bool,
    match_context: str
) -> str:
    """
    Calculate final confidence based on various factors.
    Returns: 'critical', 'high', 'medium', 'low'
    """
    confidence_levels = ['low', 'medium', 'high', 'critical']

    # Start with base confidence
    confidence_idx = confidence_levels.index(base_confidence) if base_confidence in confidence_levels else 1

    # Reduce confidence if safe pattern detected
    if has_safe_pattern:
        confidence_idx = max(0, confidence_idx - 2)

    # Reduce confidence for test files
    if is_in_test_file:
        confidence_idx = max(0, confidence_idx - 1)

    return confidence_levels[confidence_idx]
