"""
SAST (Static Application Security Testing) Scanner
Professional-grade multi-language security analyzer with comprehensive vulnerability detection
"""
import re
from typing import List, Dict, Any, Set
import os

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
                r'(execute|query|exec|executemany|rawQuery)\s*\(\s*["\'].*?(\+|%|\$\{|f["\'])',
                r'(cursor|db|conn)\.(execute|query)\s*\([^)]*\+',
                r'(SELECT|INSERT|UPDATE|DELETE).*?(\+|%s|\$\{)',
                r'createQuery\s*\([^)]*\+',  # JPA
                r'\$wpdb->query\s*\([^)]*\$',  # WordPress
            ],
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "severity": "critical",
            "description": "SQL query construction using string concatenation or formatting. Vulnerable to SQL injection attacks.",
            "remediation": "Use parameterized queries, prepared statements, or ORM frameworks. Never concatenate user input into SQL queries.",
            "remediation_code": """# Python - Bad
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)

# Python - Good
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

// Java - Bad
String query = "SELECT * FROM users WHERE id = " + userId;
statement.executeQuery(query);

// Java - Good
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
stmt.executeQuery();"""
        },

        "NoSQL Injection": {
            "patterns": [
                r'(find|findOne|update|remove)\s*\(\s*\{.*?(\$|request\.|params\.)',
                r'db\.collection.*?\$where',
                r'new\s+ObjectId\s*\([^)]*req\.',
            ],
            "cwe": "CWE-943",
            "owasp": "A03:2021 - Injection",
            "severity": "high",
            "description": "NoSQL query constructed with unsanitized user input.",
            "remediation": "Validate and sanitize all user inputs. Use query builders or avoid $where operators.",
            "remediation_code": """// Bad
db.collection.find({ name: req.query.name })

// Good
const sanitizedName = validator.escape(req.query.name);
db.collection.find({ name: sanitizedName })"""
        },

        "XSS (Cross-Site Scripting)": {
            "patterns": [
                r'(innerHTML|outerHTML|document\.write)\s*=.*?(\+|`\$\{)',
                r'dangerouslySetInnerHTML\s*=\s*\{\{.*?\}\}',
                r'(eval|Function)\s*\(.*?(request\.|params\.|req\.)',
                r'<script>.*?\$\{',
                r'\.html\s*\(.*?(\+|\$\{)',  # jQuery
            ],
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "severity": "high",
            "description": "Direct DOM manipulation or HTML rendering with unsanitized user input. Vulnerable to XSS attacks.",
            "remediation": "Use textContent instead of innerHTML, sanitize input with DOMPurify, or use frameworks with auto-escaping.",
            "remediation_code": """// Bad
element.innerHTML = userInput;
element.outerHTML = "<div>" + userInput + "</div>";

// Good
element.textContent = userInput;
element.innerHTML = DOMPurify.sanitize(userInput);

// React - Bad
<div dangerouslySetInnerHTML={{__html: userInput}} />

// React - Good
<div>{userInput}</div>"""
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
            "owasp": "A03:2021 - Injection",
            "severity": "critical",
            "description": "Command execution with user-controlled input. Allows arbitrary command execution on the server.",
            "remediation": "Avoid shell execution. Use subprocess with argument lists (shell=False). Validate and whitelist inputs.",
            "remediation_code": """# Python - Bad
os.system("ping " + user_input)
subprocess.call("ping " + user_input, shell=True)

# Python - Good
subprocess.run(["ping", "-c", "4", user_input], shell=False, timeout=5)

// Java - Bad
Runtime.getRuntime().exec("ping " + userInput);

// Java - Good
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", userInput);
pb.start();"""
        },

        "LDAP Injection": {
            "patterns": [
                r'search\s*\(\s*["\'][^"\']*\+.*?["\']',
                r'LdapTemplate.*?search.*?\+',
            ],
            "cwe": "CWE-90",
            "owasp": "A03:2021 - Injection",
            "severity": "high",
            "description": "LDAP query constructed with unsanitized user input.",
            "remediation": "Use parameterized LDAP queries or sanitize special characters.",
            "remediation_code": """# Bad
ldap_filter = "(uid=" + username + ")"

# Good
from ldap3 import Connection, SUBTREE
username = ldap3.utils.conv.escape_filter_chars(username)
ldap_filter = f"(uid={username})" """
        },

        "XML Injection": {
            "patterns": [
                r'(parseXML|XMLParser|xml\.etree).*?(\+|\$\{)',
                r'XXE|ENTITY',
            ],
            "cwe": "CWE-91",
            "owasp": "A03:2021 - Injection",
            "severity": "high",
            "description": "XML parsing with unsanitized input. May allow XXE attacks.",
            "remediation": "Disable external entity processing. Use secure XML parsers.",
            "remediation_code": """# Python - Bad
import xml.etree.ElementTree as ET
tree = ET.parse(user_file)

# Python - Good
import defusedxml.ElementTree as ET
tree = ET.parse(user_file)"""
        },

        # ==================== AUTHENTICATION & SESSION VULNERABILITIES ====================
        "Hardcoded Credentials": {
            "patterns": [
                r'(password|passwd|pwd|secret|api[_-]?key|token|auth)\s*=\s*["\'][^"\']{6,}["\']',
                r'(DB_PASSWORD|DATABASE_PASSWORD|SECRET_KEY)\s*=\s*["\'][^"\']{6,}["\']',
                r'(AWS_SECRET|PRIVATE_KEY|CLIENT_SECRET)\s*=\s*["\'][^"\']{8,}["\']',
            ],
            "cwe": "CWE-798",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "severity": "critical",
            "description": "Hardcoded credentials or secrets found in source code. Exposes sensitive authentication data.",
            "remediation": "Store credentials in environment variables, secrets managers (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault), or encrypted configuration files.",
            "remediation_code": """# Bad
password = "MySecretPassword123"
API_KEY = "sk-1234567890abcdef"

# Good
import os
password = os.environ.get('DB_PASSWORD')
api_key = os.environ.get('API_KEY')

# Or use secrets manager
from aws_secretsmanager import get_secret
password = get_secret('db_password')"""
        },

        "Weak Password Storage": {
            "patterns": [
                r'(md5|sha1|base64)\s*\(\s*password',
                r'password\s*=\s*(md5|sha1)',
                r'hashlib\.(md5|sha1)\s*\(',
            ],
            "cwe": "CWE-916",
            "owasp": "A02:2021 - Cryptographic Failures",
            "severity": "critical",
            "description": "Password stored using weak hashing algorithm (MD5, SHA1). Vulnerable to rainbow table attacks.",
            "remediation": "Use strong password hashing algorithms: bcrypt, scrypt, argon2, or PBKDF2.",
            "remediation_code": """# Bad
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# Good
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Or use argon2
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)"""
        },

        "Insecure JWT": {
            "patterns": [
                r'jwt\.encode.*?algorithm\s*=\s*["\']none["\']',
                r'jwt\.decode.*?verify\s*=\s*False',
                r'jsonwebtoken\.sign\(\s*[^,]*,\s*["\']["\']',  # Empty secret
            ],
            "cwe": "CWE-347",
            "owasp": "A02:2021 - Cryptographic Failures",
            "severity": "critical",
            "description": "JWT token with 'none' algorithm or disabled verification. Allows token forgery.",
            "remediation": "Use strong algorithms (RS256, HS256) with proper secret keys. Never use 'none' algorithm.",
            "remediation_code": """# Bad
token = jwt.encode(payload, '', algorithm='none')
data = jwt.decode(token, verify=False)

# Good
token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])"""
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
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "severity": "critical",
            "description": "Insecure deserialization of untrusted data. Can lead to remote code execution.",
            "remediation": "Avoid deserializing untrusted data. Use JSON instead of pickle. For YAML, use yaml.safe_load(). Never use eval() or exec().",
            "remediation_code": """# Python - Bad
import pickle
data = pickle.loads(user_input)
result = eval(user_input)

# Python - Good
import json
data = json.loads(user_input)

# For YAML
import yaml
data = yaml.safe_load(user_input)

// Java - Bad
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// Java - Good
// Use JSON libraries like Jackson or Gson"""
        },

        # ==================== FILE & PATH VULNERABILITIES ====================
        "Path Traversal": {
            "patterns": [
                r'(open|read|readFile|file_get_contents)\s*\([^)]*(\+|f["\']|\$\{)',
                r'(File|FileInputStream|FileReader)\s*\([^)]*\+',
                r'\.\./',
                r'os\.path\.join\([^)]*(?!os\.path\.basename)',
            ],
            "cwe": "CWE-22",
            "owasp": "A01:2021 - Broken Access Control",
            "severity": "high",
            "description": "File path constructed with unsanitized user input. Allows reading arbitrary files via path traversal.",
            "remediation": "Validate file paths. Use os.path.basename() to strip directory components. Implement whitelist of allowed paths.",
            "remediation_code": """# Bad
with open("/var/files/" + user_filename, 'r') as f:
    content = f.read()

# Good
import os
safe_name = os.path.basename(user_filename)
safe_path = os.path.join("/var/files/", safe_name)
if os.path.commonprefix([os.path.realpath(safe_path), "/var/files/"]) == "/var/files/":
    with open(safe_path, 'r') as f:
        content = f.read()"""
        },

        "Unrestricted File Upload": {
            "patterns": [
                r'(save|saveAs|upload|write).*?filename\s*=',
                r'move_uploaded_file.*?\$_FILES',
                r'file\.write\s*\([^)]*request\.',
            ],
            "cwe": "CWE-434",
            "owasp": "A01:2021 - Broken Access Control",
            "severity": "critical",
            "description": "File upload without proper validation. May allow uploading malicious files.",
            "remediation": "Validate file type, extension, size, and content. Store uploaded files outside webroot. Use randomized filenames.",
            "remediation_code": """# Bad
file.save(f"uploads/{file.filename}")

# Good
import os, uuid
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4()}_{filename}"
    file.save(os.path.join(UPLOAD_FOLDER, unique_name))"""
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
            "owasp": "A02:2021 - Cryptographic Failures",
            "severity": "high",
            "description": "Use of weak or broken cryptographic algorithms. MD5, SHA1, and DES are cryptographically broken.",
            "remediation": "Use strong algorithms: AES-256-GCM for encryption, SHA-256/SHA-512 for hashing, bcrypt/argon2 for passwords.",
            "remediation_code": """# Bad
import hashlib
hash = hashlib.md5(data).hexdigest()

# Good
import hashlib
hash = hashlib.sha256(data).hexdigest()

# For encryption - Bad
from Crypto.Cipher import DES

# For encryption - Good
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())"""
        },

        "Hardcoded Cryptographic Key": {
            "patterns": [
                r'(key|secret|iv|salt)\s*=\s*b?["\'][^"\']{16,}["\']',
                r'AES\.new\s*\([^,]*b?["\'][^"\']{16}',
            ],
            "cwe": "CWE-321",
            "owasp": "A02:2021 - Cryptographic Failures",
            "severity": "critical",
            "description": "Hardcoded cryptographic key in source code. Compromises all encrypted data.",
            "remediation": "Generate keys at runtime or store in secure key management systems.",
            "remediation_code": """# Bad
key = b'hardcoded_secret'

# Good
import os
key = os.urandom(32)  # Generate random key
# Or retrieve from key management
from aws_encryption_sdk import KMSMasterKeyProvider
key_provider = KMSMasterKeyProvider(key_ids=['arn:aws:kms:...'])"""
        },

        "Insecure Random": {
            "patterns": [
                r'random\.(random|randint|choice)',
                r'Math\.random\(\)',
                r'new Random\(',
            ],
            "cwe": "CWE-338",
            "owasp": "A02:2021 - Cryptographic Failures",
            "severity": "medium",
            "description": "Use of non-cryptographic random number generator for security-sensitive operations.",
            "remediation": "Use cryptographically secure random generators: secrets module (Python), crypto.randomBytes (Node.js), SecureRandom (Java).",
            "remediation_code": """# Python - Bad
import random
token = random.randint(100000, 999999)

# Python - Good
import secrets
token = secrets.randbelow(900000) + 100000

// Node.js - Bad
const token = Math.random();

// Node.js - Good
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');"""
        },

        # ==================== INPUT VALIDATION ====================
        "Insufficient Input Validation": {
            "patterns": [
                r'request\.(GET|POST|args|form|json|query|body|params)\[',
                r'req\.(query|params|body)\.',
                r'\$_(GET|POST|REQUEST|COOKIE)\[',
            ],
            "cwe": "CWE-20",
            "owasp": "A03:2021 - Injection",
            "severity": "medium",
            "description": "Direct use of user input without validation or sanitization.",
            "remediation": "Validate and sanitize all user inputs. Use schema validation libraries (pydantic, joi, express-validator).",
            "remediation_code": """# Python Flask - Bad
user_id = request.args['id']

# Python Flask - Good
from flask import request, abort
user_id = request.args.get('id', type=int)
if not user_id or user_id < 0:
    abort(400)

// Express - Bad
const userId = req.query.id;

// Express - Good
const Joi = require('joi');
const schema = Joi.object({ id: Joi.number().integer().positive().required() });
const { error, value } = schema.validate(req.query);
if (error) return res.status(400).send(error.details);"""
        },

        "Mass Assignment": {
            "patterns": [
                r'(Model|model)\.(create|update).*?request\.(data|json|body)',
                r'User\.objects\.(create|update).*?\*\*request',
                r'new\s+\w+\(req\.body\)',
            ],
            "cwe": "CWE-915",
            "owasp": "A01:2021 - Broken Access Control",
            "severity": "high",
            "description": "Direct assignment of user input to model. May allow modifying unintended fields.",
            "remediation": "Use explicit field whitelisting. Define allowed fields for user input.",
            "remediation_code": """# Python Django - Bad
User.objects.create(**request.data)

# Python Django - Good
allowed_fields = ['username', 'email', 'first_name', 'last_name']
user_data = {k: request.data[k] for k in allowed_fields if k in request.data}
User.objects.create(**user_data)

// Express/Sequelize - Bad
User.create(req.body)

// Express/Sequelize - Good
const { username, email, firstName, lastName } = req.body;
User.create({ username, email, firstName, lastName })"""
        },

        # ==================== SECURITY MISCONFIGURATION ====================
        "Debug Mode Enabled": {
            "patterns": [
                r'(DEBUG|debug)\s*=\s*True',
                r'app\.debug\s*=\s*True',
                r'(development|dev)\s*:\s*true',
            ],
            "cwe": "CWE-489",
            "owasp": "A05:2021 - Security Misconfiguration",
            "severity": "high",
            "description": "Debug mode enabled. Exposes sensitive information including stack traces, variable values, and source code.",
            "remediation": "Disable debug mode in production. Use environment-specific configurations.",
            "remediation_code": """# Bad
DEBUG = True

# Good
import os
DEBUG = os.environ.get('DEBUG', 'False') == 'True'

# Or
DEBUG = os.environ.get('FLASK_ENV') == 'development'"""
        },

        "CORS Misconfiguration": {
            "patterns": [
                r'Access-Control-Allow-Origin.*?\*',
                r'cors\s*\(\s*\{\s*origin\s*:\s*["\' ]\*',
                r'AllowAnyOrigin\s*\(\s*\)',
            ],
            "cwe": "CWE-942",
            "owasp": "A05:2021 - Security Misconfiguration",
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
            "owasp": "A02:2021 - Cryptographic Failures",
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
            "owasp": "A01:2021 - Broken Access Control",
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
            "owasp": "A04:2021 - Insecure Design",
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
            "owasp": "A04:2021 - Insecure Design",
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
            "owasp": "A02:2021 - Cryptographic Failures",
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
            "owasp": "A04:2021 - Insecure Design",
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
            "owasp": "A04:2021 - Insecure Design",
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

        # ==================== REGEX & LOGIC ====================
        "Regular Expression DoS (ReDoS)": {
            "patterns": [
                r're\.compile\([^)]*\(\.\*\)\+',
                r're\.compile\([^)]*\(\.\+\)\*',
                r'new RegExp\([^)]*\(\.\*\)\+',
            ],
            "cwe": "CWE-1333",
            "owasp": "A04:2021 - Insecure Design",
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
    }

    def __init__(self):
        """Initialize the scanner"""
        self.scanned_files = 0
        self.skipped_files = 0
        self.errors = []
        self.custom_rules = []
        self._load_custom_rules()

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

                            # Add category prefix for better organization
                            category = self._get_vulnerability_category(vuln_name)
                            formatted_title = f"{category}: {vuln_name}" if category != vuln_name else vuln_name

                            findings.append({
                                "title": formatted_title,
                                "description": vuln_info['description'],
                                "severity": vuln_info['severity'],
                                "cwe_id": vuln_info['cwe'],
                                "owasp_category": vuln_info['owasp'],
                                "file_path": file_path,
                                "line_number": line_num,
                                "code_snippet": line.strip(),
                                "remediation": vuln_info['remediation'],
                                "remediation_code": vuln_info['remediation_code'],
                                "cvss_score": self._calculate_cvss(vuln_info['severity']),
                                "stride_category": self._map_to_stride(vuln_name),
                                "mitre_attack_id": self._map_to_mitre(vuln_name),
                                "language": language,
                                "confidence": "high" if "critical" in vuln_info['severity'] else "medium"
                            })
                    except re.error as e:
                        self.errors.append(f"Regex error in pattern '{pattern}': {e}")

        # Scan with custom rules (user-defined and AI-generated)
        custom_findings = self._scan_with_custom_rules(code_content, file_path, language, lines)
        findings.extend(custom_findings)

        return findings

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
        try:
            conn = sqlite3.connect('appsec.db')
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
