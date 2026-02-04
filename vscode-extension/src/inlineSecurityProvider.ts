import * as vscode from 'vscode';

export class InlineSecurityProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    private securityPatterns = [
        // ============================================================
        // A01:2021 - BROKEN ACCESS CONTROL
        // ============================================================
        {
            pattern: /\.role\s*[!=]==?\s*['"`]admin['"`]/gi,
            message: '🔐 A01: Hardcoded role check - Broken Access Control',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use role-based access control (RBAC) with configurable permissions'
        },
        {
            pattern: /if\s*\(\s*user\.id\s*[!=]==?\s*\d+/gi,
            message: '🔐 A01: Hardcoded user ID check - Broken Access Control',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use proper authorization checks, not hardcoded IDs'
        },
        {
            pattern: /\/admin|\/api\/admin|isAdmin\s*[=:]/gi,
            message: '🔐 A01: Admin endpoint/flag detected - ensure proper authorization',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Implement proper RBAC and verify admin access on server-side'
        },
        {
            pattern: /req\.user\.id\s*[!=]==?\s*req\.params/gi,
            message: '🔐 A01: IDOR vulnerability - comparing user ID with URL parameter',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use proper authorization middleware, not direct ID comparison'
        },
        {
            pattern: /document\.cookie|localStorage\.getItem\s*\(\s*['"`]token/gi,
            message: '🔐 A01: Client-side token storage detected',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use HttpOnly cookies for sensitive tokens to prevent XSS theft'
        },
        {
            pattern: /bypass|skip.*auth|noauth|disable.*auth/gi,
            message: '🔐 A01: Authentication bypass pattern detected',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never bypass authentication checks in production code'
        },

        // ============================================================
        // A02:2021 - CRYPTOGRAPHIC FAILURES
        // ============================================================
        {
            pattern: /md5\s*\(|MD5\.|hashlib\.md5/gi,
            message: '🔒 A02: MD5 is cryptographically broken',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use SHA-256, SHA-3, or bcrypt/Argon2 for passwords'
        },
        {
            pattern: /sha1\s*\(|SHA1\.|hashlib\.sha1/gi,
            message: '🔒 A02: SHA-1 is deprecated and vulnerable to collisions',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use SHA-256 or SHA-3 for cryptographic hashing'
        },
        {
            pattern: /DES|3DES|RC4|RC2|Blowfish/gi,
            message: '🔒 A02: Weak/deprecated encryption algorithm',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use AES-256-GCM or ChaCha20-Poly1305'
        },
        {
            pattern: /ECB|AES\/ECB|mode\s*[=:]\s*['"`]?ECB/gi,
            message: '🔒 A02: ECB mode reveals patterns in encrypted data',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use GCM, CBC with HMAC, or CTR mode'
        },
        {
            pattern: /Math\.random\s*\(/gi,
            message: '🔒 A02: Math.random() is not cryptographically secure',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use crypto.getRandomValues() or crypto.randomBytes()'
        },
        {
            pattern: /random\.random\s*\(|random\.randint/gi,
            message: '🔒 A02: Python random module is not cryptographically secure',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use secrets module for security-sensitive randomness'
        },
        {
            pattern: /new\s+Random\s*\(/gi,
            message: '🔒 A02: java.util.Random is not cryptographically secure',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use SecureRandom for cryptographic operations'
        },
        {
            pattern: /(password|passwd|pwd)\s*[=:]\s*['"`][^'"`]{3,}['"`]/gi,
            message: '🔒 A02: Hardcoded password detected',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use environment variables or secure vault'
        },
        {
            pattern: /(secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[=:]\s*['"`][^'"`]{8,}['"`]/gi,
            message: '🔒 A02: Hardcoded secret/API key detected',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use secrets manager or environment variables'
        },
        {
            pattern: /AKIA[A-Z0-9]{16}/gi,
            message: '🔒 A02: AWS Access Key ID detected',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use IAM roles or AWS Secrets Manager'
        },
        {
            pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/gi,
            message: '🔒 A02: Private key detected in code',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Store private keys in secure key management systems'
        },
        {
            pattern: /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi,
            message: '🔒 A02: Bearer token detected in code',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never hardcode authentication tokens'
        },
        {
            pattern: /ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/gi,
            message: '🔒 A02: GitHub token detected',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use GitHub Actions secrets or environment variables'
        },
        {
            pattern: /sk-[a-zA-Z0-9]{48}/gi,
            message: '🔒 A02: OpenAI API key detected',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use environment variables for API keys'
        },
        {
            pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/gi,
            message: '🔒 A02: Slack token detected',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use environment variables for Slack tokens'
        },
        {
            pattern: /http:\/\/(?!localhost|127\.0\.0\.1)/gi,
            message: '🔒 A02: Unencrypted HTTP connection detected',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use HTTPS for all external connections'
        },
        {
            pattern: /verify\s*[=:]\s*[Ff]alse|verify_ssl\s*[=:]\s*[Ff]alse|ssl[_-]?verify\s*[=:]\s*[Ff]alse|CURLOPT_SSL_VERIFYPEER.*false/gi,
            message: '🔒 A02: SSL/TLS verification disabled',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Enable SSL verification to prevent MITM attacks'
        },
        {
            pattern: /rejectUnauthorized\s*:\s*false/gi,
            message: '🔒 A02: Node.js TLS verification disabled',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Enable rejectUnauthorized for secure connections'
        },

        // ============================================================
        // A03:2021 - INJECTION (SQL, NoSQL, OS, LDAP, XSS)
        // ============================================================
        // SQL Injection - Simple patterns that catch common cases
        {
            pattern: /SELECT\s+.*\s+FROM\s+.*\+/gi,
            message: '💉 A03: SQL Injection - SELECT with string concatenation',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use parameterized queries or prepared statements'
        },
        {
            pattern: /SELECT\s+\*\s+FROM/gi,
            message: '💉 A03: SQL Injection risk - SELECT * FROM detected',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Avoid SELECT *, specify columns. If dynamic, use parameterized queries'
        },
        {
            pattern: /WHERE\s+.*\s*=\s*['"]\s*\+/gi,
            message: '💉 A03: SQL Injection - WHERE clause with string concatenation',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use parameterized queries instead of string concatenation'
        },
        {
            pattern: /WHERE\s+\w+\s*=\s*['"]?\s*\$\{/gi,
            message: '💉 A03: SQL Injection - WHERE with template literal',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use parameterized queries instead of template literals'
        },
        {
            pattern: /"\s*\+\s*\w+\s*\+\s*"/gi,
            message: '💉 A03: String concatenation detected - potential SQL injection if used in query',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'If this is a SQL query, use parameterized queries'
        },
        {
            pattern: /'\s*\+\s*\w+\s*\+\s*'/gi,
            message: '💉 A03: String concatenation detected - potential SQL injection if used in query',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'If this is a SQL query, use parameterized queries'
        },
        {
            pattern: /query\s*=\s*["'].*SELECT|query\s*=\s*["'].*INSERT|query\s*=\s*["'].*UPDATE|query\s*=\s*["'].*DELETE/gi,
            message: '💉 A03: SQL query string detected',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Ensure parameterized queries are used, not string concatenation'
        },
        {
            pattern: /execute\s*\(\s*["'].*SELECT|execute\s*\(\s*["'].*INSERT|execute\s*\(\s*f["']/gi,
            message: '💉 A03: SQL Injection - direct query execution',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use parameterized queries: cursor.execute(query, params)'
        },
        {
            pattern: /mysql_query|mysqli_query|pg_query|sqlite3?_query/gi,
            message: '💉 A03: Raw SQL query function - high injection risk',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use prepared statements with bound parameters'
        },
        {
            pattern: /INSERT\s+INTO.*VALUES.*\+|UPDATE.*SET.*\+|DELETE\s+FROM.*\+/gi,
            message: '💉 A03: SQL Injection - INSERT/UPDATE/DELETE with concatenation',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use parameterized queries or prepared statements'
        },
        {
            pattern: /f["']SELECT|f["']INSERT|f["']UPDATE|f["']DELETE|f["']DROP/gi,
            message: '💉 A03: SQL Injection - Python f-string in SQL query',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use cursor.execute(query, params) with placeholders'
        },
        {
            pattern: /\.format\s*\(.*\).*WHERE|\.format\s*\(.*\).*SELECT/gi,
            message: '💉 A03: SQL Injection - .format() in SQL query',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use parameterized queries instead of string formatting'
        },
        {
            pattern: /%s.*WHERE|%s.*SELECT|%d.*WHERE/gi,
            message: '💉 A03: SQL Injection - printf-style formatting in query',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use parameterized queries with ? or $1 placeholders'
        },
        {
            pattern: /executeQuery\s*\(|prepareStatement\s*\(/gi,
            message: '💉 A03: Java SQL execution - ensure prepared statements are used correctly',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Use PreparedStatement with setString/setInt for all parameters'
        },
        {
            pattern: /UNION\s+SELECT|OR\s+1\s*=\s*1|OR\s+['"]1['"]\s*=\s*['"]1['"]/gi,
            message: '💉 A03: SQL Injection payload pattern detected!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'This is a common SQL injection attack pattern'
        },
        {
            pattern: /--\s*$|;\s*DROP|;\s*DELETE|;\s*UPDATE|;\s*INSERT/gi,
            message: '💉 A03: SQL Injection - comment or stacked query pattern',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'This pattern is commonly used in SQL injection attacks'
        },

        // NoSQL Injection
        {
            pattern: /\$where\s*:|\.find\s*\(\s*\{.*\$(?:gt|lt|ne|eq|regex)/gi,
            message: '💉 A03: NoSQL Injection - MongoDB operator injection',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Sanitize input and avoid $where, use schema validation'
        },
        {
            pattern: /\$regex.*req\.|req\..*\$regex/gi,
            message: '💉 A03: NoSQL Injection - user input in regex',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Escape special regex characters from user input'
        },

        // Command Injection
        {
            pattern: /eval\s*\(/gi,
            message: '💉 A03: Code Injection - eval() executes arbitrary code',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use JSON.parse() for data or safer alternatives'
        },
        {
            pattern: /new\s+Function\s*\(/gi,
            message: '💉 A03: Code Injection - new Function() like eval()',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Avoid dynamic code execution'
        },
        {
            pattern: /exec\s*\(|child_process\.exec|shell_exec|system\s*\(/gi,
            message: '💉 A03: Command Injection - shell command execution',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use execFile() with array args, never concatenate user input'
        },
        {
            pattern: /os\.system\s*\(|os\.popen\s*\(/gi,
            message: '💉 A03: Command Injection - Python shell execution',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use subprocess.run() with shell=False and list arguments'
        },
        {
            pattern: /subprocess.*shell\s*=\s*True/gi,
            message: '💉 A03: Command Injection - shell=True is dangerous',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use shell=False and pass arguments as a list'
        },
        {
            pattern: /Runtime\.getRuntime\(\)\.exec/gi,
            message: '💉 A03: Command Injection - Java Runtime.exec()',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use ProcessBuilder with separate arguments'
        },
        {
            pattern: /passthru\s*\(|proc_open\s*\(|popen\s*\(/gi,
            message: '💉 A03: Command Injection - PHP shell function',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Avoid shell functions or use escapeshellarg()'
        },

        // ============================================================
        // PHP-SPECIFIC VULNERABILITIES (DVWA patterns)
        // ============================================================
        {
            pattern: /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['"][^'"]+['"]\s*\]/gi,
            message: '💉 A03: PHP User Input - Potential injection source',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Sanitize with htmlspecialchars(), filter_input(), or prepared statements'
        },
        {
            pattern: /\$(?:query|sql|stmt)\s*=\s*["'].*\$_(?:GET|POST|REQUEST)/gi,
            message: '💉 A03: SQL Injection - User input directly in SQL query!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use prepared statements: $stmt = $pdo->prepare(); $stmt->execute()'
        },
        {
            pattern: /["']SELECT.*FROM.*WHERE.*\$_(?:GET|POST|REQUEST)/gi,
            message: '💉 A03: SQL Injection - $_GET/$_POST in SELECT query!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use PDO prepared statements with bound parameters'
        },
        {
            pattern: /["']SELECT.*FROM.*WHERE.*['"]?\s*\.\s*\$/gi,
            message: '💉 A03: SQL Injection - Variable concatenated in query',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never concatenate variables in SQL - use prepared statements'
        },
        {
            pattern: /mysqli?_query\s*\([^,]+,\s*["'].*\$/gi,
            message: '💉 A03: SQL Injection - Variable in mysqli_query!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use mysqli_prepare() and mysqli_stmt_bind_param()'
        },
        {
            pattern: /mysql_(?:query|real_escape_string|escape_string)/gi,
            message: '💉 A03: Deprecated mysql_* functions - vulnerable to injection',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use PDO or mysqli with prepared statements'
        },
        {
            pattern: /echo\s+\$_(?:GET|POST|REQUEST|COOKIE)/gi,
            message: '🔓 A07: XSS - Echoing user input directly!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use htmlspecialchars($_GET["param"], ENT_QUOTES, "UTF-8")'
        },
        {
            pattern: /print\s+\$_(?:GET|POST|REQUEST|COOKIE)/gi,
            message: '🔓 A07: XSS - Printing user input directly!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use htmlspecialchars() to escape output'
        },
        {
            pattern: /echo\s+["'].*\$(?!this|_(?:SERVER|ENV))/gi,
            message: '🔓 A07: XSS - Variable in echo without escaping',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Escape with htmlspecialchars() before output'
        },
        {
            pattern: /include\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
            message: '💉 A03: LFI/RFI - User input in include()!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never include files based on user input - use whitelist'
        },
        {
            pattern: /require(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
            message: '💉 A03: LFI/RFI - User input in require()!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never require files based on user input'
        },
        {
            pattern: /file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
            message: '💉 A03: SSRF/LFI - User input in file_get_contents!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Validate and whitelist allowed URLs/paths'
        },
        {
            pattern: /header\s*\(\s*["']Location:\s*["']?\s*\.\s*\$_(?:GET|POST|REQUEST)/gi,
            message: '🔓 A10: Open Redirect - User input in redirect!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Validate redirect URLs against whitelist'
        },
        {
            pattern: /unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi,
            message: '💉 A08: Insecure Deserialization - User input in unserialize!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never unserialize untrusted data - use JSON instead'
        },
        {
            pattern: /preg_replace\s*\(\s*['"]\/.*\/e['"]/gi,
            message: '💉 A03: Code Injection - preg_replace with /e modifier!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use preg_replace_callback() instead of /e modifier'
        },
        {
            pattern: /assert\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
            message: '💉 A03: Code Injection - User input in assert()!',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never use assert() with user input'
        },
        {
            pattern: /\$\w+\s*=\s*\$_(?:GET|POST|REQUEST)\s*\[\s*['"][^'"]+['"]\s*\]\s*;(?!\s*(?:\/\/|\/\*|\$\w+\s*=\s*(?:htmlspecialchars|filter|intval|mysqli_real_escape)))/gi,
            message: '⚠️ User input assigned without validation',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Validate/sanitize: filter_input(), htmlspecialchars(), intval()'
        },

        // LDAP Injection
        {
            pattern: /ldap_search\s*\(.*\$|ldap_bind\s*\(.*\$/gi,
            message: '💉 A03: LDAP Injection - user input in LDAP query',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Escape special LDAP characters: * ( ) \\ NUL'
        },
        {
            pattern: /\(\w+=[^)]*\$\{|\(\w+=[^)]*\+\s*\w+/gi,
            message: '💉 A03: LDAP Injection - dynamic filter construction',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use parameterized LDAP queries'
        },

        // XPath Injection
        {
            pattern: /xpath\s*\(.*\+|selectNodes\s*\(.*\+/gi,
            message: '💉 A03: XPath Injection - string concatenation',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use parameterized XPath queries'
        },

        // XSS (Cross-Site Scripting)
        {
            pattern: /innerHTML\s*=/gi,
            message: '💉 A03: XSS - innerHTML can execute scripts',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use textContent or sanitize with DOMPurify'
        },
        {
            pattern: /outerHTML\s*=/gi,
            message: '💉 A03: XSS - outerHTML can execute scripts',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use safe DOM methods instead'
        },
        {
            pattern: /document\.write\s*\(/gi,
            message: '💉 A03: XSS - document.write() is dangerous',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use modern DOM manipulation methods'
        },
        {
            pattern: /\.insertAdjacentHTML\s*\(/gi,
            message: '💉 A03: XSS - insertAdjacentHTML needs sanitization',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Sanitize input with DOMPurify first'
        },
        {
            pattern: /dangerouslySetInnerHTML/gi,
            message: '💉 A03: XSS - React dangerouslySetInnerHTML',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Sanitize with DOMPurify before rendering'
        },
        {
            pattern: /v-html\s*=/gi,
            message: '💉 A03: XSS - Vue v-html directive',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use v-text or sanitize content first'
        },
        {
            pattern: /\[innerHTML\]\s*=/gi,
            message: '💉 A03: XSS - Angular innerHTML binding',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use DomSanitizer.bypassSecurityTrustHtml carefully'
        },
        {
            pattern: /\{\{\{.*\}\}\}|<%=.*%>|<%-.*%>/gi,
            message: '💉 A03: XSS - Unescaped template output',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use escaped output: {{ }} or <%- %>'
        },
        {
            pattern: /echo\s+\$_(GET|POST|REQUEST)|print\s+\$_(GET|POST|REQUEST)/gi,
            message: '💉 A03: XSS - PHP echoing unsanitized input',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use htmlspecialchars() or htmlentities()'
        },

        // Template Injection
        {
            pattern: /render_template_string\s*\(|Jinja2.*from_string/gi,
            message: '💉 A03: Template Injection - dynamic template rendering',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use pre-defined templates, never user input as template'
        },

        // ============================================================
        // A04:2021 - INSECURE DESIGN
        // ============================================================
        {
            pattern: /TODO.*security|FIXME.*security|HACK.*auth/gi,
            message: '📐 A04: Security TODO/FIXME found - incomplete implementation',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Address security-related TODOs before deployment'
        },
        {
            pattern: /rate[_-]?limit\s*[=:]\s*0|disable.*rate|no.*throttl/gi,
            message: '📐 A04: Rate limiting disabled - DoS vulnerability',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Implement rate limiting to prevent abuse'
        },
        {
            pattern: /max[_-]?attempts\s*[=:]\s*-1|unlimited.*attempts|infinite.*retry/gi,
            message: '📐 A04: Unlimited attempts - brute force vulnerability',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Limit attempts and implement exponential backoff'
        },
        {
            pattern: /sleep\s*\(\s*\d{4,}\s*\)|time\.sleep\s*\(\s*\d{3,}\s*\)/gi,
            message: '📐 A04: Long sleep detected - potential DoS vector',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Avoid long blocking operations in request handlers'
        },
        {
            pattern: /while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)/gi,
            message: '📐 A04: Infinite loop detected - potential DoS',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Add proper termination conditions'
        },
        {
            pattern: /maxBodyLength\s*:\s*Infinity|limit\s*:\s*['"`]?unlimited/gi,
            message: '📐 A04: Unlimited request size - memory DoS vulnerability',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Set reasonable limits on request body size'
        },
        {
            pattern: /recursion|recursive.*call/gi,
            message: '📐 A04: Recursion detected - ensure depth limits exist',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Implement recursion depth limits to prevent stack overflow'
        },

        // ============================================================
        // A05:2021 - SECURITY MISCONFIGURATION
        // ============================================================
        {
            pattern: /debug\s*[=:]\s*[Tt]rue|DEBUG\s*[=:]\s*True|app\.debug\s*=\s*True/gi,
            message: '⚙️ A05: Debug mode enabled',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Disable debug mode in production'
        },
        {
            pattern: /CORS.*\*|Access-Control-Allow-Origin.*\*|cors\(\s*\)|allowedOrigins.*\*/gi,
            message: '⚙️ A05: Wildcard CORS - allows any origin',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Restrict CORS to specific trusted origins'
        },
        {
            pattern: /allow_all_origins|Access-Control-Allow-Credentials.*true.*\*/gi,
            message: '⚙️ A05: Dangerous CORS with credentials',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never use wildcard origin with credentials'
        },
        {
            pattern: /X-Frame-Options.*ALLOWALL|frameguard.*false|frame-ancestors.*\*/gi,
            message: '⚙️ A05: Clickjacking protection disabled',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Set X-Frame-Options to DENY or SAMEORIGIN'
        },
        {
            pattern: /helmet\s*\(\s*\)|securityHeaders\s*:\s*false/gi,
            message: '⚙️ A05: Security headers not configured',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Configure helmet() with appropriate options'
        },
        {
            pattern: /Content-Security-Policy.*unsafe-inline|CSP.*unsafe-eval/gi,
            message: '⚙️ A05: Weak CSP - allows unsafe inline/eval',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Remove unsafe-inline and unsafe-eval from CSP'
        },
        {
            pattern: /expose.*stack|showStackTrace|includeStackTrace/gi,
            message: '⚙️ A05: Stack traces exposed to users',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Hide stack traces in production, log them internally'
        },
        {
            pattern: /\.env|config\.json|settings\.py|application\.properties/gi,
            message: '⚙️ A05: Configuration file reference detected',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Ensure config files are not exposed and contain no secrets'
        },
        {
            pattern: /admin:admin|root:root|test:test|user:password/gi,
            message: '⚙️ A05: Default credentials detected',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Remove default credentials, require strong passwords'
        },
        {
            pattern: /AllowAny|PermitAll|permitAll\(\)|@PermitAll/gi,
            message: '⚙️ A05: Unrestricted access configured',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Review if public access is intended'
        },
        {
            pattern: /chmod\s+777|os\.chmod.*0o777|permission.*0777/gi,
            message: '⚙️ A05: World-writable permissions (777)',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use restrictive permissions (644 for files, 755 for dirs)'
        },
        {
            pattern: /disable.*csrf|csrf.*false|@csrf_exempt/gi,
            message: '⚙️ A05: CSRF protection disabled',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Enable CSRF protection for state-changing requests'
        },
        {
            pattern: /secure\s*[=:]\s*false|httponly\s*[=:]\s*false|sameSite\s*[=:]\s*['"]none['"]/gi,
            message: '⚙️ A05: Insecure cookie configuration',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Set secure=true, httpOnly=true, sameSite=strict'
        },

        // ============================================================
        // A06:2021 - VULNERABLE AND OUTDATED COMPONENTS
        // ============================================================
        {
            pattern: /jquery[.-]1\.|jquery[.-]2\.[0-2]/gi,
            message: '📦 A06: Outdated jQuery version with known vulnerabilities',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Upgrade to latest jQuery version'
        },
        {
            pattern: /lodash[.-][0-3]\.|lodash[.-]4\.[0-9]\./gi,
            message: '📦 A06: Potentially vulnerable lodash version',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Upgrade lodash to 4.17.21 or later'
        },
        {
            pattern: /moment[.-][0-1]\.|moment[.-]2\.[0-9]\./gi,
            message: '📦 A06: Moment.js is deprecated',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Consider using date-fns, dayjs, or Luxon'
        },
        {
            pattern: /angular[.-]1\.[0-5]/gi,
            message: '📦 A06: AngularJS 1.x is end-of-life',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Migrate to current Angular or another framework'
        },
        {
            pattern: /struts-1\.|struts-2\.[0-3]/gi,
            message: '📦 A06: Apache Struts version with critical vulnerabilities',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Upgrade to latest Struts version immediately'
        },
        {
            pattern: /log4j-core-2\.[0-9]\.|log4j-core-2\.1[0-4]/gi,
            message: '📦 A06: Log4j version vulnerable to Log4Shell',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Upgrade to Log4j 2.17.1 or later immediately'
        },

        // ============================================================
        // A07:2021 - IDENTIFICATION AND AUTHENTICATION FAILURES
        // ============================================================
        {
            pattern: /password.*length.*[<]\s*8|minLength.*[<]\s*8.*password/gi,
            message: '🔑 A07: Weak password policy - minimum length too short',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Require minimum 12 characters for passwords'
        },
        {
            pattern: /session[_-]?timeout\s*[=:]\s*0|session.*never.*expire/gi,
            message: '🔑 A07: Session never expires',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Set appropriate session timeouts (15-30 minutes)'
        },
        {
            pattern: /compare\s*\(\s*password|password\s*[!=]==?\s*|\.equals\s*\(\s*password/gi,
            message: '🔑 A07: Plain text password comparison',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use bcrypt.compare() or similar secure comparison'
        },
        {
            pattern: /jwt\.decode|verify\s*[=:]\s*false.*jwt|algorithm.*none/gi,
            message: '🔑 A07: JWT verification disabled or weak',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Always verify JWT signatures with strong algorithms'
        },
        {
            pattern: /HS256|algorithm\s*[=:]\s*['"]HS/gi,
            message: '🔑 A07: JWT using symmetric algorithm (HS256)',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Consider RS256 for better key management'
        },
        {
            pattern: /expiresIn\s*[=:]\s*['"`]\d+d['"`]|exp.*days?\s*[=:]\s*[3-9]\d+/gi,
            message: '🔑 A07: Long JWT expiration time',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use short-lived tokens (15-60 minutes) with refresh tokens'
        },
        {
            pattern: /remember[_-]?me|persistent[_-]?login|stay[_-]?logged/gi,
            message: '🔑 A07: Remember me functionality detected',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Implement securely with rotating tokens'
        },
        {
            pattern: /password.*reset.*token.*[=:]|reset[_-]?token\s*[=:]/gi,
            message: '🔑 A07: Password reset token handling',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Use short expiry, single-use tokens, and secure random generation'
        },
        {
            pattern: /Invalid\s+(username|password|credentials)|Login\s+failed/gi,
            message: '🔑 A07: Specific error message may aid attackers',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Use generic "Invalid credentials" message'
        },
        {
            pattern: /bcrypt.*rounds?\s*[=:]\s*[1-9]\b|cost\s*[=:]\s*[1-9]\b/gi,
            message: '🔑 A07: Low bcrypt cost factor',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use bcrypt cost factor of 10 or higher'
        },

        // ============================================================
        // A08:2021 - SOFTWARE AND DATA INTEGRITY FAILURES
        // ============================================================
        {
            pattern: /pickle\.loads?\s*\(/gi,
            message: '🔧 A08: Pickle deserialization can execute arbitrary code',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use JSON or other safe serialization formats'
        },
        {
            pattern: /yaml\.load\s*\([^)]*\)(?!.*Loader)/gi,
            message: '🔧 A08: Unsafe YAML loading',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use yaml.safe_load() or specify SafeLoader'
        },
        {
            pattern: /unserialize\s*\(/gi,
            message: '🔧 A08: PHP unserialize can lead to object injection',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use JSON encoding or validate serialized data'
        },
        {
            pattern: /ObjectInputStream|readObject\s*\(/gi,
            message: '🔧 A08: Java deserialization vulnerability',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Implement ObjectInputFilter or use safe alternatives'
        },
        {
            pattern: /Marshal\.load|Marshal\.restore/gi,
            message: '🔧 A08: Ruby Marshal deserialization is unsafe',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Use JSON or verify data integrity before unmarshaling'
        },
        {
            pattern: /npm\s+install(?!.*--ignore-scripts)|yarn\s+add/gi,
            message: '🔧 A08: Package installation without verification',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Use lock files and verify package integrity'
        },
        {
            pattern: /integrity\s*[=:]\s*['"]sha/gi,
            message: '🔧 A08: SRI hash detected - good practice',
            severity: vscode.DiagnosticSeverity.Hint,
            suggestion: 'Ensure SRI is used for all external scripts'
        },
        {
            pattern: /<!ENTITY/gi,
            message: '🔧 A08: XXE - XML external entity declaration',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Disable external entities in XML parser'
        },
        {
            pattern: /LIBXML_NOENT|resolveExternals\s*[=:]\s*true/gi,
            message: '🔧 A08: XXE - External entities enabled',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Disable external entity resolution'
        },

        // ============================================================
        // A09:2021 - SECURITY LOGGING AND MONITORING FAILURES
        // ============================================================
        {
            pattern: /console\.log\s*\(.*password|console\.log\s*\(.*token|console\.log\s*\(.*secret/gi,
            message: '📋 A09: Sensitive data logged to console',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never log passwords, tokens, or secrets'
        },
        {
            pattern: /print\s*\(.*password|print\s*\(.*token|logger.*password|log\..*password/gi,
            message: '📋 A09: Sensitive data in logs',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Mask or redact sensitive data in logs'
        },
        {
            pattern: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}|except.*pass\s*$/gim,
            message: '📋 A09: Empty catch block - errors silently ignored',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Log exceptions for debugging and monitoring'
        },
        {
            pattern: /logging\.disable|logger\.disabled\s*=\s*True/gi,
            message: '📋 A09: Logging disabled',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Enable logging for security monitoring'
        },
        {
            pattern: /alert\s*\(|console\.error.*stack/gi,
            message: '📋 A09: Error details may be exposed to users',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Show generic errors to users, log details internally'
        },

        // ============================================================
        // A10:2021 - SERVER-SIDE REQUEST FORGERY (SSRF)
        // ============================================================
        {
            pattern: /requests\.get\s*\(\s*\w+|fetch\s*\(\s*\w+[^'"`]|urllib\.request\.urlopen\s*\(\s*\w+/gi,
            message: '🌐 A10: SSRF - URL from variable may be user-controlled',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Validate and whitelist allowed URLs/domains'
        },
        {
            pattern: /HttpClient.*getString\s*\(\s*\w+|WebClient.*downloadString\s*\(\s*\w+/gi,
            message: '🌐 A10: SSRF - HTTP request with dynamic URL',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Validate URLs against allowlist'
        },
        {
            pattern: /curl_setopt.*CURLOPT_URL.*\$/gi,
            message: '🌐 A10: SSRF - PHP cURL with dynamic URL',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Validate and sanitize URLs before requests'
        },
        {
            pattern: /file_get_contents\s*\(\s*\$|fopen\s*\(\s*\$/gi,
            message: '🌐 A10: SSRF/LFI - PHP file functions with variable',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never pass user input directly to file functions'
        },
        {
            pattern: /127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\./gi,
            message: '🌐 A10: Internal IP address detected',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Ensure internal addresses cannot be reached via SSRF'
        },
        {
            pattern: /file:\/\/|gopher:\/\/|dict:\/\/|ldap:\/\//gi,
            message: '🌐 A10: Dangerous URL scheme detected',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Only allow http:// and https:// schemes'
        },

        // ============================================================
        // PATH TRAVERSAL / LFI / RFI
        // ============================================================
        {
            pattern: /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\//gi,
            message: '📂 Path Traversal pattern detected',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Sanitize file paths, use path.resolve() and verify within allowed directory'
        },
        {
            pattern: /include\s*\(\s*\$|require\s*\(\s*\$|include_once\s*\(\s*\$|require_once\s*\(\s*\$/gi,
            message: '📂 LFI/RFI - PHP include with variable',
            severity: vscode.DiagnosticSeverity.Error,
            suggestion: 'Never use user input in include/require statements'
        },
        {
            pattern: /open\s*\(\s*\w+[^'"`].*['"]\s*\)|fs\.readFile\s*\(\s*\w+/gi,
            message: '📂 File operation with dynamic path',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Validate paths are within allowed directories'
        },

        // ============================================================
        // MASS ASSIGNMENT / OVER-POSTING
        // ============================================================
        {
            pattern: /Object\.assign\s*\(\s*\w+\s*,\s*req\.body|\.create\s*\(\s*req\.body\s*\)|\.update\s*\(\s*req\.body/gi,
            message: '📝 Mass Assignment - directly using request body',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Whitelist allowed fields, never pass raw request body'
        },
        {
            pattern: /\*\*request\.(POST|GET|data)|form\.populate_obj/gi,
            message: '📝 Mass Assignment - spreading request data',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Explicitly specify which fields to update'
        },
        {
            pattern: /attr_accessible|attr_protected/gi,
            message: '📝 Rails mass assignment protection',
            severity: vscode.DiagnosticSeverity.Information,
            suggestion: 'Use strong parameters instead in Rails 4+'
        },

        // ============================================================
        // RACE CONDITIONS
        // ============================================================
        {
            pattern: /check.*then.*use|toctou|if.*exists.*then/gi,
            message: '⏱️ Potential TOCTOU race condition',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use atomic operations or proper locking'
        },
        {
            pattern: /balance.*-=|inventory.*-=|stock.*-=/gi,
            message: '⏱️ Non-atomic decrement - potential race condition',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Use database transactions or atomic operations'
        },

        // ============================================================
        // REGEX DoS (ReDoS)
        // ============================================================
        {
            pattern: /\(\.\*\)\+|\(\.\+\)\*|\(\[.*\]\+\)\+/gi,
            message: '💣 ReDoS - catastrophic backtracking regex pattern',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Simplify regex, add length limits, or use RE2'
        },
        {
            pattern: /new\s+RegExp\s*\(\s*\w+|re\.compile\s*\(\s*\w+/gi,
            message: '💣 Dynamic regex from variable - potential ReDoS',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Validate regex complexity and add timeout'
        },

        // ============================================================
        // OPEN REDIRECT
        // ============================================================
        {
            pattern: /redirect\s*\(\s*req\.|res\.redirect\s*\(\s*req\.|header\s*\(\s*['"]Location.*\$/gi,
            message: '↪️ Open Redirect - redirecting to user-controlled URL',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Validate redirect URLs against allowlist'
        },
        {
            pattern: /window\.location\s*=\s*\w+|location\.href\s*=\s*\w+/gi,
            message: '↪️ Client-side redirect with variable',
            severity: vscode.DiagnosticSeverity.Warning,
            suggestion: 'Validate URLs before redirecting'
        }
    ];

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const codeActions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source === 'appsec-inline') {
                const fix = this.createFix(document, range, diagnostic);
                if (fix) {
                    codeActions.push(fix);
                }
            }
        }

        return codeActions;
    }

    private createFix(
        document: vscode.TextDocument,
        range: vscode.Range,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction | undefined {
        const fix = new vscode.CodeAction(
            'View security suggestion',
            vscode.CodeActionKind.QuickFix
        );
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;

        return fix;
    }

    public analyzeLine(line: string, lineNumber: number): vscode.Diagnostic[] {
        const diagnostics: vscode.Diagnostic[] = [];

        for (const pattern of this.securityPatterns) {
            const matches = line.matchAll(pattern.pattern);
            for (const match of matches) {
                if (match.index !== undefined) {
                    const start = new vscode.Position(lineNumber, match.index);
                    const end = new vscode.Position(lineNumber, match.index + match[0].length);
                    const range = new vscode.Range(start, end);

                    const diagnostic = new vscode.Diagnostic(
                        range,
                        `${pattern.message}\n💡 ${pattern.suggestion}`,
                        pattern.severity
                    );
                    diagnostic.source = 'appsec-inline';
                    diagnostic.code = 'security-pattern';

                    diagnostics.push(diagnostic);
                }
            }
        }

        return diagnostics;
    }

    public analyzeDocument(document: vscode.TextDocument): vscode.Diagnostic[] {
        const diagnostics: vscode.Diagnostic[] = [];

        for (let i = 0; i < document.lineCount; i++) {
            const line = document.lineAt(i).text;
            const lineDiagnostics = this.analyzeLine(line, i);
            diagnostics.push(...lineDiagnostics);
        }

        return diagnostics;
    }
}
