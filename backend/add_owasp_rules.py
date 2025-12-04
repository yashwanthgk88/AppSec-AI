"""Add comprehensive OWASP Top 10 rules for Web, API, and Mobile"""
import sqlite3

conn = sqlite3.connect('appsec.db')
cursor = conn.cursor()

# OWASP Top 10 Web Application Security Risks (2021)
web_rules = [
    # A01:2021 - Broken Access Control
    ('Insecure Direct Object Reference', r'(\/api\/.*\/\d+|userId\s*=\s*\d+|id\s*=\s*["\']?\d+)', 'high', 'Detects potential IDOR vulnerabilities with direct object references', '*', 'CWE-639', 'A01:2021 - Broken Access Control', 'Implement proper authorization checks before accessing resources', 1, 'system', 'user'),
    ('Missing Authorization Check', r'(def\s+delete|function\s+delete|\.delete\(|\.remove\(|DELETE\s+FROM)(?!.*(?:authorize|check_permission|has_permission|require_auth))', 'high', 'Detects delete operations without authorization checks', '*', 'CWE-862', 'A01:2021 - Broken Access Control', 'Add authorization checks before delete operations', 1, 'system', 'user'),
    ('Path Traversal', r'\.\.[/\\]|\.\.%2[fF]|%2[eE]%2[eE][/\\]', 'critical', 'Detects directory traversal attempts', '*', 'CWE-22', 'A01:2021 - Broken Access Control', 'Validate and sanitize file paths, use allowlists', 1, 'system', 'user'),

    # A02:2021 - Cryptographic Failures
    ('Weak Encryption Algorithm', r'(DES|RC4|MD5|SHA1)(?!.*deprecated)', 'high', 'Detects use of weak cryptographic algorithms', '*', 'CWE-327', 'A02:2021 - Cryptographic Failures', 'Use strong algorithms like AES-256, SHA-256 or better', 1, 'system', 'user'),
    ('Hardcoded Encryption Key', r'(key|secret|password)\s*=\s*["\'][a-zA-Z0-9+/=]{16,}["\']', 'critical', 'Detects hardcoded encryption keys', '*', 'CWE-321', 'A02:2021 - Cryptographic Failures', 'Store keys in secure key management systems', 1, 'system', 'user'),
    ('Insecure SSL/TLS Configuration', r'(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|verify\s*=\s*False|verify_ssl\s*=\s*False)', 'high', 'Detects insecure SSL/TLS configurations', '*', 'CWE-326', 'A02:2021 - Cryptographic Failures', 'Use TLS 1.2+ and enable certificate verification', 1, 'system', 'user'),

    # A03:2021 - Injection
    ('SQL Injection', r'(execute|query|raw)\s*\([^)]*(\+|%|\bformat\b|f["\']).*\b(SELECT|INSERT|UPDATE|DELETE)\b', 'critical', 'Detects potential SQL injection vulnerabilities', '*', 'CWE-89', 'A03:2021 - Injection', 'Use parameterized queries or ORMs', 1, 'system', 'user'),
    ('NoSQL Injection', r'\$where|\$ne|\$gt|\$regex|query\s*\([^)]*\+', 'high', 'Detects potential NoSQL injection', '*', 'CWE-943', 'A03:2021 - Injection', 'Validate and sanitize all inputs, use parameterized queries', 1, 'system', 'user'),
    ('LDAP Injection', r'(objectClass|cn|uid|ou)\s*=.*[*()&|]', 'high', 'Detects potential LDAP injection', '*', 'CWE-90', 'A03:2021 - Injection', 'Escape special LDAP characters in user input', 1, 'system', 'user'),
    ('XML External Entity (XXE)', r'(<!ENTITY|SYSTEM\s+["\']|<!DOCTYPE.*\[)', 'critical', 'Detects potential XXE vulnerabilities', '*', 'CWE-611', 'A03:2021 - Injection', 'Disable external entity processing in XML parsers', 1, 'system', 'user'),
    ('Template Injection', r'(render_template_string|Jinja2|{{.*}}|\${.*}|<%.*%>).*request\.|template\([^)]*\+', 'critical', 'Detects server-side template injection', '*', 'CWE-94', 'A03:2021 - Injection', 'Never pass user input directly to template engines', 1, 'system', 'user'),

    # A04:2021 - Insecure Design
    ('Unlimited Resource Consumption', r'(while\s*\(\s*true\)|for\s*\(\s*;;\s*\)|recursion)(?!.*limit|timeout)', 'medium', 'Detects potential infinite loops without limits', '*', 'CWE-400', 'A04:2021 - Insecure Design', 'Implement rate limiting and resource quotas', 1, 'system', 'user'),

    # A05:2021 - Security Misconfiguration
    ('Debug Mode Enabled', r'(DEBUG\s*=\s*True|debug\s*=\s*true|development\s*mode)', 'high', 'Detects debug mode enabled in production', '*', 'CWE-11', 'A05:2021 - Security Misconfiguration', 'Disable debug mode in production', 1, 'system', 'user'),
    ('Default Credentials', r'(password|passwd|pwd)\s*[:=]\s*["\']?(admin|password|12345|root)["\']?', 'critical', 'Detects default or common passwords', '*', 'CWE-798', 'A05:2021 - Security Misconfiguration', 'Use strong, unique credentials', 1, 'system', 'user'),
    ('Permissive CORS Policy', r'Access-Control-Allow-Origin\s*:\s*\*', 'medium', 'Detects overly permissive CORS configuration', '*', 'CWE-942', 'A05:2021 - Security Misconfiguration', 'Restrict CORS to specific trusted origins', 1, 'system', 'user'),

    # A06:2021 - Vulnerable and Outdated Components
    ('Outdated Dependency', r'(jquery|angular|react)@[0-9]\.|<script.*jquery-1\.|bootstrap.*[23]\.', 'medium', 'Detects potentially outdated JavaScript libraries', 'javascript', 'CWE-1104', 'A06:2021 - Vulnerable and Outdated Components', 'Keep dependencies updated regularly', 1, 'system', 'user'),

    # A07:2021 - Identification and Authentication Failures
    ('Weak Password Policy', r'password\.length\s*[<>=]+\s*[1-7]\b|min_length\s*=\s*[1-7]\b', 'high', 'Detects weak password length requirements', '*', 'CWE-521', 'A07:2021 - Identification and Authentication Failures', 'Enforce minimum 8+ character passwords with complexity', 1, 'system', 'user'),
    ('Missing Password Hashing', r'password\s*=\s*request\.|password\s*=.*input(?!.*hash|bcrypt|pbkdf2|scrypt|argon2)', 'critical', 'Detects passwords stored without hashing', '*', 'CWE-256', 'A07:2021 - Identification and Authentication Failures', 'Use bcrypt, scrypt, or Argon2 for password hashing', 1, 'system', 'user'),
    ('JWT Without Expiration', r'jwt\.encode\((?!.*exp\b|expir)', 'medium', 'Detects JWT tokens without expiration', '*', 'CWE-613', 'A07:2021 - Identification and Authentication Failures', 'Set expiration time for JWT tokens', 1, 'system', 'user'),
    ('Session Fixation', r'session\.regenerate\(|session_regenerate_id\((?!.*true\))', 'high', 'Detects missing session regeneration after authentication', '*', 'CWE-384', 'A07:2021 - Identification and Authentication Failures', 'Regenerate session ID after successful login', 1, 'system', 'user'),

    # A08:2021 - Software and Data Integrity Failures
    ('Insecure Deserialization', r'(pickle\.loads|yaml\.load|unserialize|eval|json\.loads)(?!.*safe)', 'critical', 'Detects insecure deserialization', '*', 'CWE-502', 'A08:2021 - Software and Data Integrity Failures', 'Use safe deserialization methods and validate data', 1, 'system', 'user'),
    ('Missing Integrity Check', r'(npm install|pip install|apt-get install)(?!.*--verify|--check)', 'medium', 'Detects package installation without integrity verification', '*', 'CWE-494', 'A08:2021 - Software and Data Integrity Failures', 'Use lock files and verify package integrity', 1, 'system', 'user'),

    # A09:2021 - Security Logging and Monitoring Failures
    ('Logging Sensitive Data', r'log.*\b(password|secret|token|api_key|credit_card)\b', 'high', 'Detects logging of sensitive information', '*', 'CWE-532', 'A09:2021 - Security Logging and Monitoring Failures', 'Avoid logging sensitive data, use masking', 1, 'system', 'user'),
    ('Missing Error Logging', r'except\s*:(?!.*log|print|raise)', 'low', 'Detects exception handling without logging', 'python', 'CWE-778', 'A09:2021 - Security Logging and Monitoring Failures', 'Log all exceptions for monitoring', 1, 'system', 'user'),

    # A10:2021 - Server-Side Request Forgery (SSRF)
    ('SSRF Vulnerability', r'(requests\.get|urllib\.request|fetch|axios\.get)\s*\([^)]*request\.|url\s*=.*request\.', 'critical', 'Detects potential SSRF vulnerabilities', '*', 'CWE-918', 'A10:2021 - Server-Side Request Forgery', 'Validate and whitelist URLs, disable redirects', 1, 'system', 'user'),
]

# OWASP API Security Top 10 (2023)
api_rules = [
    # API1:2023 - Broken Object Level Authorization
    ('API Missing Object-Level Authorization', r'@(app\.route|api\.get|api\.post)\s*\(["\'][^"\']*\{id\}|:\w+id["\'][^)]*\)(?!.*@require|@auth|@permission)', 'critical', 'Detects API endpoints with path parameters lacking authorization', '*', 'CWE-639', 'API1:2023 - Broken Object Level Authorization', 'Implement object-level authorization checks', 1, 'system', 'user'),

    # API2:2023 - Broken Authentication
    ('API Key in URL', r'(api_key|apikey|key)\s*=\s*[a-zA-Z0-9]{20,}', 'high', 'Detects API keys in URLs', '*', 'CWE-598', 'API2:2023 - Broken Authentication', 'Use headers or secure storage for API keys', 1, 'system', 'user'),
    ('Missing API Rate Limiting', r'@(app\.route|api\.(get|post|put|delete))(?!.*rate_limit|throttle)', 'medium', 'Detects API endpoints without rate limiting', '*', 'CWE-770', 'API2:2023 - Broken Authentication', 'Implement rate limiting on all API endpoints', 1, 'system', 'user'),

    # API3:2023 - Broken Object Property Level Authorization
    ('Mass Assignment Vulnerability', r'(\.update\(|\.save\(|\.create\().*request\.(data|json|form)(?!.*whitelist|allowed_fields)', 'high', 'Detects mass assignment without field filtering', '*', 'CWE-915', 'API3:2023 - Broken Object Property Level Authorization', 'Use explicit field whitelists for updates', 1, 'system', 'user'),

    # API4:2023 - Unrestricted Resource Consumption
    ('No Pagination Limit', r'(\.all\(\)|\.findAll\(\)|SELECT \*)(?!.*LIMIT|limit\s*=|take\s*=)', 'medium', 'Detects database queries without pagination', '*', 'CWE-400', 'API4:2023 - Unrestricted Resource Consumption', 'Implement pagination and query limits', 1, 'system', 'user'),
    ('Large File Upload Without Limit', r'(upload|multipart)(?!.*max_size|size_limit|maxFileSize)', 'medium', 'Detects file uploads without size limits', '*', 'CWE-400', 'API4:2023 - Unrestricted Resource Consumption', 'Enforce file size limits', 1, 'system', 'user'),

    # API5:2023 - Broken Function Level Authorization
    ('Admin Endpoint Without Auth', r'(admin|internal|private).*@(app\.route|api\.(get|post))(?!.*@require_admin|@admin_required)', 'critical', 'Detects admin endpoints without proper authorization', '*', 'CWE-285', 'API5:2023 - Broken Function Level Authorization', 'Enforce role-based access control', 1, 'system', 'user'),

    # API6:2023 - Unrestricted Access to Sensitive Business Flows
    ('Missing CAPTCHA', r'(register|signup|login|contact).*@(app\.route|api\.post)(?!.*captcha|recaptcha)', 'medium', 'Detects forms without CAPTCHA protection', '*', 'CWE-841', 'API6:2023 - Unrestricted Access to Sensitive Business Flows', 'Implement CAPTCHA for sensitive operations', 1, 'system', 'user'),

    # API7:2023 - Server Side Request Forgery
    ('Webhook SSRF', r'webhook.*url.*request\.|callback.*url.*request\.', 'high', 'Detects webhook URLs from user input', '*', 'CWE-918', 'API7:2023 - Server Side Request Forgery', 'Validate webhook URLs against allowlist', 1, 'system', 'user'),

    # API8:2023 - Security Misconfiguration
    ('Verbose Error Messages', r'(return.*Exception|throw.*e\.getMessage|error.*stack)', 'medium', 'Detects verbose error messages', '*', 'CWE-209', 'API8:2023 - Security Misconfiguration', 'Return generic error messages to clients', 1, 'system', 'user'),

    # API9:2023 - Improper Inventory Management
    ('Undocumented API Endpoint', r'@(app\.route|api\.(get|post))\(["\'][^"\']*\/v[0-9]', 'low', 'Detects versioned API endpoints', '*', 'CWE-1059', 'API9:2023 - Improper Inventory Management', 'Document all API endpoints and versions', 1, 'system', 'user'),

    # API10:2023 - Unsafe Consumption of APIs
    ('Unvalidated API Response', r'(requests\.get|axios\.get|fetch)\([^)]*\)\.(?!.*validate|verify)', 'medium', 'Detects API responses used without validation', '*', 'CWE-20', 'API10:2023 - Unsafe Consumption of APIs', 'Validate all external API responses', 1, 'system', 'user'),
]

# OWASP Mobile Top 10 (2024)
mobile_rules = [
    # M1: Improper Credential Usage
    ('Hardcoded API Endpoint', r'(http://|https://)[a-zA-Z0-9.-]+\.(com|net|org|io)', 'medium', 'Detects hardcoded API endpoints', '*', 'CWE-798', 'M1:2024 - Improper Credential Usage', 'Use configuration files or environment variables', 1, 'system', 'user'),
    ('Mobile API Key Hardcoded', r'(apiKey|api_key|API_KEY)\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']', 'critical', 'Detects hardcoded mobile API keys', 'java,kotlin,swift,dart', 'CWE-798', 'M1:2024 - Improper Credential Usage', 'Use secure storage like Keychain/KeyStore', 1, 'system', 'user'),

    # M2: Inadequate Supply Chain Security
    ('Outdated Mobile SDK', r'(compileSdkVersion|targetSdkVersion|platform\s*:ios)\s+["\']?([0-9]|1[0-9]|2[0-5])["\']?', 'medium', 'Detects potentially outdated mobile SDKs', 'java,kotlin,swift', 'CWE-1104', 'M2:2024 - Inadequate Supply Chain Security', 'Keep SDKs and dependencies updated', 1, 'system', 'user'),

    # M3: Insecure Authentication/Authorization
    ('Biometric Auth Without Fallback', r'(BiometricPrompt|LocalAuthentication)(?!.*fallback|password)', 'medium', 'Detects biometric auth without secure fallback', 'java,kotlin,swift', 'CWE-287', 'M3:2024 - Insecure Authentication/Authorization', 'Implement secure fallback authentication', 1, 'system', 'user'),
    ('Root Detection Missing', r'(MainActivity|AppDelegate)(?!.*root_check|jailbreak_check)', 'low', 'Detects missing root/jailbreak detection', 'java,kotlin,swift', 'CWE-919', 'M3:2024 - Insecure Authentication/Authorization', 'Implement root/jailbreak detection', 1, 'system', 'user'),

    # M4: Insufficient Input/Output Validation
    ('WebView XSS', r'WebView.*loadUrl\(.*\+|evaluateJavascript\(.*\+', 'high', 'Detects potential XSS in WebView', 'java,kotlin,swift', 'CWE-79', 'M4:2024 - Insufficient Input/Output Validation', 'Sanitize all data passed to WebView', 1, 'system', 'user'),
    ('Deep Link Validation Missing', r'(intent\.getData|openURL|handleOpenURL)(?!.*validate|verify|whitelist)', 'high', 'Detects deep links without validation', 'java,kotlin,swift', 'CWE-939', 'M4:2024 - Insufficient Input/Output Validation', 'Validate all deep link parameters', 1, 'system', 'user'),

    # M5: Insecure Communication
    ('Cleartext HTTP Traffic', r'http://(?!localhost|127\.0\.0\.1)', 'high', 'Detects cleartext HTTP traffic', '*', 'CWE-319', 'M5:2024 - Insecure Communication', 'Use HTTPS for all network communication', 1, 'system', 'user'),
    ('Certificate Pinning Missing', r'(URLSession|OkHttpClient)(?!.*certificatePinner|pinning)', 'medium', 'Detects missing certificate pinning', 'swift,java,kotlin', 'CWE-295', 'M5:2024 - Insecure Communication', 'Implement certificate pinning', 1, 'system', 'user'),

    # M6: Inadequate Privacy Controls
    ('Sensitive Data in Logs', r'(Log\.[dive]|NSLog|print)\s*\([^)]*\b(password|token|ssn|credit_card)\b', 'high', 'Detects sensitive data in mobile logs', 'java,kotlin,swift,dart', 'CWE-532', 'M6:2024 - Inadequate Privacy Controls', 'Remove sensitive data from logs', 1, 'system', 'user'),
    ('Clipboard Data Exposure', r'(UIPasteboard|ClipboardManager)\.set.*sensitive|password|token', 'medium', 'Detects sensitive data in clipboard', 'swift,java,kotlin', 'CWE-200', 'M6:2024 - Inadequate Privacy Controls', 'Avoid copying sensitive data to clipboard', 1, 'system', 'user'),

    # M7: Insufficient Binary Protections
    ('Debuggable App', r'android:debuggable\s*=\s*["\']?true["\']?', 'high', 'Detects debuggable Android app', 'xml', 'CWE-11', 'M7:2024 - Insufficient Binary Protections', 'Disable debugging in production builds', 1, 'system', 'user'),
    ('Code Obfuscation Missing', r'minifyEnabled\s*=\s*false|obfuscate\s*=\s*false', 'medium', 'Detects missing code obfuscation', 'java,kotlin', 'CWE-656', 'M7:2024 - Insufficient Binary Protections', 'Enable ProGuard/R8 for release builds', 1, 'system', 'user'),

    # M8: Security Misconfiguration
    ('Insecure File Permissions', r'chmod.*777|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', 'high', 'Detects insecure file permissions', 'java,kotlin,swift', 'CWE-732', 'M8:2024 - Security Misconfiguration', 'Use restrictive file permissions', 1, 'system', 'user'),
    ('Backup Allowed', r'android:allowBackup\s*=\s*["\']?true["\']?', 'medium', 'Detects backup enabled for sensitive data', 'xml', 'CWE-530', 'M8:2024 - Security Misconfiguration', 'Disable backup for sensitive applications', 1, 'system', 'user'),

    # M9: Insecure Data Storage
    ('SharedPreferences Unencrypted', r'getSharedPreferences\((?!.*MODE_PRIVATE|EncryptedSharedPreferences)', 'high', 'Detects unencrypted SharedPreferences', 'java,kotlin', 'CWE-311', 'M9:2024 - Insecure Data Storage', 'Use EncryptedSharedPreferences', 1, 'system', 'user'),
    ('SQLite Database Unencrypted', r'SQLiteOpenHelper|SQLiteDatabase(?!.*encrypt|cipher)', 'high', 'Detects unencrypted SQLite database', 'java,kotlin', 'CWE-311', 'M9:2024 - Insecure Data Storage', 'Use SQLCipher for database encryption', 1, 'system', 'user'),
    ('Keychain Without Access Control', r'kSecAttrAccessible.*kSecAttrAccessibleAlways', 'medium', 'Detects Keychain without proper access control', 'swift', 'CWE-522', 'M9:2024 - Insecure Data Storage', 'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly', 1, 'system', 'user'),

    # M10: Insufficient Cryptography
    ('ECB Mode Encryption', r'(AES/ECB|Cipher\.getInstance\(["\']AES/ECB)', 'critical', 'Detects insecure ECB encryption mode', 'java,kotlin,swift', 'CWE-327', 'M10:2024 - Insufficient Cryptography', 'Use AES/GCM or AES/CBC with proper IV', 1, 'system', 'user'),
    ('Static IV for Encryption', r'(IvParameterSpec|CCCrypt).*["\'][0-9a-fA-F]{16,}["\']', 'high', 'Detects static initialization vectors', 'java,kotlin,swift', 'CWE-329', 'M10:2024 - Insufficient Cryptography', 'Generate random IV for each encryption', 1, 'system', 'user'),
]

# Additional common security issues
additional_rules = [
    # XSS
    ('DOM-based XSS', r'(innerHTML|outerHTML|document\.write)\s*=.*\+|\.html\(.*\+', 'high', 'Detects potential DOM-based XSS', 'javascript', 'CWE-79', 'A03:2021 - Injection', 'Use textContent or sanitize HTML input', 1, 'system', 'user'),
    ('Reflected XSS', r'(echo|print|render)\s*.*\$_(GET|POST|REQUEST)|response\.write\(request\.', 'critical', 'Detects potential reflected XSS', '*', 'CWE-79', 'A03:2021 - Injection', 'Sanitize and encode all user input', 1, 'system', 'user'),

    # CSRF
    ('Missing CSRF Protection', r'@(app\.route|api\.post).*method.*POST(?!.*csrf|@csrf_protect)', 'medium', 'Detects POST endpoints without CSRF protection', '*', 'CWE-352', 'A01:2021 - Broken Access Control', 'Implement CSRF tokens', 1, 'system', 'user'),

    # Information Disclosure
    ('Sensitive Data in Error', r'(exception|error|throw).*\b(password|token|key|secret)\b', 'high', 'Detects sensitive data in error messages', '*', 'CWE-209', 'A09:2021 - Security Logging and Monitoring Failures', 'Sanitize error messages', 1, 'system', 'user'),
    ('Git Directory Exposed', r'\.git/|\.gitignore', 'low', 'Detects exposed .git directory references', '*', 'CWE-552', 'A05:2021 - Security Misconfiguration', 'Ensure .git is not publicly accessible', 1, 'system', 'user'),

    # Cryptography
    ('Weak Hash Function', r'\b(md5|sha1)\s*\(', 'medium', 'Detects use of weak hash functions', '*', 'CWE-328', 'A02:2021 - Cryptographic Failures', 'Use SHA-256 or stronger', 1, 'system', 'user'),
    ('Predictable Random', r'time\(\)|Date\.now\(\)|System\.currentTimeMillis\(\)', 'low', 'Detects predictable random seed', '*', 'CWE-338', 'A02:2021 - Cryptographic Failures', 'Use cryptographically secure random generators', 1, 'system', 'user'),

    # Cloud Security
    ('AWS S3 Bucket Public', r's3.*public-read|s3.*public-read-write', 'critical', 'Detects public S3 bucket ACL', '*', 'CWE-732', 'A05:2021 - Security Misconfiguration', 'Use private ACLs with IAM policies', 1, 'system', 'user'),
    ('GCP Public Storage', r'allUsers|allAuthenticatedUsers', 'critical', 'Detects public GCP storage access', '*', 'CWE-732', 'A05:2021 - Security Misconfiguration', 'Restrict storage access to specific users', 1, 'system', 'user'),

    # Container Security
    ('Docker Running as Root', r'USER root|RUN.*sudo', 'medium', 'Detects Docker container running as root', 'dockerfile', 'CWE-250', 'A05:2021 - Security Misconfiguration', 'Use non-root user in containers', 1, 'system', 'user'),
    ('Hardcoded Secrets in Dockerfile', r'ENV.*(PASSWORD|SECRET|KEY|TOKEN)\s*=\s*[a-zA-Z0-9]+', 'critical', 'Detects hardcoded secrets in Dockerfile', 'dockerfile', 'CWE-798', 'A02:2021 - Cryptographic Failures', 'Use Docker secrets or env variables at runtime', 1, 'system', 'user'),
]

# Combine all rules
all_rules = web_rules + api_rules + mobile_rules + additional_rules

# Insert rules
print(f"Adding {len(all_rules)} comprehensive OWASP security rules...")
inserted = 0
skipped = 0

for rule in all_rules:
    try:
        cursor.execute('''
            INSERT INTO custom_rules (name, pattern, severity, description, language, cwe, owasp, remediation, enabled, created_by, generated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', rule)
        inserted += 1
    except sqlite3.IntegrityError:
        # Rule already exists (duplicate name+language), skip
        skipped += 1

conn.commit()

# Print summary
cursor.execute("SELECT COUNT(*) FROM custom_rules")
total_rules = cursor.fetchone()[0]

cursor.execute("SELECT severity, COUNT(*) FROM custom_rules GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 END")
severity_counts = cursor.fetchall()

cursor.close()
conn.close()

print(f"\n✅ Successfully added {inserted} new rules")
print(f"⏭️  Skipped {skipped} duplicate rules")
print(f"📊 Total rules in database: {total_rules}")
print(f"\n📈 Rules by severity:")
for severity, count in severity_counts:
    print(f"   {severity.upper()}: {count}")

print("\n🎯 Coverage:")
print(f"   OWASP Web Top 10: {len(web_rules)} rules")
print(f"   OWASP API Top 10: {len(api_rules)} rules")
print(f"   OWASP Mobile Top 10: {len(mobile_rules)} rules")
print(f"   Additional Security: {len(additional_rules)} rules")
