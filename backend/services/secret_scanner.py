"""
Secret Scanner - Professional-grade credential and sensitive data detection
Detects hardcoded credentials, API keys, private keys, and sensitive data with entropy analysis
"""
import re
import math
import logging
from typing import List, Dict, Any, Set, Tuple, Optional
from collections import Counter
import os

logger = logging.getLogger(__name__)

class SecretScanner:
    """
    Enhanced secret scanner with entropy analysis and false positive reduction
    Features:
    - Shannon entropy calculation for high-entropy string detection
    - Context-aware validation to reduce false positives
    - Support for 50+ secret types
    - Confidence scoring
    - Comment and test file detection
    """

    # Comprehensive secret detection patterns organized by provider/type
    SECRET_PATTERNS = {
        # ==================== CLOUD PROVIDERS ====================
        "AWS Access Key ID": {
            "pattern": r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            "severity": "critical",
            "description": "AWS Access Key ID detected in source code",
            "remediation": "Remove AWS credentials from code. Use AWS IAM roles, AWS Secrets Manager, or environment variables.",
            "entropy_check": True,
            "min_entropy": 3.5
        },
        "AWS Secret Access Key": {
            "pattern": r'aws[_-]?secret[_-]?access[_-]?key[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
            "severity": "critical",
            "description": "AWS Secret Access Key detected",
            "remediation": "Revoke this key immediately in AWS console and use AWS Secrets Manager.",
            "entropy_check": True,
            "min_entropy": 4.5
        },
        "AWS Session Token": {
            "pattern": r'aws[_-]?session[_-]?token[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{100,})[\'"]?',
            "severity": "high",
            "description": "AWS Session Token detected",
            "remediation": "Remove temporary AWS credentials. Use IAM roles for EC2/Lambda.",
            "entropy_check": True,
            "min_entropy": 4.0
        },
        "Azure Storage Account Key": {
            "pattern": r'DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=([A-Za-z0-9+/=]{88});',
            "severity": "critical",
            "description": "Azure Storage Account connection string with key",
            "remediation": "Rotate Azure Storage key and use Azure Key Vault.",
            "entropy_check": True
        },
        "Azure Client Secret": {
            "pattern": r'azure[_-]?client[_-]?secret[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9~._-]{34,})[\'"]?',
            "severity": "critical",
            "description": "Azure Active Directory client secret",
            "remediation": "Revoke and rotate in Azure AD. Use managed identities where possible.",
            "entropy_check": True
        },
        "Google Cloud API Key": {
            "pattern": r'AIza[0-9A-Za-z_-]{35}',
            "severity": "high",
            "description": "Google Cloud Platform API key detected",
            "remediation": "Rotate this API key in GCP console and restrict API key scopes. Use Google Secret Manager.",
            "entropy_check": True,
            "min_entropy": 4.0
        },
        "Google OAuth Token": {
            "pattern": r'ya29\.[0-9A-Za-z_-]{50,}',
            "severity": "high",
            "description": "Google OAuth access token detected",
            "remediation": "Revoke token and implement proper OAuth flow.",
            "entropy_check": True
        },
        "GCP Service Account Key": {
            "pattern": r'"type":\s*"service_account".*?"private_key":\s*"-----BEGIN PRIVATE KEY-----',
            "severity": "critical",
            "description": "Google Cloud service account JSON key file",
            "remediation": "Delete service account key and use Workload Identity or metadata server.",
            "entropy_check": False
        },

        # ==================== VERSION CONTROL ====================
        "GitHub Personal Access Token": {
            "pattern": r'ghp_[0-9a-zA-Z]{36}',
            "severity": "critical",
            "description": "GitHub personal access token detected",
            "remediation": "Revoke this token immediately on GitHub and use GitHub Secrets for CI/CD. Enable token expiration.",
            "entropy_check": True,
            "min_entropy": 4.0
        },
        "GitHub OAuth Token": {
            "pattern": r'gho_[0-9a-zA-Z]{36}',
            "severity": "critical",
            "description": "GitHub OAuth access token",
            "remediation": "Revoke token in GitHub settings.",
            "entropy_check": True
        },
        "GitHub App Token": {
            "pattern": r'(ghu|ghs)_[0-9a-zA-Z]{36}',
            "severity": "critical",
            "description": "GitHub App token detected",
            "remediation": "Revoke GitHub App installation token.",
            "entropy_check": True
        },
        "GitLab Personal Access Token": {
            "pattern": r'glpat-[0-9a-zA-Z_-]{20}',
            "severity": "critical",
            "description": "GitLab personal access token",
            "remediation": "Revoke token in GitLab user settings.",
            "entropy_check": True
        },
        "Bitbucket App Password": {
            "pattern": r'BB[0-9A-Za-z_-]{22}',
            "severity": "high",
            "description": "Bitbucket app-specific password",
            "remediation": "Revoke app password in Bitbucket settings.",
            "entropy_check": True
        },

        # ==================== COMMUNICATION PLATFORMS ====================
        "Slack Bot Token": {
            "pattern": r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
            "severity": "high",
            "description": "Slack bot token detected",
            "remediation": "Revoke this Slack bot token and regenerate. Store in environment variables.",
            "entropy_check": True
        },
        "Slack Webhook URL": {
            "pattern": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}',
            "severity": "medium",
            "description": "Slack webhook URL exposed",
            "remediation": "Rotate webhook URL and store securely.",
            "entropy_check": False
        },
        "Discord Bot Token": {
            "pattern": r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
            "severity": "high",
            "description": "Discord bot token detected",
            "remediation": "Regenerate bot token in Discord developer portal.",
            "entropy_check": True
        },
        "Telegram Bot Token": {
            "pattern": r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',
            "severity": "high",
            "description": "Telegram bot API token",
            "remediation": "Revoke via @BotFather on Telegram.",
            "entropy_check": True
        },

        # ==================== PAYMENT PROCESSORS ====================
        "Stripe Live API Key": {
            "pattern": r'sk_live_[0-9a-zA-Z]{24,}',
            "severity": "critical",
            "description": "Stripe live API secret key detected - CRITICAL",
            "remediation": "Revoke immediately in Stripe dashboard. This exposes payment processing capabilities. Use environment variables and Stripe restricted keys.",
            "entropy_check": True,
            "min_entropy": 4.0
        },
        "Stripe Restricted API Key": {
            "pattern": r'rk_live_[0-9a-zA-Z]{24,}',
            "severity": "high",
            "description": "Stripe restricted API key",
            "remediation": "Rotate key and ensure proper permissions.",
            "entropy_check": True
        },
        "PayPal OAuth Token": {
            "pattern": r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            "severity": "critical",
            "description": "PayPal OAuth token",
            "remediation": "Revoke in PayPal developer dashboard.",
            "entropy_check": False
        },
        "Square Access Token": {
            "pattern": r'sq0atp-[0-9A-Za-z_-]{22}',
            "severity": "critical",
            "description": "Square access token",
            "remediation": "Revoke in Square developer dashboard.",
            "entropy_check": True
        },

        # ==================== DATABASES ====================
        "Database Connection String": {
            "pattern": r'(mongodb(\+srv)?|mysql|postgresql|postgres|redis):\/\/[^\s:]+:[^\s@]+@[^\s\/]+',
            "severity": "critical",
            "description": "Database connection string with embedded credentials",
            "remediation": "Remove credentials from connection strings. Use connection pooling with external credential stores.",
            "entropy_check": False
        },
        "Database Password": {
            "pattern": r'(db[_-]?password|database[_-]?password|mysql[_-]?password|postgres[_-]?password|mongodb[_-]?password)[\'"]?\s*[:=]\s*[\'"]([^\'"\s]{6,})[\'"]',
            "severity": "critical",
            "description": "Database password hardcoded in source code",
            "remediation": "Use environment variables, AWS RDS IAM auth, or secrets manager. Rotate the exposed password.",
            "entropy_check": True,
            "min_entropy": 2.5
        },
        "Redis Password": {
            "pattern": r'redis[_-]?password[\'"]?\s*[:=]\s*[\'"]([^\'"\s]{6,})[\'"]',
            "severity": "high",
            "description": "Redis password in code",
            "remediation": "Use Redis AUTH with environment variables.",
            "entropy_check": True
        },

        # ==================== CRYPTOGRAPHIC KEYS ====================
        "RSA Private Key": {
            "pattern": r'-----BEGIN RSA PRIVATE KEY-----',
            "severity": "critical",
            "description": "RSA private key detected in source code",
            "remediation": "Remove private key immediately and rotate. Store in secure key management system (AWS KMS, Azure Key Vault, HashiCorp Vault).",
            "entropy_check": False
        },
        "EC Private Key": {
            "pattern": r'-----BEGIN EC PRIVATE KEY-----',
            "severity": "critical",
            "description": "Elliptic Curve private key found",
            "remediation": "Remove and rotate EC key. Use hardware security modules.",
            "entropy_check": False
        },
        "OpenSSH Private Key": {
            "pattern": r'-----BEGIN OPENSSH PRIVATE KEY-----',
            "severity": "critical",
            "description": "SSH private key found in code",
            "remediation": "Remove key and regenerate SSH keys. Use SSH agent and proper key management.",
            "entropy_check": False
        },
        "PGP Private Key": {
            "pattern": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            "severity": "critical",
            "description": "PGP/GPG private key detected",
            "remediation": "Remove private key and revoke if compromised.",
            "entropy_check": False
        },
        "Certificate Private Key": {
            "pattern": r'-----BEGIN (DSA |EC |)PRIVATE KEY-----',
            "severity": "critical",
            "description": "SSL/TLS certificate private key",
            "remediation": "Revoke certificate and generate new keypair.",
            "entropy_check": False
        },

        # ==================== API KEYS & TOKENS ====================
        "Generic API Key": {
            "pattern": r'api[_-]?key[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9_\-]{20,})[\'"]',
            "severity": "high",
            "description": "API key hardcoded in source code",
            "remediation": "Store API keys in environment variables, AWS Secrets Manager, or secret management systems.",
            "entropy_check": True,
            "min_entropy": 3.5
        },
        "Generic Secret Key": {
            "pattern": r'(secret|token|auth)[_-]?key[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9_\-]{16,})[\'"]',
            "severity": "high",
            "description": "Secret key or authentication token hardcoded",
            "remediation": "Use environment variables or secure vault services (HashiCorp Vault, AWS Secrets Manager).",
            "entropy_check": True,
            "min_entropy": 3.0
        },
        "Bearer Token": {
            "pattern": r'bearer\s+[a-zA-Z0-9_\-\.]{20,}',
            "severity": "high",
            "description": "Bearer token found in code",
            "remediation": "Remove hardcoded tokens and implement proper authentication flow.",
            "entropy_check": True
        },
        "JWT Token": {
            "pattern": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            "severity": "high",
            "description": "JSON Web Token (JWT) hardcoded",
            "remediation": "Remove hardcoded JWT. Implement proper token generation and secure storage.",
            "entropy_check": True,
            "min_entropy": 4.0
        },
        "OAuth Client Secret": {
            "pattern": r'client[_-]?secret[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9_\-]{20,})[\'"]',
            "severity": "critical",
            "description": "OAuth client secret exposed",
            "remediation": "Rotate OAuth credentials and use backend-only OAuth flows.",
            "entropy_check": True
        },

        # ==================== CLOUD SERVICES ====================
        "Twilio API Key": {
            "pattern": r'SK[a-z0-9]{32}',
            "severity": "high",
            "description": "Twilio API key",
            "remediation": "Revoke in Twilio console and use environment variables.",
            "entropy_check": True
        },
        "SendGrid API Key": {
            "pattern": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            "severity": "high",
            "description": "SendGrid API key detected",
            "remediation": "Revoke in SendGrid dashboard.",
            "entropy_check": True
        },
        "Mailgun API Key": {
            "pattern": r'key-[a-zA-Z0-9]{32}',
            "severity": "high",
            "description": "Mailgun API key",
            "remediation": "Rotate in Mailgun control panel.",
            "entropy_check": True
        },
        "Heroku API Key": {
            "pattern": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            "severity": "high",
            "description": "Heroku API key (UUID format)",
            "remediation": "Regenerate API key in Heroku account settings.",
            "entropy_check": False
        },
        "DigitalOcean Personal Access Token": {
            "pattern": r'dop_v1_[a-f0-9]{64}',
            "severity": "critical",
            "description": "DigitalOcean personal access token",
            "remediation": "Revoke in DigitalOcean API settings.",
            "entropy_check": True
        },
        "Cloudflare API Key": {
            "pattern": r'cloudflare[_-]?api[_-]?key[\'"]?\s*[:=]\s*[\'"]?([a-z0-9]{37})[\'"]?',
            "severity": "high",
            "description": "Cloudflare API key detected",
            "remediation": "Verify and rotate if confirmed. Use scoped API tokens.",
            "entropy_check": True,
            "min_entropy": 4.5
        },

        # ==================== CI/CD & DEVOPS ====================
        "NPM Token": {
            "pattern": r'npm_[A-Za-z0-9]{36}',
            "severity": "high",
            "description": "NPM access token",
            "remediation": "Revoke token at npmjs.com and use .npmrc with environment variables.",
            "entropy_check": True
        },
        "PyPI Token": {
            "pattern": r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}',
            "severity": "high",
            "description": "PyPI API token",
            "remediation": "Revoke in PyPI account settings.",
            "entropy_check": True
        },
        "Docker Hub Token": {
            "pattern": r'dckr_pat_[a-zA-Z0-9_-]{36}',
            "severity": "high",
            "description": "Docker Hub personal access token",
            "remediation": "Revoke in Docker Hub security settings.",
            "entropy_check": True
        },

        # ==================== SENSITIVE DATA ====================
        "Email Address": {
            "pattern": r'(email|contact|admin|user_email|customer_email)\s*[:=]\s*[\'"]([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\'"]',
            "severity": "info",
            "description": "Hardcoded email address found (potential PII)",
            "remediation": "Consider if email exposure is necessary. May violate GDPR/privacy regulations. Use data anonymization.",
            "entropy_check": False,
            "false_positive_check": True
        },
        "IPv4 Address": {
            "pattern": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            "severity": "low",
            "description": "IP address hardcoded",
            "remediation": "Use configuration files, service discovery, or DNS instead of hardcoded IPs.",
            "entropy_check": False,
            "false_positive_check": True
        },
        "Credit Card Number": {
            "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            "severity": "critical",
            "description": "Potential credit card number detected - PCI DSS violation",
            "remediation": "NEVER store credit card numbers in code or logs. Use PCI-compliant payment processors (Stripe, PayPal) with tokenization.",
            "entropy_check": False
        },
        "Social Security Number": {
            "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
            "severity": "critical",
            "description": "Potential US Social Security Number (SSN)",
            "remediation": "Remove immediately. This is highly sensitive PII. Implement encryption and access controls.",
            "entropy_check": False
        },
        "Phone Number": {
            "pattern": r'(\+1|1)?[-.\s]?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
            "severity": "low",
            "description": "Phone number detected (PII)",
            "remediation": "Consider data minimization and privacy requirements.",
            "entropy_check": False,
            "false_positive_check": True
        },

        # ==================== HIGH ENTROPY STRINGS ====================
        "High Entropy String": {
            "pattern": r'(secret|key|token|password|credential)\s*[:=]\s*[\'"]([a-zA-Z0-9+/=_-]{32,})[\'"]',
            "severity": "medium",
            "description": "High entropy string detected - potential secret",
            "remediation": "Verify if this is a secret. If yes, move to secure storage.",
            "entropy_check": True,
            "min_entropy": 5.0,
            "false_positive_check": True
        },
    }

    # Known false positive patterns
    FALSE_POSITIVE_PATTERNS = {
        # Common variable names
        "example", "sample", "test", "demo", "placeholder", "dummy", "fake",
        "mock", "your_api_key", "your_secret", "insert_key_here", "replace_me",
        # Common placeholders
        "xxxx", "****", "0000", "1111", "1234567890", "abcdefgh",
        # Documentation examples
        "sk_test_", "pk_test_", "AKIA00000000",
        # Common UUIDs in examples
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        # Version numbers and hashes that might look like secrets
        "sha256", "md5", "base64",
    }

    def __init__(self, ai_impact_service=None, ai_impact_enabled: bool = True):
        """
        Initialize the secret scanner

        Args:
            ai_impact_service: Optional AI impact service for dynamic impact generation
            ai_impact_enabled: Whether to use AI for impact generation (default True)
        """
        self.scanned_files = 0
        self.skipped_files = 0
        self.errors = []
        self.false_positives_filtered = 0

        # AI Impact Service configuration
        self.ai_impact_service = ai_impact_service
        self.ai_impact_enabled = ai_impact_enabled

    def calculate_shannon_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string
        Higher entropy = more randomness = more likely to be a secret

        Returns: Entropy value (typically 0-8 for base-256)
        """
        if not string:
            return 0.0

        # Count frequency of each character
        entropy = 0.0
        counter = Counter(string)
        length = len(string)

        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def is_false_positive(self, value: str, context: str = "") -> bool:
        """
        Check if detected value is likely a false positive

        Args:
            value: The detected secret value
            context: Surrounding code context

        Returns:
            True if likely false positive
        """
        value_lower = value.lower()

        # Check against known false positive patterns
        for fp_pattern in self.FALSE_POSITIVE_PATTERNS:
            if fp_pattern in value_lower:
                return True

        # Check if in comment
        if any(marker in context for marker in ['//', '#', '/*', '*/', '<!--', '-->']):
            return True

        # Check if in test file
        context_lower = context.lower()
        if any(test_marker in context_lower for test_marker in ['test', 'spec', 'mock', 'fixture', 'example']):
            return True

        # Check for repeating patterns (likely not real secrets)
        if len(set(value)) < len(value) // 4:  # Less than 25% unique characters
            return True

        return False

    def is_in_comment(self, line: str) -> bool:
        """Check if line is a comment"""
        stripped = line.strip()
        comment_markers = ['#', '//', '/*', '*', '*/', '<!--', '-->', "'''", '"""']
        return any(stripped.startswith(marker) for marker in comment_markers)

    def is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file"""
        test_indicators = ['test', 'spec', '__tests__', 'tests/', 'test_', '_test', 'mock', 'fixture']
        file_lower = file_path.lower()
        return any(indicator in file_lower for indicator in test_indicators)

    def calculate_confidence(self, secret_info: Dict, value: str, context: str, file_path: str) -> str:
        """
        Calculate confidence level for detection

        Returns: 'high', 'medium', or 'low'
        """
        confidence_score = 100

        # Reduce confidence for test files
        if self.is_test_file(file_path):
            confidence_score -= 30

        # Reduce confidence for comments
        if self.is_in_comment(context):
            confidence_score -= 25

        # Check entropy if required
        if secret_info.get('entropy_check', False):
            entropy = self.calculate_shannon_entropy(value)
            min_entropy = secret_info.get('min_entropy', 3.0)

            if entropy < min_entropy:
                confidence_score -= 40
            elif entropy < min_entropy + 0.5:
                confidence_score -= 20

        # Check for false positives
        if secret_info.get('false_positive_check', False):
            if self.is_false_positive(value, context):
                confidence_score -= 50

        # Map score to confidence level
        if confidence_score >= 70:
            return 'high'
        elif confidence_score >= 40:
            return 'medium'
        else:
            return 'low'

    def scan_code(self, code_content: str, file_path: str = "unknown") -> List[Dict[str, Any]]:
        """
        Scan code for secrets and sensitive data with entropy analysis

        Args:
            code_content: Source code to scan
            file_path: Path to the file being scanned

        Returns:
            List of secret findings with confidence scores
        """
        findings = []
        lines = code_content.split('\n')
        seen_findings: Set[str] = set()

        for secret_type, secret_info in self.SECRET_PATTERNS.items():
            pattern = secret_info['pattern']

            for line_num, line in enumerate(lines, start=1):
                try:
                    matches = re.finditer(pattern, line, re.IGNORECASE)

                    for match in matches:
                        # Extract secret value
                        secret_value = match.group(1) if match.groups() else match.group(0)

                        # Create unique key to avoid duplicates
                        finding_key = f"{file_path}:{line_num}:{secret_type}:{secret_value[:20]}"
                        if finding_key in seen_findings:
                            continue
                        seen_findings.add(finding_key)

                        # Get surrounding context (3 lines before and after)
                        context_start = max(0, line_num - 4)
                        context_end = min(len(lines), line_num + 3)
                        context = '\n'.join(lines[context_start:context_end])

                        # Calculate confidence
                        confidence = self.calculate_confidence(secret_info, secret_value, line, file_path)

                        # Skip low confidence findings in test files
                        if confidence == 'low' and self.is_test_file(file_path):
                            self.false_positives_filtered += 1
                            continue

                        # Calculate entropy if string is long enough
                        entropy = None
                        if len(secret_value) > 10:
                            entropy = self.calculate_shannon_entropy(secret_value)

                        # Mask the secret value
                        masked_value = self._mask_secret(secret_value)

                        # Generate AI-powered impact statement
                        impact_data = self._generate_impact(
                            secret_type=secret_type,
                            severity=secret_info['severity'],
                            file_path=file_path,
                            confidence=confidence,
                            entropy=entropy,
                            description=secret_info['description'],
                            fallback_remediation=secret_info['remediation']
                        )

                        findings.append({
                            "title": f"{secret_type} Detected",
                            "description": secret_info['description'],
                            "severity": secret_info['severity'],
                            "confidence": confidence,
                            "cwe_id": "CWE-798",  # Use of Hard-coded Credentials
                            "owasp_category": "A07:2021 - Identification and Authentication Failures",
                            "file_path": file_path,
                            "line_number": line_num,
                            "code_snippet": line.strip(),
                            "secret_type": secret_type,
                            "masked_value": masked_value,
                            "entropy": round(entropy, 2) if entropy else None,
                            "business_impact": impact_data.get('business_impact', ''),
                            "technical_impact": impact_data.get('technical_impact', ''),
                            "recommendations": impact_data.get('recommendations', secret_info['remediation']),
                            "remediation": secret_info['remediation'],
                            "cvss_score": self._calculate_cvss(secret_info['severity']),
                            "stride_category": "Information Disclosure",
                            "mitre_attack_id": "T1552.001",  # Unsecured Credentials: Credentials In Files
                            "is_test_file": self.is_test_file(file_path),
                            "impact_generated_by": impact_data.get('generated_by', 'static')
                        })
                except re.error as e:
                    self.errors.append(f"Regex error in pattern '{pattern}': {e}")

        return findings

    def _mask_secret(self, secret: str) -> str:
        """Mask secret value for safe display"""
        if len(secret) <= 8:
            return '*' * len(secret)
        elif len(secret) <= 16:
            return secret[:2] + '*' * (len(secret) - 4) + secret[-2:]
        else:
            return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        cvss_map = {
            "critical": 9.8,
            "high": 7.5,
            "medium": 5.3,
            "low": 2.5,
            "info": 0.0
        }
        return cvss_map.get(severity.lower(), 5.0)

    def _generate_impact(
        self,
        secret_type: str,
        severity: str,
        file_path: str,
        confidence: str,
        entropy: Optional[float],
        description: str,
        fallback_remediation: str
    ) -> Dict[str, str]:
        """
        Generate AI-powered impact statement for a secret finding.

        Args:
            secret_type: Type of secret detected
            severity: Severity level
            file_path: Path to the file containing the secret
            confidence: Confidence level of detection
            entropy: Shannon entropy of the secret (if calculated)
            description: Description of the secret type
            fallback_remediation: Fallback remediation text

        Returns:
            Dictionary with 'impact', 'recommendations', and 'generated_by' keys
        """
        # If AI is enabled and service is available, use it
        if self.ai_impact_enabled and self.ai_impact_service:
            try:
                vuln_info = {
                    "secret_type": secret_type,
                    "pattern_name": secret_type,
                    "severity": severity,
                    "file_path": file_path,
                    "confidence": confidence,
                    "entropy": entropy,
                    "description": description
                }

                ai_result = self.ai_impact_service.generate_impact_statement(
                    finding_type="secret",
                    vulnerability_info=vuln_info,
                    fallback_recommendations=fallback_remediation
                )

                return {
                    "business_impact": ai_result.get('business_impact', 'Impact assessment unavailable'),
                    "technical_impact": ai_result.get('technical_impact', 'Technical impact unavailable'),
                    "recommendations": ai_result.get('recommendations', fallback_remediation),
                    "generated_by": ai_result.get('generated_by', 'ai')
                }

            except Exception as e:
                logger.warning(f"[SecretScanner] AI impact generation failed: {e}")
                # Fall through to static fallback

        # Static fallback
        return self._generate_static_impact(secret_type, severity, fallback_remediation)

    def _generate_static_impact(
        self,
        secret_type: str,
        severity: str,
        fallback_remediation: str
    ) -> Dict[str, str]:
        """Generate static impact statement when AI is unavailable."""
        severity_impacts = {
            "critical": {
                "business": "- Immediate compromise risk for cloud resources or systems\n- High-value credential with broad access scope\n- Automated scanning likely to detect and exploit\n- Immediate rotation required",
                "technical": "- Full system or service access possible\n- Potential for persistent backdoor installation\n- Lateral movement capability\n- Data exfiltration risk"
            },
            "high": {
                "business": "- Significant compromise risk\n- Valuable credential with notable access\n- Should be rotated within hours\n- May require incident response",
                "technical": "- Service or component access\n- Potential for data access\n- May enable further attacks\n- Exploitation tools available"
            },
            "medium": {
                "business": "- Moderate risk requiring attention\n- Limited scope credential\n- Should be addressed promptly\n- Track for compliance",
                "technical": "- Limited service access\n- Constrained exploitation potential\n- May require chaining\n- Lower value target"
            },
            "low": {
                "business": "- Low immediate risk\n- Test or development credential\n- Should still be removed\n- Security hygiene issue",
                "technical": "- Minimal production impact\n- Test environment risk\n- May indicate process gaps\n- Training opportunity"
            }
        }

        sev_lower = severity.lower()
        impact_info = severity_impacts.get(sev_lower, severity_impacts['medium'])

        return {
            "business_impact": impact_info['business'],
            "technical_impact": impact_info['technical'],
            "recommendations": fallback_remediation,
            "generated_by": "static"
        }

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file for secrets

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
                content = f.read()

            findings = self.scan_content(content, file_path)

            return {
                'findings': findings,
                'file_path': file_path,
                'total_findings': len(findings)
            }
        except Exception as e:
            return {'findings': [], 'error': str(e)}

    def scan_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        Scan entire directory for secrets with comprehensive reporting

        Args:
            directory_path: Root directory to scan

        Returns:
            Comprehensive scan results with statistics
        """
        all_findings = []
        self.scanned_files = 0
        self.skipped_files = 0
        self.errors = []
        self.false_positives_filtered = 0

        # Comprehensive list of text-based file extensions
        supported_extensions = [
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.rb', '.go',
            '.rs', '.kt', '.swift', '.cs', '.cpp', '.c', '.h', '.hpp',
            '.yml', '.yaml', '.json', '.xml', '.toml', '.ini', '.cfg',
            '.env', '.config', '.properties', '.conf', '.sh', '.bash',
            '.sql', '.md', '.txt', '.log', '.bat', '.ps1', '.gradle',
            '.tf', '.tfvars', '.dockerfile', '.dockerignore'
        ]

        for root, dirs, files in os.walk(directory_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in [
                '.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build',
                '.pytest_cache', '.mypy_cache', 'coverage', '.tox'
            ]]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                # Also scan env files and files without extensions in root
                if ext in supported_extensions or file.startswith('.env') or (ext == '' and 'file' in root):
                    file_path = os.path.join(root, file)
                    try:
                        # Skip large files (>1MB)
                        if os.path.getsize(file_path) > 1024 * 1024:
                            self.skipped_files += 1
                            continue

                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
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
            "low": len([f for f in all_findings if f['severity'] == 'low'])
        }

        # Confidence distribution
        confidence_counts = {
            "high": len([f for f in all_findings if f['confidence'] == 'high']),
            "medium": len([f for f in all_findings if f['confidence'] == 'medium']),
            "low": len([f for f in all_findings if f['confidence'] == 'low'])
        }

        # Group by secret type
        secrets_by_type = {}
        for finding in all_findings:
            secret_type = finding['secret_type']
            secrets_by_type[secret_type] = secrets_by_type.get(secret_type, 0) + 1

        # High entropy findings
        high_entropy_findings = [f for f in all_findings if (f.get('entropy') or 0) > 4.5]

        return {
            "total_secrets": len(all_findings),
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "false_positives_filtered": self.false_positives_filtered,
            "errors": len(self.errors),
            "severity_counts": severity_counts,
            "confidence_distribution": confidence_counts,
            "secrets_by_type": secrets_by_type,
            "high_entropy_count": len(high_entropy_findings),
            "findings": all_findings,
            "scan_errors": self.errors
        }

    def generate_sample_findings(self) -> List[Dict[str, Any]]:
        """Generate realistic sample secret findings for demo"""
        sample_secrets = [
            {
                "code": "AWS_ACCESS_KEY_ID = 'AKIAXXXXXXXXXXXXXXXX'",
                "file": "config/aws_config.py",
                "line": 8
            },
            {
                "code": "const stripeKey = 'sk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';",
                "file": "payment/stripe_client.js",
                "line": 15
            },
            {
                "code": "db_password = 'MySecretDBPassword123!'",
                "file": "database/connection.py",
                "line": 23
            },
            {
                "code": "const githubToken = 'ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s';",
                "file": "scripts/deploy.js",
                "line": 42
            },
            {
                "code": "GOOGLE_API_KEY = 'AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz12345678'",
                "file": "services/maps_service.py",
                "line": 6
            },
            {
                "code": "private_key = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA...'",
                "file": "certs/key.py",
                "line": 12
            },
            {
                "code": "SLACK_WEBHOOK = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX'",
                "file": "notifications/slack.py",
                "line": 5
            },
        ]

        findings = []
        for snippet in sample_secrets:
            results = self.scan_code(snippet['code'], snippet['file'])
            for result in results:
                result['line_number'] = snippet['line']
                findings.append(result)

        return findings
