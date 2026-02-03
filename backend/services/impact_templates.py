"""
Static Impact Templates for Security Findings
Used as fallback when AI service is unavailable.
"""
from typing import Dict, Any, Optional


# ==================== SAST IMPACT TEMPLATES ====================

SAST_SEVERITY_TEMPLATES = {
    "critical": {
        "business_impact": """- **Immediate risk of complete system compromise** and large-scale data breach
- Regulatory violations (GDPR, PCI-DSS, HIPAA) with potential fines up to 4% of annual revenue
- Severe reputational damage and loss of customer trust
- Potential for business disruption and operational downtime""",
        "technical_impact": """- **Remote code execution (RCE)** or authentication bypass likely possible
- Complete database access enabling extraction of all sensitive data
- Privilege escalation allowing attacker persistence and backdoor installation
- Potential for lateral movement to other systems and services""",
        "recommendations": """1. **Immediately** review and patch the affected code - this is a priority 1 issue
2. Conduct emergency security review of similar code patterns across the codebase
3. Implement input validation and output encoding as defense-in-depth
4. Add security regression tests to prevent reintroduction
5. Consider penetration testing to validate the fix effectiveness"""
    },
    "high": {
        "business_impact": """- **Significant risk of data breach** affecting sensitive customer information
- Potential compliance violations requiring disclosure and remediation
- Reputational risk if vulnerability is exploited or disclosed
- Resource costs for incident response and remediation""",
        "technical_impact": """- Exploitation could lead to **unauthorized data access** or modification
- May enable authentication bypass or session hijacking
- Could expose sensitive configuration or credentials
- Risk of denial of service or resource exhaustion""",
        "recommendations": """1. Prioritize remediation within the current sprint/release cycle
2. Apply secure coding patterns specific to the vulnerability type
3. Implement additional monitoring for exploitation attempts
4. Review related code for similar vulnerability patterns
5. Update security documentation and developer training"""
    },
    "medium": {
        "business_impact": """- Moderate risk requiring attention in near-term planning
- May contribute to larger attack chains if combined with other vulnerabilities
- Potential for limited data exposure or integrity issues
- Should be tracked for compliance audit purposes""",
        "technical_impact": """- Limited exploitation potential but could enable further attacks
- May leak sensitive information or configuration details
- Could be used for reconnaissance or privilege escalation
- Might affect application reliability or performance""",
        "recommendations": """1. Schedule remediation within the next 1-2 release cycles
2. Implement compensating controls if immediate fix isn't possible
3. Add to security debt tracking for prioritization
4. Review for patterns that could be addressed systematically
5. Consider security hardening measures"""
    },
    "low": {
        "business_impact": """- Low immediate risk but represents security best practice deviation
- Should be addressed as part of ongoing security improvement
- May be flagged in security audits or compliance reviews
- Contributes to overall security posture improvement when fixed""",
        "technical_impact": """- Limited direct exploitation potential
- May provide minor information disclosure
- Could contribute to defense-in-depth gaps
- Represents deviation from secure coding standards""",
        "recommendations": """1. Include in regular security maintenance activities
2. Address during code refactoring or feature updates
3. Use as training opportunity for secure coding practices
4. Track in security backlog for systematic improvement
5. Consider automated tooling to prevent similar issues"""
    }
}

SAST_VULN_TEMPLATES = {
    "SQL Injection": {
        "business_impact": """- **Complete database compromise** enabling access to all stored data
- Data breach exposing PII, financial data, and credentials
- Regulatory violations (GDPR, PCI-DSS, HIPAA) with severe penalties
- Authentication bypass allowing unauthorized administrative access""",
        "technical_impact": """- Extraction of entire database contents including password hashes
- Data modification or deletion causing integrity and availability loss
- Potential OS command execution via database features (xp_cmdshell, INTO OUTFILE)
- Blind SQL injection enabling data exfiltration without direct output""",
        "recommendations": """1. Use **parameterized queries** (prepared statements) for all database operations
2. Implement an ORM framework (SQLAlchemy, Hibernate) for automatic parameterization
3. Apply input validation using allowlists for expected data formats
4. Enable database query logging and anomaly detection
5. Apply principle of least privilege for database accounts"""
    },
    "XSS": {
        "business_impact": """- User session hijacking enabling account takeover
- Credential theft through fake login forms
- Malware distribution to users visiting the application
- Reputational damage and user trust erosion""",
        "technical_impact": """- Stored XSS persists in database affecting all users
- Reflected XSS enables targeted phishing attacks
- DOM XSS exploits client-side JavaScript vulnerabilities
- Cookie theft and session token exfiltration""",
        "recommendations": """1. Implement **context-aware output encoding** (HTML, JS, URL, CSS)
2. Use Content Security Policy (CSP) headers to restrict script execution
3. Enable HTTPOnly and Secure flags on session cookies
4. Use templating engines with automatic escaping (React, Angular)
5. Validate and sanitize all user input on both client and server"""
    },
    "Command Injection": {
        "business_impact": """- **Complete server compromise** enabling full system control
- Data theft, ransomware deployment, or cryptomining
- Lateral movement to other systems in the network
- Regulatory violations and incident response costs""",
        "technical_impact": """- Arbitrary command execution with application privileges
- File system access for reading/writing sensitive data
- Network access for pivoting and data exfiltration
- Process control for persistence and backdoor installation""",
        "recommendations": """1. **Avoid shell commands** - use language-native APIs instead
2. If commands necessary, use allowlist validation for all inputs
3. Never concatenate user input into command strings
4. Use subprocess with shell=False and argument arrays
5. Implement strict input validation with character allowlists"""
    },
    "Path Traversal": {
        "business_impact": """- Unauthorized access to sensitive files (configs, credentials)
- Source code exposure revealing business logic and vulnerabilities
- Compliance violations for data protection regulations
- Potential for further exploitation using exposed information""",
        "technical_impact": """- Reading files outside intended directory (../../etc/passwd)
- Accessing configuration files with credentials
- Source code disclosure enabling targeted attacks
- Log file access revealing user data and system information""",
        "recommendations": """1. Use a **allowlist of permitted files** or directories
2. Resolve paths canonically and validate against base directory
3. Use framework-provided file serving mechanisms
4. Implement chroot or container isolation for file operations
5. Never use user input directly in file path construction"""
    }
}


# ==================== SCA IMPACT TEMPLATES ====================

SCA_SEVERITY_TEMPLATES = {
    "critical": {
        "business_impact": """- **Immediate exploitation risk** with publicly available exploits
- Potential for supply chain compromise affecting all deployments
- Emergency patching required within 24-48 hours
- Regulatory notification may be required if exploited""",
        "technical_impact": """- Remote code execution (RCE) typically possible
- No authentication required for exploitation in many cases
- Automated exploitation tools likely available
- Widespread impact due to dependency usage""",
        "recommendations": """1. **Immediately upgrade** to the patched version
2. If upgrade not possible, implement WAF rules or remove functionality
3. Review logs for signs of exploitation
4. Notify security team and stakeholders
5. Consider emergency deployment outside normal release cycle"""
    },
    "high": {
        "business_impact": """- Significant risk requiring prompt attention
- May enable data breach or system compromise
- Should be addressed within days, not weeks
- Compliance teams should be notified""",
        "technical_impact": """- Exploitation possible with moderate complexity
- May require authentication or specific conditions
- Could lead to data exposure or service disruption
- Exploit code may be publicly available""",
        "recommendations": """1. Schedule upgrade in the current sprint
2. Assess impact on dependent functionality
3. Review for compensating controls
4. Test upgrade thoroughly before deployment
5. Update dependency management processes"""
    },
    "medium": {
        "business_impact": """- Moderate risk requiring planned remediation
- Should be addressed within normal release cycles
- May be acceptable with compensating controls
- Track for security metrics and reporting""",
        "technical_impact": """- Exploitation requires specific conditions or configurations
- Limited impact scope or requires chaining with other vulnerabilities
- May affect availability more than confidentiality
- Proof of concept may exist but not weaponized""",
        "recommendations": """1. Plan upgrade in upcoming release
2. Evaluate if vulnerable functionality is used
3. Consider temporary mitigations if delay needed
4. Add to dependency update automation
5. Review similar dependencies for patterns"""
    },
    "low": {
        "business_impact": """- Low immediate risk
- Address as part of regular maintenance
- May be informational or theoretical
- Include in security hygiene metrics""",
        "technical_impact": """- Exploitation unlikely or highly constrained
- Minimal impact if exploited
- May only affect edge cases or debug features
- Often related to deprecated functionality""",
        "recommendations": """1. Include in regular dependency updates
2. Consider as part of technical debt
3. Monitor for severity changes
4. Update when convenient
5. Use as opportunity to review dependency necessity"""
    }
}

SCA_VULN_TYPE_TEMPLATES = {
    "Remote Code Execution": {
        "business_impact": """- **Complete system compromise** through dependency exploitation
- Supply chain attack vector affecting all applications using this dependency
- Data breach and ransomware deployment risk
- Immediate patching required""",
        "technical_impact": """- Arbitrary code execution in application context
- Full access to application data and connected services
- Potential for persistent backdoor installation
- Lateral movement to connected systems""",
        "recommendations": """1. **Upgrade immediately** to patched version
2. If no patch, consider removing or replacing the dependency
3. Implement runtime application protection (RASP)
4. Review for exploitation indicators in logs
5. Assess blast radius of compromised application"""
    },
    "Denial of Service": {
        "business_impact": """- Application availability disruption
- Service degradation affecting user experience
- Potential revenue loss during outage
- SLA violations and customer impact""",
        "technical_impact": """- Resource exhaustion (CPU, memory, connections)
- Crash or hang conditions
- Amplification attacks possible
- May affect dependent services""",
        "recommendations": """1. Upgrade to patched version when available
2. Implement rate limiting and resource quotas
3. Add monitoring for abnormal resource usage
4. Consider WAF rules for known attack patterns
5. Review timeout and resource limit configurations"""
    },
    "Information Disclosure": {
        "business_impact": """- Sensitive data exposure risk
- Compliance implications for PII/PHI disclosure
- May enable further targeted attacks
- Audit trail and notification requirements""",
        "technical_impact": """- Exposure of internal data structures
- Credential or token leakage
- Configuration and environment disclosure
- Debug information exposure""",
        "recommendations": """1. Upgrade to address the vulnerability
2. Review logs for potential exposure incidents
3. Rotate any potentially exposed credentials
4. Implement data classification and protection
5. Review error handling and logging practices"""
    }
}


# ==================== SECRET IMPACT TEMPLATES ====================

SECRET_TYPE_TEMPLATES = {
    "AWS Access Key ID": {
        "business_impact": """- **Unauthorized AWS resource access** with associated billing charges
- Data breach via S3, RDS, or other AWS services
- Compliance violations (SOC2, ISO 27001, PCI-DSS)
- Potential for cryptocurrency mining abuse""",
        "technical_impact": """- Full AWS account access depending on IAM permissions
- S3 bucket enumeration and data exfiltration
- EC2 instance compromise and lateral movement
- CloudFormation/Terraform state access""",
        "recommendations": """1. **Immediately rotate** the exposed AWS credentials in IAM console
2. Review CloudTrail logs for unauthorized access
3. Implement AWS Secrets Manager for credential storage
4. Enable MFA on AWS accounts
5. Use IAM roles instead of access keys where possible"""
    },
    "GitHub Personal Access Token": {
        "business_impact": """- **Repository access** including private code and secrets
- Code modification or malicious commit injection
- CI/CD pipeline compromise via GitHub Actions
- Organization-wide impact if token has org scope""",
        "technical_impact": """- Repository read/write access
- GitHub Actions workflow modification
- Secrets exposure from repository settings
- Issue/PR manipulation for social engineering""",
        "recommendations": """1. **Revoke the token immediately** on GitHub settings
2. Review recent repository activity for unauthorized changes
3. Rotate any secrets stored in affected repositories
4. Use fine-grained tokens with minimal scope
5. Enable GitHub secret scanning and push protection"""
    },
    "Database URL": {
        "business_impact": """- **Direct database access** bypassing application controls
- Complete data breach of stored information
- Data manipulation affecting business integrity
- Compliance violations for data protection""",
        "technical_impact": """- Full database read/write access
- User credential extraction
- Data export and exfiltration
- Schema and structure disclosure""",
        "recommendations": """1. **Rotate database credentials immediately**
2. Review database access logs for unauthorized queries
3. Implement connection string encryption
4. Use secrets management (Vault, AWS Secrets Manager)
5. Enable database audit logging"""
    },
    "API Key": {
        "business_impact": """- **Unauthorized API access** with associated costs
- Rate limit exhaustion affecting legitimate users
- Data access depending on API scope
- Service abuse and reputation impact""",
        "technical_impact": """- API endpoint access with key permissions
- Data retrieval or modification via API
- Potential for automated abuse
- May expose internal service details""",
        "recommendations": """1. **Revoke and rotate** the exposed API key
2. Review API logs for unauthorized usage
3. Implement API key restrictions (IP, referrer)
4. Use environment variables for API keys
5. Enable API key expiration policies"""
    },
    "Private Key": {
        "business_impact": """- **Cryptographic identity compromise**
- SSL/TLS certificate impersonation
- Code signing abuse for malware distribution
- SSH access to servers and systems""",
        "technical_impact": """- Man-in-the-middle attacks possible
- Server impersonation for phishing
- Decryption of intercepted traffic
- Unauthorized system access""",
        "recommendations": """1. **Revoke and regenerate** the private key immediately
2. Replace associated certificates
3. Review access logs for affected systems
4. Use HSM or secrets management for key storage
5. Implement key rotation policies"""
    },
    "JWT Secret": {
        "business_impact": """- **Authentication bypass** for all users
- Token forgery enabling privilege escalation
- Session hijacking and account takeover
- Complete application access control failure""",
        "technical_impact": """- Arbitrary JWT token creation
- Admin privilege escalation
- User impersonation
- Persistent unauthorized access""",
        "recommendations": """1. **Rotate the JWT secret immediately**
2. Invalidate all existing tokens
3. Force re-authentication for all users
4. Use asymmetric keys (RS256) instead of secrets
5. Implement token expiration and refresh"""
    }
}

SECRET_SEVERITY_TEMPLATES = {
    "critical": {
        "business_impact": """- **Immediate compromise risk** for cloud resources or systems
- High-value credential with broad access scope
- Automated scanning likely to detect and exploit
- Immediate rotation required""",
        "technical_impact": """- Full system or service access
- Potential for persistent backdoor
- Lateral movement capability
- Data exfiltration risk""",
        "recommendations": """1. **Rotate immediately** - within minutes, not hours
2. Review access logs for unauthorized usage
3. Assess and contain blast radius
4. Implement secrets management solution
5. Enable secret scanning in CI/CD"""
    },
    "high": {
        "business_impact": """- Significant compromise risk
- Valuable credential with notable access
- Should be rotated within hours
- May require incident response""",
        "technical_impact": """- Service or component access
- Potential for data access
- May enable further attacks
- Exploitation tools available""",
        "recommendations": """1. Rotate within 24 hours
2. Review usage patterns
3. Implement access restrictions
4. Add monitoring alerts
5. Update credential management"""
    },
    "medium": {
        "business_impact": """- Moderate risk requiring attention
- Limited scope credential
- Should be addressed promptly
- Track for compliance""",
        "technical_impact": """- Limited service access
- Constrained exploitation potential
- May require chaining
- Lower value target""",
        "recommendations": """1. Schedule rotation in current sprint
2. Assess actual usage requirements
3. Consider service account options
4. Implement least privilege
5. Add to credential inventory"""
    },
    "low": {
        "business_impact": """- Low immediate risk
- Test or development credential
- Should still be removed
- Security hygiene issue""",
        "technical_impact": """- Minimal production impact
- Test environment risk
- May indicate process gaps
- Training opportunity""",
        "recommendations": """1. Remove from code
2. Use environment variables
3. Update development practices
4. Consider git-secrets hooks
5. Review onboarding materials"""
    }
}


def get_fallback_impact(finding_type: str, vuln_info: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Get fallback impact template based on finding type and vulnerability info.

    Args:
        finding_type: "sast", "sca", or "secret"
        vuln_info: Dictionary containing vulnerability details

    Returns:
        Dictionary with business_impact, technical_impact, recommendations
        or None if no template matches
    """
    severity = vuln_info.get('severity', 'medium').lower()

    if finding_type == "sast":
        # Try specific vulnerability type first
        vuln_type = vuln_info.get('title', '')
        for key, template in SAST_VULN_TEMPLATES.items():
            if key.lower() in vuln_type.lower():
                return template

        # Fall back to severity-based template
        return SAST_SEVERITY_TEMPLATES.get(severity, SAST_SEVERITY_TEMPLATES['medium'])

    elif finding_type == "sca":
        # Try vulnerability type first
        vuln_desc = vuln_info.get('vulnerability', '').lower()
        for key, template in SCA_VULN_TYPE_TEMPLATES.items():
            if key.lower() in vuln_desc:
                return template

        # Fall back to severity-based template
        return SCA_SEVERITY_TEMPLATES.get(severity, SCA_SEVERITY_TEMPLATES['medium'])

    elif finding_type == "secret":
        # Try specific secret type first
        secret_type = vuln_info.get('secret_type') or vuln_info.get('pattern_name', '')
        for key, template in SECRET_TYPE_TEMPLATES.items():
            if key.lower() in secret_type.lower():
                return template

        # Fall back to severity-based template
        return SECRET_SEVERITY_TEMPLATES.get(severity, SECRET_SEVERITY_TEMPLATES['medium'])

    return None
