"""
AI Rule Suggester Service

This service uses AI to generate intelligent security rule suggestions based on
the application profile. It analyzes the detected technology stack, frameworks,
and patterns to suggest relevant security rules.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class AIRuleSuggester:
    """
    AI-powered service that generates security rule suggestions based on
    application profiles.
    """

    # Framework-specific rule templates
    FRAMEWORK_RULES = {
        "FastAPI": [
            {
                "name": "FastAPI SQL Injection via Raw Query",
                "category": "sql_injection",
                "severity": "critical",
                "description": "Detects potential SQL injection in FastAPI applications using raw SQL queries",
                "reason": "FastAPI applications using SQLAlchemy may be vulnerable to SQL injection if using raw queries with string formatting",
                "cwe_ids": ["CWE-89"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1190"],
                "pattern_indicators": ["execute(", "text(", "raw(", "f\"SELECT", "f'SELECT"]
            },
            {
                "name": "FastAPI Authentication Bypass",
                "category": "auth_bypass",
                "severity": "high",
                "description": "Detects endpoints potentially missing authentication dependency",
                "reason": "FastAPI routes should use Depends() for authentication to prevent unauthorized access",
                "cwe_ids": ["CWE-287", "CWE-306"],
                "owasp_categories": ["A07:2021 - Identification and Authentication Failures"],
                "mitre_techniques": ["T1078"],
                "pattern_indicators": ["@app.post", "@app.put", "@app.delete", "@router.post"]
            },
            {
                "name": "FastAPI CORS Misconfiguration",
                "category": "cors",
                "severity": "medium",
                "description": "Detects overly permissive CORS configuration",
                "reason": "Using allow_origins=['*'] with allow_credentials=True is a security risk",
                "cwe_ids": ["CWE-942"],
                "owasp_categories": ["A05:2021 - Security Misconfiguration"],
                "mitre_techniques": ["T1557"],
                "pattern_indicators": ["allow_origins=['*']", 'allow_origins=["*"]', "allow_credentials=True"]
            }
        ],
        "Django": [
            {
                "name": "Django SQL Injection via Raw Query",
                "category": "sql_injection",
                "severity": "critical",
                "description": "Detects potential SQL injection in Django using raw() or extra()",
                "reason": "Django raw() and extra() methods bypass ORM protections",
                "cwe_ids": ["CWE-89"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1190"],
                "pattern_indicators": [".raw(", ".extra(", "cursor.execute("]
            },
            {
                "name": "Django XSS via mark_safe",
                "category": "xss",
                "severity": "high",
                "description": "Detects potential XSS vulnerabilities using mark_safe with user input",
                "reason": "Using mark_safe() with user-controlled data can lead to XSS",
                "cwe_ids": ["CWE-79"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1059.007"],
                "pattern_indicators": ["mark_safe(", "|safe"]
            },
            {
                "name": "Django CSRF Protection Disabled",
                "category": "csrf",
                "severity": "high",
                "description": "Detects disabled CSRF protection",
                "reason": "Disabling CSRF protection exposes the application to cross-site request forgery attacks",
                "cwe_ids": ["CWE-352"],
                "owasp_categories": ["A01:2021 - Broken Access Control"],
                "mitre_techniques": ["T1185"],
                "pattern_indicators": ["@csrf_exempt", "csrf_protect = False"]
            }
        ],
        "Flask": [
            {
                "name": "Flask SQL Injection",
                "category": "sql_injection",
                "severity": "critical",
                "description": "Detects SQL injection in Flask applications",
                "reason": "Flask applications using direct database queries are vulnerable to SQL injection",
                "cwe_ids": ["CWE-89"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1190"],
                "pattern_indicators": ["execute(", "db.engine.execute(", "session.execute("]
            },
            {
                "name": "Flask Debug Mode in Production",
                "category": "security_misconfiguration",
                "severity": "high",
                "description": "Detects Flask debug mode enabled",
                "reason": "Debug mode exposes sensitive information and allows code execution",
                "cwe_ids": ["CWE-489"],
                "owasp_categories": ["A05:2021 - Security Misconfiguration"],
                "mitre_techniques": ["T1592"],
                "pattern_indicators": ["debug=True", "FLASK_DEBUG=1"]
            },
            {
                "name": "Flask Session Secret Key Weakness",
                "category": "crypto",
                "severity": "high",
                "description": "Detects weak or hardcoded secret keys",
                "reason": "Weak secret keys can lead to session hijacking",
                "cwe_ids": ["CWE-798", "CWE-330"],
                "owasp_categories": ["A02:2021 - Cryptographic Failures"],
                "mitre_techniques": ["T1552"],
                "pattern_indicators": ["SECRET_KEY = ", "app.secret_key = "]
            }
        ],
        "Express": [
            {
                "name": "Express NoSQL Injection",
                "category": "nosql_injection",
                "severity": "critical",
                "description": "Detects potential NoSQL injection in Express/MongoDB applications",
                "reason": "Direct use of user input in MongoDB queries can lead to injection",
                "cwe_ids": ["CWE-943"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1190"],
                "pattern_indicators": ["$where", "$regex", "findOne({", "find({"]
            },
            {
                "name": "Express XSS via innerHTML",
                "category": "xss",
                "severity": "high",
                "description": "Detects potential XSS through unescaped output",
                "reason": "Using res.send() with user input without sanitization",
                "cwe_ids": ["CWE-79"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1059.007"],
                "pattern_indicators": ["res.send(", "res.write(", "innerHTML"]
            },
            {
                "name": "Express Security Headers Missing",
                "category": "security_misconfiguration",
                "severity": "medium",
                "description": "Detects missing security headers (helmet not used)",
                "reason": "Missing security headers expose the application to various attacks",
                "cwe_ids": ["CWE-693"],
                "owasp_categories": ["A05:2021 - Security Misconfiguration"],
                "mitre_techniques": ["T1189"],
                "pattern_indicators": ["express()"]
            }
        ],
        "React": [
            {
                "name": "React XSS via dangerouslySetInnerHTML",
                "category": "xss",
                "severity": "high",
                "description": "Detects potential XSS using dangerouslySetInnerHTML",
                "reason": "dangerouslySetInnerHTML bypasses React's XSS protection",
                "cwe_ids": ["CWE-79"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1059.007"],
                "pattern_indicators": ["dangerouslySetInnerHTML"]
            },
            {
                "name": "React Sensitive Data in State",
                "category": "data_exposure",
                "severity": "medium",
                "description": "Detects sensitive data stored in React state (accessible via DevTools)",
                "reason": "Sensitive data in React state can be viewed via browser DevTools",
                "cwe_ids": ["CWE-200"],
                "owasp_categories": ["A01:2021 - Broken Access Control"],
                "mitre_techniques": ["T1552"],
                "pattern_indicators": ["useState(", "password", "token", "apiKey"]
            }
        ],
        "Spring": [
            {
                "name": "Spring SQL Injection",
                "category": "sql_injection",
                "severity": "critical",
                "description": "Detects SQL injection in Spring applications using native queries",
                "reason": "Spring native queries with string concatenation are vulnerable",
                "cwe_ids": ["CWE-89"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1190"],
                "pattern_indicators": ["@Query(", "createNativeQuery(", "jdbcTemplate.query("]
            },
            {
                "name": "Spring SpEL Injection",
                "category": "code_injection",
                "severity": "critical",
                "description": "Detects potential Spring Expression Language injection",
                "reason": "SpEL injection can lead to remote code execution",
                "cwe_ids": ["CWE-917"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1059"],
                "pattern_indicators": ["SpelExpressionParser", "@Value(", "parseExpression("]
            },
            {
                "name": "Spring Actuator Exposure",
                "category": "security_misconfiguration",
                "severity": "high",
                "description": "Detects exposed Spring Actuator endpoints",
                "reason": "Exposed actuator endpoints can leak sensitive information",
                "cwe_ids": ["CWE-200"],
                "owasp_categories": ["A05:2021 - Security Misconfiguration"],
                "mitre_techniques": ["T1592"],
                "pattern_indicators": ["management.endpoints.web.exposure.include=*"]
            }
        ],
        "NestJS": [
            {
                "name": "NestJS SQL Injection via TypeORM",
                "category": "sql_injection",
                "severity": "critical",
                "description": "Detects SQL injection in NestJS TypeORM applications",
                "reason": "Raw queries in TypeORM can lead to SQL injection",
                "cwe_ids": ["CWE-89"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1190"],
                "pattern_indicators": [".query(", "createQueryBuilder(", "raw("]
            },
            {
                "name": "NestJS Authorization Bypass",
                "category": "auth_bypass",
                "severity": "high",
                "description": "Detects endpoints potentially missing guards",
                "reason": "NestJS endpoints should use Guards for authorization",
                "cwe_ids": ["CWE-862"],
                "owasp_categories": ["A01:2021 - Broken Access Control"],
                "mitre_techniques": ["T1078"],
                "pattern_indicators": ["@Post(", "@Put(", "@Delete(", "@Patch("]
            }
        ]
    }

    # ORM-specific rules
    ORM_RULES = {
        "SQLAlchemy": [
            {
                "name": "SQLAlchemy Raw SQL Injection",
                "category": "sql_injection",
                "severity": "critical",
                "description": "Detects SQL injection via SQLAlchemy text() or execute()",
                "reason": "Using text() with f-strings or format() bypasses ORM protection",
                "cwe_ids": ["CWE-89"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1190"],
                "pattern_indicators": ["text(f\"", "text(f'", ".execute(f\"", "format("]
            }
        ],
        "Prisma": [
            {
                "name": "Prisma Raw Query Injection",
                "category": "sql_injection",
                "severity": "critical",
                "description": "Detects SQL injection via Prisma $queryRaw",
                "reason": "Using $queryRaw with template literals can be unsafe",
                "cwe_ids": ["CWE-89"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1190"],
                "pattern_indicators": ["$queryRaw", "$executeRaw"]
            }
        ],
        "TypeORM": [
            {
                "name": "TypeORM Raw Query Injection",
                "category": "sql_injection",
                "severity": "critical",
                "description": "Detects SQL injection via TypeORM raw queries",
                "reason": "Raw queries with string interpolation are vulnerable",
                "cwe_ids": ["CWE-89"],
                "owasp_categories": ["A03:2021 - Injection"],
                "mitre_techniques": ["T1190"],
                "pattern_indicators": [".query(`", ".query(\"", "createQueryBuilder"]
            }
        ]
    }

    # Authentication-specific rules
    AUTH_RULES = {
        "JWT": [
            {
                "name": "JWT Algorithm None Attack",
                "category": "auth_bypass",
                "severity": "critical",
                "description": "Detects JWT configurations vulnerable to algorithm confusion",
                "reason": "Accepting 'none' algorithm allows token forgery",
                "cwe_ids": ["CWE-327", "CWE-345"],
                "owasp_categories": ["A02:2021 - Cryptographic Failures"],
                "mitre_techniques": ["T1550"],
                "pattern_indicators": ["algorithms=", "algorithm:", "verify=False"]
            },
            {
                "name": "JWT Weak Secret Key",
                "category": "crypto",
                "severity": "high",
                "description": "Detects weak or hardcoded JWT secrets",
                "reason": "Weak JWT secrets can be brute-forced",
                "cwe_ids": ["CWE-798", "CWE-330"],
                "owasp_categories": ["A02:2021 - Cryptographic Failures"],
                "mitre_techniques": ["T1552"],
                "pattern_indicators": ["SECRET_KEY", "JWT_SECRET", "secret="]
            }
        ],
        "OAuth2": [
            {
                "name": "OAuth2 Open Redirect",
                "category": "open_redirect",
                "severity": "high",
                "description": "Detects potential open redirect in OAuth callback",
                "reason": "Unvalidated redirect_uri can lead to token theft",
                "cwe_ids": ["CWE-601"],
                "owasp_categories": ["A01:2021 - Broken Access Control"],
                "mitre_techniques": ["T1557"],
                "pattern_indicators": ["redirect_uri", "callback", "return_url"]
            }
        ],
        "Session": [
            {
                "name": "Session Fixation Vulnerability",
                "category": "session",
                "severity": "high",
                "description": "Detects session not being regenerated after login",
                "reason": "Session IDs should be regenerated after authentication",
                "cwe_ids": ["CWE-384"],
                "owasp_categories": ["A07:2021 - Identification and Authentication Failures"],
                "mitre_techniques": ["T1563"],
                "pattern_indicators": ["session[", "req.session", "session."]
            }
        ]
    }

    # Sensitive data handling rules
    SENSITIVE_DATA_RULES = [
        {
            "name": "Hardcoded Credentials",
            "category": "hardcoded_secrets",
            "severity": "critical",
            "description": "Detects hardcoded passwords, API keys, or tokens",
            "reason": "Hardcoded credentials in source code can be extracted",
            "cwe_ids": ["CWE-798"],
            "owasp_categories": ["A07:2021 - Identification and Authentication Failures"],
            "mitre_techniques": ["T1552.001"],
            "pattern_indicators": ["password = ", "api_key = ", "secret = ", "token = "]
        },
        {
            "name": "Sensitive Data Logging",
            "category": "data_exposure",
            "severity": "high",
            "description": "Detects logging of sensitive information",
            "reason": "Logging sensitive data can lead to information disclosure",
            "cwe_ids": ["CWE-532"],
            "owasp_categories": ["A09:2021 - Security Logging and Monitoring Failures"],
            "mitre_techniques": ["T1552"],
            "pattern_indicators": ["logger.info(", "console.log(", "print(", "password", "token"]
        },
        {
            "name": "Unencrypted Sensitive Data Storage",
            "category": "data_exposure",
            "severity": "high",
            "description": "Detects sensitive data stored without encryption",
            "reason": "Sensitive data should be encrypted at rest",
            "cwe_ids": ["CWE-311"],
            "owasp_categories": ["A02:2021 - Cryptographic Failures"],
            "mitre_techniques": ["T1552"],
            "pattern_indicators": ["password", "credit_card", "ssn", "Column(String"]
        }
    ]

    def __init__(self, ai_client=None):
        """
        Initialize the AI Rule Suggester.

        Args:
            ai_client: Optional AI client for enhanced rule generation
        """
        self.ai_client = ai_client

    async def generate_suggestions(
        self,
        profile: Dict[str, Any],
        progress_callback: Optional[callable] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate security rule suggestions based on application profile.

        Args:
            profile: Application profile from ApplicationProfiler
            progress_callback: Optional callback for progress updates

        Returns:
            List of suggested rules with full details
        """
        suggestions = []

        try:
            if progress_callback:
                await progress_callback(0, "Analyzing technology stack...")

            # Generate framework-specific rules
            frameworks = profile.get("frameworks", [])
            for framework in frameworks:
                framework_name = framework.get("name", "")
                if framework_name in self.FRAMEWORK_RULES:
                    for rule_template in self.FRAMEWORK_RULES[framework_name]:
                        suggestion = self._create_suggestion(
                            rule_template,
                            framework_context=framework_name,
                            profile=profile
                        )
                        suggestions.append(suggestion)

            if progress_callback:
                await progress_callback(25, "Analyzing ORM patterns...")

            # Generate ORM-specific rules
            orm_libs = profile.get("orm_libraries", [])
            for orm in orm_libs:
                if orm in self.ORM_RULES:
                    for rule_template in self.ORM_RULES[orm]:
                        suggestion = self._create_suggestion(
                            rule_template,
                            framework_context=orm,
                            profile=profile
                        )
                        suggestions.append(suggestion)

            if progress_callback:
                await progress_callback(50, "Analyzing authentication mechanisms...")

            # Generate auth-specific rules
            auth_mechanisms = profile.get("auth_mechanisms", [])
            for auth in auth_mechanisms:
                if auth in self.AUTH_RULES:
                    for rule_template in self.AUTH_RULES[auth]:
                        suggestion = self._create_suggestion(
                            rule_template,
                            framework_context=auth,
                            profile=profile
                        )
                        suggestions.append(suggestion)

            if progress_callback:
                await progress_callback(75, "Analyzing sensitive data patterns...")

            # Generate sensitive data rules if sensitive fields detected
            sensitive_fields = profile.get("sensitive_data_fields", [])
            if sensitive_fields:
                for rule_template in self.SENSITIVE_DATA_RULES:
                    suggestion = self._create_suggestion(
                        rule_template,
                        framework_context="sensitive_data",
                        profile=profile,
                        detected_patterns=sensitive_fields[:5]  # Include sample patterns
                    )
                    suggestions.append(suggestion)

            if progress_callback:
                await progress_callback(90, "Generating rule exports...")

            # Generate multi-format rules for each suggestion
            for suggestion in suggestions:
                suggestion["semgrep_rule"] = self._generate_semgrep_rule(suggestion, profile)
                suggestion["codeql_rule"] = self._generate_codeql_rule(suggestion, profile)
                suggestion["checkmarx_rule"] = self._generate_checkmarx_rule(suggestion, profile)
                suggestion["fortify_rule"] = self._generate_fortify_rule(suggestion, profile)

            # Calculate confidence scores
            for suggestion in suggestions:
                suggestion["confidence_score"] = self._calculate_confidence(suggestion, profile)

            # Sort by severity and confidence
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            suggestions.sort(key=lambda x: (
                severity_order.get(x["severity"], 5),
                -x.get("confidence_score", 0)
            ))

            if progress_callback:
                await progress_callback(100, "Suggestions generated successfully")

            logger.info(f"Generated {len(suggestions)} rule suggestions")
            return suggestions

        except Exception as e:
            logger.error(f"Error generating suggestions: {str(e)}")
            raise

    def _create_suggestion(
        self,
        template: Dict[str, Any],
        framework_context: str,
        profile: Dict[str, Any],
        detected_patterns: List[Dict] = None
    ) -> Dict[str, Any]:
        """Create a suggestion from a template."""
        languages = list(profile.get("languages", {}).keys())
        primary_language = languages[0] if languages else "unknown"

        return {
            "name": template["name"],
            "description": template["description"],
            "category": template["category"],
            "severity": template["severity"],
            "reason": template["reason"],
            "framework_context": framework_context,
            "detected_patterns": detected_patterns or [],
            "cwe_ids": template.get("cwe_ids", []),
            "owasp_categories": template.get("owasp_categories", []),
            "mitre_techniques": template.get("mitre_techniques", []),
            "pattern_indicators": template.get("pattern_indicators", []),
            "target_language": primary_language,
            "rule_type": "semgrep"
        }

    def _generate_semgrep_rule(self, suggestion: Dict, profile: Dict) -> str:
        """Generate Semgrep YAML rule."""
        languages = list(profile.get("languages", {}).keys())

        # Map common language names to Semgrep language identifiers
        lang_map = {
            "python": "python",
            "javascript": "javascript",
            "typescript": "typescript",
            "java": "java",
            "go": "go",
            "ruby": "ruby",
            "php": "php",
            "csharp": "csharp",
            "rust": "rust"
        }

        semgrep_langs = []
        for lang in languages:
            mapped = lang_map.get(lang.lower())
            if mapped:
                semgrep_langs.append(mapped)

        if not semgrep_langs:
            semgrep_langs = ["python"]  # Default

        rule_id = suggestion["name"].lower().replace(" ", "-").replace("_", "-")
        patterns = suggestion.get("pattern_indicators", [])

        # Create pattern based on category
        if suggestion["category"] == "sql_injection":
            pattern = self._get_sql_injection_pattern(semgrep_langs[0])
        elif suggestion["category"] == "xss":
            pattern = self._get_xss_pattern(semgrep_langs[0])
        elif suggestion["category"] == "auth_bypass":
            pattern = self._get_auth_bypass_pattern(semgrep_langs[0], suggestion.get("framework_context"))
        else:
            # Generic pattern using indicators
            pattern = f'pattern: $FUNC(..., "{patterns[0] if patterns else "..."}", ...)'

        cwe_refs = ", ".join(suggestion.get("cwe_ids", []))
        owasp_refs = ", ".join(suggestion.get("owasp_categories", []))

        rule = f"""rules:
  - id: {rule_id}
    message: |
      {suggestion['description']}
      Reason: {suggestion['reason']}
    severity: {"ERROR" if suggestion['severity'] in ['critical', 'high'] else "WARNING"}
    languages:
      - {semgrep_langs[0]}
    metadata:
      category: security
      technology:
        - {suggestion.get('framework_context', 'generic')}
      cwe: "{cwe_refs}"
      owasp: "{owasp_refs}"
      confidence: {"HIGH" if suggestion.get('confidence_score', 0) > 0.7 else "MEDIUM"}
    {pattern}
"""
        return rule

    def _get_sql_injection_pattern(self, language: str) -> str:
        """Get SQL injection detection pattern for Semgrep."""
        patterns = {
            "python": '''patterns:
      - pattern-either:
          - pattern: $DB.execute(f"...")
          - pattern: $DB.execute("..." % ...)
          - pattern: $DB.execute("...".format(...))
          - pattern: text(f"...")
          - pattern: text("..." % ...)''',
            "javascript": '''patterns:
      - pattern-either:
          - pattern: $DB.query(`...${...}...`)
          - pattern: $DB.query("..." + ...)
          - pattern: $DB.raw(`...${...}...`)''',
            "java": '''patterns:
      - pattern-either:
          - pattern: $STMT.executeQuery("..." + ...)
          - pattern: $CONN.createStatement().executeQuery("..." + ...)
          - pattern: |
              String $QUERY = "..." + $USER_INPUT;
              ...
              $STMT.executeQuery($QUERY);'''
        }
        return patterns.get(language, patterns["python"])

    def _get_xss_pattern(self, language: str) -> str:
        """Get XSS detection pattern for Semgrep."""
        patterns = {
            "python": '''patterns:
      - pattern-either:
          - pattern: mark_safe($USER_INPUT)
          - pattern: Markup($USER_INPUT)
          - pattern: |
              $X = request.$METHOD(...)
              ...
              return HttpResponse($X)''',
            "javascript": '''patterns:
      - pattern-either:
          - pattern: dangerouslySetInnerHTML={{__html: $USER_INPUT}}
          - pattern: $EL.innerHTML = $USER_INPUT
          - pattern: document.write($USER_INPUT)''',
            "java": '''patterns:
      - pattern-either:
          - pattern: $RESP.getWriter().write($USER_INPUT)
          - pattern: |
              String $INPUT = request.getParameter(...);
              ...
              $RESP.getWriter().write($INPUT);'''
        }
        return patterns.get(language, patterns["javascript"])

    def _get_auth_bypass_pattern(self, language: str, framework: str = None) -> str:
        """Get authentication bypass detection pattern for Semgrep."""
        if framework == "FastAPI":
            return '''patterns:
      - pattern: |
          @$DECORATOR("$PATH")
          def $FUNC(...):
              ...
      - pattern-not: |
          @$DECORATOR("$PATH")
          def $FUNC(..., $AUTH: ... = Depends(...), ...):
              ...
      - metavariable-regex:
          metavariable: $DECORATOR
          regex: (app|router)\\.(post|put|delete|patch)'''
        elif framework == "NestJS":
            return '''patterns:
      - pattern: |
          @$DECORATOR($PATH)
          $FUNC(...) {
              ...
          }
      - pattern-not: |
          @UseGuards(...)
          @$DECORATOR($PATH)
          $FUNC(...) {
              ...
          }'''
        else:
            return '''pattern: |
      $FUNC(...) {
          ...
          // Missing authentication check
          ...
      }'''

    def _generate_codeql_rule(self, suggestion: Dict, profile: Dict) -> str:
        """Generate CodeQL rule."""
        languages = list(profile.get("languages", {}).keys())
        primary_lang = languages[0].lower() if languages else "python"

        rule_name = suggestion["name"].replace(" ", "")

        if suggestion["category"] == "sql_injection":
            if primary_lang == "python":
                return f'''/**
 * @name {suggestion['name']}
 * @description {suggestion['description']}
 * @kind path-problem
 * @problem.severity {"error" if suggestion['severity'] in ['critical', 'high'] else "warning"}
 * @security-severity 9.8
 * @precision high
 * @id py/sql-injection-{rule_name.lower()}
 * @tags security
 *       external/cwe/{suggestion.get('cwe_ids', ['CWE-89'])[0]}
 */

import python
import semmle.python.security.dataflow.SqlInjectionQuery
import DataFlow::PathGraph

from SqlInjection::Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection vulnerability from $@.", source.getNode(), "user input"
'''
            elif primary_lang in ["javascript", "typescript"]:
                return f'''/**
 * @name {suggestion['name']}
 * @description {suggestion['description']}
 * @kind path-problem
 * @problem.severity {"error" if suggestion['severity'] in ['critical', 'high'] else "warning"}
 * @security-severity 9.8
 * @precision high
 * @id js/sql-injection-{rule_name.lower()}
 * @tags security
 *       external/cwe/{suggestion.get('cwe_ids', ['CWE-89'])[0]}
 */

import javascript
import DataFlow::PathGraph
import semmle.javascript.security.dataflow.SqlInjectionQuery

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "SQL injection from $@.", source.getNode(), "user input"
'''
            elif primary_lang == "java":
                return f'''/**
 * @name {suggestion['name']}
 * @description {suggestion['description']}
 * @kind path-problem
 * @problem.severity {"error" if suggestion['severity'] in ['critical', 'high'] else "warning"}
 * @security-severity 9.8
 * @precision high
 * @id java/sql-injection-{rule_name.lower()}
 * @tags security
 *       external/cwe/{suggestion.get('cwe_ids', ['CWE-89'])[0]}
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.SqlInjectionQuery
import DataFlow::PathGraph

from QueryInjectionSink query, DataFlow::PathNode source, DataFlow::PathNode sink
where
  source.getNode() instanceof RemoteFlowSource and
  sink.getNode() = query and
  hasFlowPath(source, sink)
select query, source, sink, "SQL injection from $@.", source.getNode(), "user input"
'''

        # Generic template for other categories
        return f'''/**
 * @name {suggestion['name']}
 * @description {suggestion['description']}
 * @kind problem
 * @problem.severity {"error" if suggestion['severity'] in ['critical', 'high'] else "warning"}
 * @precision medium
 * @id custom/{suggestion['category']}-{rule_name.lower()}
 * @tags security
 *       {' '.join([f'external/cwe/{cwe}' for cwe in suggestion.get('cwe_ids', [])])}
 */

import {primary_lang}

// Custom query implementation needed
from Expr e
where
  // Add detection logic here
  e.toString().matches("%{suggestion.get('pattern_indicators', [''])[0]}%")
select e, "{suggestion['description']}"
'''

    def _generate_checkmarx_rule(self, suggestion: Dict, profile: Dict) -> str:
        """Generate Checkmarx CxQL rule."""
        rule_name = suggestion["name"].replace(" ", "_")
        cwe = suggestion.get("cwe_ids", ["CWE-0"])[0]

        if suggestion["category"] == "sql_injection":
            return f'''// Checkmarx CxQL Rule: {suggestion['name']}
// CWE: {cwe}
// Severity: {suggestion['severity'].upper()}

CxList inputs = Find_Interactive_Inputs();
CxList dbMethods = All.FindByMemberAccess("*.execute*") +
                   All.FindByMemberAccess("*.query*") +
                   All.FindByMemberAccess("*.raw*");

CxList stringConcats = dbMethods.DataInfluencedBy(inputs);

// Filter for actual SQL injection patterns
CxList sqlInjections = stringConcats.FindByType(typeof(BinaryExpr))
    .FindByShortName("*+*");

result = sqlInjections;
'''
        elif suggestion["category"] == "xss":
            return f'''// Checkmarx CxQL Rule: {suggestion['name']}
// CWE: {cwe}
// Severity: {suggestion['severity'].upper()}

CxList inputs = Find_Interactive_Inputs();
CxList outputs = All.FindByMemberAccess("*.write*") +
                 All.FindByMemberAccess("*.send*") +
                 All.FindByMemberAccess("*.innerHTML*");

CxList unsanitizedOutputs = outputs.DataInfluencedBy(inputs);

// Exclude properly sanitized outputs
CxList sanitizers = All.FindByMemberAccess("*.escape*") +
                    All.FindByMemberAccess("*.sanitize*") +
                    All.FindByMemberAccess("*.encode*");

result = unsanitizedOutputs - unsanitizedOutputs.DataInfluencedBy(sanitizers);
'''
        else:
            return f'''// Checkmarx CxQL Rule: {suggestion['name']}
// CWE: {cwe}
// Severity: {suggestion['severity'].upper()}
// Category: {suggestion['category']}

CxList inputs = Find_Interactive_Inputs();
CxList sinks = All.FindByName("*{suggestion.get('pattern_indicators', [''])[0]}*");

CxList vulnerablePaths = sinks.DataInfluencedBy(inputs);

result = vulnerablePaths;
'''

    def _generate_fortify_rule(self, suggestion: Dict, profile: Dict) -> str:
        """Generate Fortify rule in XML format."""
        rule_id = suggestion["name"].replace(" ", "_").upper()
        cwe = suggestion.get("cwe_ids", ["CWE-0"])[0]

        return f'''<?xml version="1.0" encoding="UTF-8"?>
<RulePack xmlns="xmlns://www.fortify.com/schema/rules">
  <RulePackID>{rule_id}</RulePackID>
  <SKU>SKU-CUSTOM-{suggestion['category'].upper()}</SKU>
  <Name>{suggestion['name']}</Name>
  <Version>1.0</Version>
  <Description>{suggestion['description']}</Description>
  <Rules>
    <Rule formatVersion="3.18" language="python,java,javascript">
      <MetaInfo>
        <Group name="category">{suggestion['category']}</Group>
        <Group name="owasp">{', '.join(suggestion.get('owasp_categories', []))}</Group>
        <Group name="cwe">{cwe}</Group>
      </MetaInfo>
      <RuleID>{rule_id}-001</RuleID>
      <VulnKingdom>{suggestion['category'].replace('_', ' ').title()}</VulnKingdom>
      <VulnCategory>{suggestion['category']}</VulnCategory>
      <VulnSubcategory>{suggestion.get('framework_context', 'Generic')}</VulnSubcategory>
      <DefaultSeverity>{4.0 if suggestion['severity'] == 'critical' else 3.0 if suggestion['severity'] == 'high' else 2.0}</DefaultSeverity>
      <Description>{suggestion['description']}</Description>
      <Recommendations>{suggestion['reason']}</Recommendations>
      <TaintFlags>
        <TaintFlag name="INPUT"/>
      </TaintFlags>
      <FunctionIdentifier>
        <NamespaceName>
          <Pattern>.*</Pattern>
        </NamespaceName>
        <ClassName>
          <Pattern>.*</Pattern>
        </ClassName>
        <FunctionName>
          <Pattern>{suggestion.get('pattern_indicators', ['.*'])[0].replace('(', '').replace(')', '')}</Pattern>
        </FunctionName>
      </FunctionIdentifier>
    </Rule>
  </Rules>
</RulePack>
'''

    def _calculate_confidence(self, suggestion: Dict, profile: Dict) -> float:
        """Calculate confidence score for a suggestion."""
        confidence = 0.5  # Base confidence

        # Increase confidence based on framework detection
        if suggestion.get("framework_context"):
            frameworks = [f.get("name") for f in profile.get("frameworks", [])]
            if suggestion["framework_context"] in frameworks:
                confidence += 0.2

        # Increase confidence based on pattern matches in profile
        entry_points = profile.get("entry_points", [])
        sensitive_fields = profile.get("sensitive_data_fields", [])

        if entry_points:
            confidence += 0.1
        if sensitive_fields:
            confidence += 0.1

        # Increase for auth rules if auth mechanisms detected
        if suggestion["category"] in ["auth_bypass", "session"]:
            auth_mechs = profile.get("auth_mechanisms", [])
            if auth_mechs:
                confidence += 0.1

        return min(confidence, 1.0)

    async def enhance_with_ai(
        self,
        suggestions: List[Dict],
        profile: Dict,
        code_samples: List[Dict] = None
    ) -> List[Dict]:
        """
        Enhance suggestions using AI for more context-specific rules.

        Args:
            suggestions: Existing suggestions to enhance
            profile: Application profile
            code_samples: Optional code samples for better context

        Returns:
            Enhanced suggestions with AI-generated patterns
        """
        if not self.ai_client:
            return suggestions

        try:
            # Prepare context for AI
            context = {
                "frameworks": profile.get("frameworks", []),
                "languages": profile.get("languages", {}),
                "auth_mechanisms": profile.get("auth_mechanisms", []),
                "entry_points": profile.get("entry_points", [])[:10],
                "sensitive_fields": profile.get("sensitive_data_fields", [])[:10]
            }

            prompt = f"""Based on this application profile:
{json.dumps(context, indent=2)}

Review and enhance these security rule suggestions:
{json.dumps([{
    'name': s['name'],
    'category': s['category'],
    'severity': s['severity'],
    'description': s['description']
} for s in suggestions[:10]], indent=2)}

For each rule, suggest:
1. More specific detection patterns based on the frameworks used
2. Potential false positive scenarios to exclude
3. Custom remediation advice for this specific tech stack

Return as JSON array with enhanced_pattern, false_positives, and remediation fields."""

            # Call AI for enhancement (implementation depends on AI client)
            # For now, return original suggestions
            logger.info("AI enhancement requested but not implemented")
            return suggestions

        except Exception as e:
            logger.error(f"AI enhancement failed: {str(e)}")
            return suggestions

    def get_rule_statistics(self, suggestions: List[Dict]) -> Dict[str, Any]:
        """Get statistics about generated rules."""
        stats = {
            "total": len(suggestions),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_category": {},
            "by_framework": {},
            "average_confidence": 0
        }

        total_confidence = 0
        for suggestion in suggestions:
            severity = suggestion.get("severity", "info")
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            category = suggestion.get("category", "other")
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

            framework = suggestion.get("framework_context", "generic")
            stats["by_framework"][framework] = stats["by_framework"].get(framework, 0) + 1

            total_confidence += suggestion.get("confidence_score", 0)

        if suggestions:
            stats["average_confidence"] = total_confidence / len(suggestions)

        return stats
