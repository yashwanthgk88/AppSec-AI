"""
Application Profiler Service
Analyzes application codebase to build security-relevant metadata for AI-powered rule suggestions.
"""

import os
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ApplicationProfiler:
    """Analyzes application codebase to build security-relevant metadata"""

    # File extension to language mapping
    LANGUAGE_EXTENSIONS = {
        '.py': 'Python',
        '.js': 'JavaScript',
        '.ts': 'TypeScript',
        '.tsx': 'TypeScript',
        '.jsx': 'JavaScript',
        '.java': 'Java',
        '.go': 'Go',
        '.rb': 'Ruby',
        '.php': 'PHP',
        '.cs': 'C#',
        '.cpp': 'C++',
        '.c': 'C',
        '.rs': 'Rust',
        '.swift': 'Swift',
        '.kt': 'Kotlin',
        '.scala': 'Scala',
        '.sql': 'SQL',
        '.html': 'HTML',
        '.css': 'CSS',
        '.scss': 'SCSS',
        '.vue': 'Vue',
        '.svelte': 'Svelte',
    }

    # Framework detection signatures
    FRAMEWORK_SIGNATURES = {
        # Python Frameworks
        'fastapi': {
            'files': ['main.py'],
            'imports': ['fastapi', 'FastAPI'],
            'type': 'backend',
            'language': 'Python'
        },
        'django': {
            'files': ['manage.py', 'settings.py', 'wsgi.py'],
            'imports': ['django'],
            'type': 'backend',
            'language': 'Python'
        },
        'flask': {
            'imports': ['flask', 'Flask'],
            'type': 'backend',
            'language': 'Python'
        },
        'sqlalchemy': {
            'imports': ['sqlalchemy', 'SQLAlchemy'],
            'type': 'orm',
            'language': 'Python'
        },
        'pydantic': {
            'imports': ['pydantic', 'BaseModel'],
            'type': 'validation',
            'language': 'Python'
        },
        'celery': {
            'imports': ['celery', 'Celery'],
            'type': 'task_queue',
            'language': 'Python'
        },

        # JavaScript/TypeScript Frameworks
        'react': {
            'deps': ['react', 'react-dom'],
            'type': 'frontend',
            'language': 'JavaScript'
        },
        'nextjs': {
            'files': ['next.config.js', 'next.config.mjs', 'next.config.ts'],
            'deps': ['next'],
            'type': 'fullstack',
            'language': 'JavaScript'
        },
        'express': {
            'deps': ['express'],
            'type': 'backend',
            'language': 'JavaScript'
        },
        'nestjs': {
            'deps': ['@nestjs/core'],
            'type': 'backend',
            'language': 'TypeScript'
        },
        'vue': {
            'deps': ['vue'],
            'type': 'frontend',
            'language': 'JavaScript'
        },
        'angular': {
            'deps': ['@angular/core'],
            'type': 'frontend',
            'language': 'TypeScript'
        },
        'prisma': {
            'deps': ['@prisma/client'],
            'files': ['prisma/schema.prisma'],
            'type': 'orm',
            'language': 'TypeScript'
        },

        # Java Frameworks
        'spring': {
            'files': ['pom.xml'],
            'imports': ['org.springframework'],
            'type': 'backend',
            'language': 'Java'
        },
        'hibernate': {
            'imports': ['org.hibernate', 'javax.persistence'],
            'type': 'orm',
            'language': 'Java'
        },

        # Go Frameworks
        'gin': {
            'imports': ['github.com/gin-gonic/gin'],
            'type': 'backend',
            'language': 'Go'
        },
        'echo': {
            'imports': ['github.com/labstack/echo'],
            'type': 'backend',
            'language': 'Go'
        },
    }

    # Sensitive data field patterns
    SENSITIVE_PATTERNS = {
        'password': {
            'pattern': r'[\w_]*(password|passwd|pwd|secret|pass_?word)[\w_]*',
            'category': 'credential',
            'severity': 'critical'
        },
        'api_key': {
            'pattern': r'[\w_]*(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)[\w_]*',
            'category': 'credential',
            'severity': 'critical'
        },
        'token': {
            'pattern': r'[\w_]*(token|jwt|bearer|auth[_-]?token|access[_-]?token|refresh[_-]?token)[\w_]*',
            'category': 'credential',
            'severity': 'high'
        },
        'credit_card': {
            'pattern': r'[\w_]*(credit[_-]?card|card[_-]?number|ccn|cvv|cvc|card[_-]?num)[\w_]*',
            'category': 'pci',
            'severity': 'critical'
        },
        'ssn': {
            'pattern': r'[\w_]*(ssn|social[_-]?security|social[_-]?sec)[\w_]*',
            'category': 'pii',
            'severity': 'critical'
        },
        'email': {
            'pattern': r'[\w_]*(email|e[_-]?mail)[\w_]*',
            'category': 'pii',
            'severity': 'medium'
        },
        'phone': {
            'pattern': r'[\w_]*(phone|mobile|cell|telephone)[\w_]*',
            'category': 'pii',
            'severity': 'medium'
        },
        'address': {
            'pattern': r'[\w_]*(address|street|city|zip[_-]?code|postal)[\w_]*',
            'category': 'pii',
            'severity': 'low'
        },
        'private_key': {
            'pattern': r'[\w_]*(private[_-]?key|priv[_-]?key|rsa[_-]?key)[\w_]*',
            'category': 'credential',
            'severity': 'critical'
        },
    }

    # External service/integration patterns
    INTEGRATION_PATTERNS = {
        'stripe': {
            'imports': ['stripe'],
            'env_vars': ['STRIPE_SECRET_KEY', 'STRIPE_API_KEY'],
            'type': 'payment'
        },
        'paypal': {
            'imports': ['paypal'],
            'env_vars': ['PAYPAL_CLIENT_ID'],
            'type': 'payment'
        },
        'aws_s3': {
            'imports': ['boto3', '@aws-sdk/client-s3', 'aws-sdk'],
            'env_vars': ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'S3_BUCKET'],
            'type': 'cloud_storage'
        },
        'aws_ses': {
            'imports': ['@aws-sdk/client-ses'],
            'type': 'email'
        },
        'sendgrid': {
            'imports': ['@sendgrid/mail', 'sendgrid'],
            'env_vars': ['SENDGRID_API_KEY'],
            'type': 'email'
        },
        'twilio': {
            'imports': ['twilio'],
            'env_vars': ['TWILIO_ACCOUNT_SID'],
            'type': 'sms'
        },
        'firebase': {
            'imports': ['firebase', 'firebase-admin'],
            'type': 'backend_service'
        },
        'mongodb': {
            'imports': ['pymongo', 'mongoose', 'mongodb'],
            'type': 'database'
        },
        'redis': {
            'imports': ['redis', 'ioredis'],
            'type': 'cache'
        },
        'elasticsearch': {
            'imports': ['elasticsearch', '@elastic/elasticsearch'],
            'type': 'search'
        },
        'rabbitmq': {
            'imports': ['pika', 'amqplib'],
            'type': 'message_queue'
        },
        'kafka': {
            'imports': ['kafka-python', 'kafkajs'],
            'type': 'message_queue'
        },
    }

    # Directories to skip during analysis
    SKIP_DIRECTORIES = {
        'node_modules', 'venv', '.venv', 'env', '.env', '.git', '__pycache__',
        'dist', 'build', '.next', '.nuxt', 'target', 'bin', 'obj',
        'vendor', 'packages', '.idea', '.vscode', 'coverage', '.pytest_cache',
        'migrations', 'static', 'public/assets'
    }

    def __init__(self):
        self.progress_callback = None

    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self.progress_callback = callback

    def update_progress(self, progress: int, message: str):
        """Update profiling progress"""
        if self.progress_callback:
            self.progress_callback(progress, message)

    async def profile_application(self, project_path: str, progress_callback=None) -> Dict[str, Any]:
        """
        Generate comprehensive application profile.
        Returns a dictionary with all analyzed metadata.

        Args:
            project_path: Path to the project directory
            progress_callback: Optional callback function(progress: int, message: str) for progress updates
        """
        # Set the progress callback if provided
        if progress_callback:
            self.set_progress_callback(progress_callback)
        profile = {
            'languages': {},
            'frameworks': [],
            'databases': [],
            'orm_libraries': [],
            'entry_points': [],
            'sensitive_data_fields': [],
            'auth_mechanisms': [],
            'dependencies': {},
            'dev_dependencies': {},
            'external_integrations': [],
            'cloud_services': [],
            'file_count': 0,
            'total_lines_of_code': 0,
            'security_concerns': [],
        }

        if not os.path.exists(project_path):
            raise ValueError(f"Project path does not exist: {project_path}")

        self.update_progress(5, "Starting application analysis...")

        # Step 1: Detect languages (10-20%)
        self.update_progress(10, "Detecting programming languages...")
        profile['languages'], profile['file_count'], profile['total_lines_of_code'] = \
            self._detect_languages(project_path)

        # Step 2: Detect frameworks (20-35%)
        self.update_progress(20, "Detecting frameworks and libraries...")
        profile['frameworks'] = self._detect_frameworks(project_path)

        # Extract databases and ORMs from frameworks
        for fw in profile['frameworks']:
            if fw.get('type') == 'orm':
                profile['orm_libraries'].append(fw['name'])
            if fw.get('type') == 'database':
                profile['databases'].append(fw['name'])

        # Step 3: Analyze dependencies (35-45%)
        self.update_progress(35, "Analyzing dependencies...")
        deps_result = self._analyze_dependencies(project_path)
        profile['dependencies'] = deps_result.get('dependencies', {})
        profile['dev_dependencies'] = deps_result.get('dev_dependencies', {})

        # Step 4: Find entry points (45-60%)
        self.update_progress(45, "Finding API entry points...")
        profile['entry_points'] = self._find_entry_points(project_path)

        # Step 5: Find sensitive data fields (60-75%)
        self.update_progress(60, "Scanning for sensitive data fields...")
        profile['sensitive_data_fields'] = self._find_sensitive_data(project_path)

        # Step 6: Detect auth mechanisms (75-85%)
        self.update_progress(75, "Detecting authentication mechanisms...")
        profile['auth_mechanisms'] = self._detect_auth_mechanisms(project_path)

        # Step 7: Detect external integrations (85-95%)
        self.update_progress(85, "Detecting external integrations...")
        integrations = self._detect_integrations(project_path)
        profile['external_integrations'] = integrations.get('services', [])
        profile['cloud_services'] = integrations.get('cloud', [])

        # Step 8: Calculate security score (95-100%)
        self.update_progress(95, "Calculating security posture...")
        profile['security_score'], profile['risk_level'] = self._calculate_security_score(profile)

        self.update_progress(100, "Profiling complete!")

        return profile

    def _detect_languages(self, path: str) -> Tuple[Dict[str, float], int, int]:
        """Detect programming languages and calculate percentages"""
        counts = {}
        total_files = 0
        total_lines = 0

        for root, dirs, files in os.walk(path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRECTORIES]

            for file in files:
                ext = Path(file).suffix.lower()
                if ext in self.LANGUAGE_EXTENSIONS:
                    lang = self.LANGUAGE_EXTENSIONS[ext]
                    filepath = os.path.join(root, file)

                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = len(f.readlines())
                            counts[lang] = counts.get(lang, 0) + lines
                            total_lines += lines
                            total_files += 1
                    except Exception:
                        pass

        # Convert to percentages
        if total_lines > 0:
            percentages = {
                lang: round((count / total_lines) * 100, 1)
                for lang, count in counts.items()
            }
        else:
            percentages = {}

        return percentages, total_files, total_lines

    def _detect_frameworks(self, path: str) -> List[Dict[str, str]]:
        """Detect frameworks and their versions"""
        detected = []
        seen = set()

        # Check package.json for JS/TS frameworks
        pkg_json_path = os.path.join(path, 'package.json')
        if os.path.exists(pkg_json_path):
            try:
                with open(pkg_json_path, 'r') as f:
                    pkg = json.load(f)
                    deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}

                    for framework, sig in self.FRAMEWORK_SIGNATURES.items():
                        if 'deps' in sig:
                            for dep in sig['deps']:
                                if dep in deps and framework not in seen:
                                    detected.append({
                                        'name': framework.title(),
                                        'version': deps[dep].replace('^', '').replace('~', ''),
                                        'type': sig.get('type', 'unknown'),
                                        'language': sig.get('language', 'JavaScript')
                                    })
                                    seen.add(framework)
            except Exception as e:
                logger.warning(f"Error reading package.json: {e}")

        # Check requirements.txt for Python frameworks
        req_files = ['requirements.txt', 'requirements/base.txt', 'requirements/prod.txt']
        for req_file in req_files:
            req_path = os.path.join(path, req_file)
            if os.path.exists(req_path):
                try:
                    with open(req_path, 'r') as f:
                        requirements = f.read().lower()

                        for framework, sig in self.FRAMEWORK_SIGNATURES.items():
                            if framework not in seen and sig.get('language') == 'Python':
                                if 'imports' in sig:
                                    for imp in sig['imports']:
                                        if imp.lower() in requirements:
                                            # Extract version if present
                                            version_match = re.search(
                                                rf"{imp.lower()}[=<>~]+([0-9.]+)",
                                                requirements
                                            )
                                            version = version_match.group(1) if version_match else 'unknown'

                                            detected.append({
                                                'name': framework.title(),
                                                'version': version,
                                                'type': sig.get('type', 'unknown'),
                                                'language': 'Python'
                                            })
                                            seen.add(framework)
                                            break
                except Exception as e:
                    logger.warning(f"Error reading {req_file}: {e}")

        # Check for framework files
        for framework, sig in self.FRAMEWORK_SIGNATURES.items():
            if framework not in seen and 'files' in sig:
                for sig_file in sig['files']:
                    if os.path.exists(os.path.join(path, sig_file)):
                        detected.append({
                            'name': framework.title(),
                            'version': 'detected',
                            'type': sig.get('type', 'unknown'),
                            'language': sig.get('language', 'unknown')
                        })
                        seen.add(framework)
                        break

        return detected

    def _analyze_dependencies(self, path: str) -> Dict[str, Dict]:
        """Analyze project dependencies"""
        result = {'dependencies': {}, 'dev_dependencies': {}}

        # package.json
        pkg_json_path = os.path.join(path, 'package.json')
        if os.path.exists(pkg_json_path):
            try:
                with open(pkg_json_path, 'r') as f:
                    pkg = json.load(f)
                    result['dependencies'].update(pkg.get('dependencies', {}))
                    result['dev_dependencies'].update(pkg.get('devDependencies', {}))
            except Exception:
                pass

        # requirements.txt
        req_path = os.path.join(path, 'requirements.txt')
        if os.path.exists(req_path):
            try:
                with open(req_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Parse package==version or package>=version
                            match = re.match(r'^([a-zA-Z0-9_-]+)[=<>~]+(.+)$', line)
                            if match:
                                result['dependencies'][match.group(1)] = match.group(2)
                            elif re.match(r'^[a-zA-Z0-9_-]+$', line):
                                result['dependencies'][line] = 'latest'
            except Exception:
                pass

        # pyproject.toml
        pyproject_path = os.path.join(path, 'pyproject.toml')
        if os.path.exists(pyproject_path):
            try:
                with open(pyproject_path, 'r') as f:
                    content = f.read()
                    # Simple parsing for dependencies section
                    in_deps = False
                    for line in content.split('\n'):
                        if '[project.dependencies]' in line or '[tool.poetry.dependencies]' in line:
                            in_deps = True
                        elif line.startswith('[') and in_deps:
                            in_deps = False
                        elif in_deps and '=' in line:
                            parts = line.split('=')
                            if len(parts) == 2:
                                pkg = parts[0].strip().strip('"')
                                ver = parts[1].strip().strip('"')
                                result['dependencies'][pkg] = ver
            except Exception:
                pass

        return result

    def _find_entry_points(self, path: str) -> List[Dict[str, Any]]:
        """Find API endpoints and routes"""
        entry_points = []

        # Route patterns for different frameworks
        route_patterns = [
            # FastAPI
            (r'@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'FastAPI'),
            # Flask
            (r'@(?:app|blueprint)\.(route)\s*\(\s*["\']([^"\']+)["\']', 'Flask'),
            # Express
            (r'(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'Express'),
            # Django URLs
            (r'path\s*\(\s*["\']([^"\']+)["\']', 'Django'),
            # Spring
            (r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(\s*["\']([^"\']+)["\']', 'Spring'),
            # NestJS
            (r'@(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']', 'NestJS'),
        ]

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRECTORIES]

            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.go')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            lines = content.split('\n')

                            for pattern, framework in route_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    groups = match.groups()
                                    if len(groups) >= 2:
                                        method = groups[0].upper()
                                        route = groups[1]
                                    else:
                                        method = 'GET'
                                        route = groups[0]

                                    # Find line number
                                    line_num = content[:match.start()].count('\n') + 1

                                    # Assess risk
                                    risk_indicators = self._assess_endpoint_risk(route, method)

                                    entry_points.append({
                                        'method': method,
                                        'path': route,
                                        'file': filepath.replace(path, '').lstrip('/\\'),
                                        'line': line_num,
                                        'framework': framework,
                                        'risk_indicators': risk_indicators
                                    })
                    except Exception:
                        pass

        return entry_points[:100]  # Limit to 100 most relevant

    def _assess_endpoint_risk(self, route: str, method: str) -> List[str]:
        """Assess security risk indicators for an endpoint"""
        risks = []
        route_lower = route.lower()

        # High-risk endpoint patterns
        if any(p in route_lower for p in ['/auth', '/login', '/signin', '/token', '/password', '/register']):
            risks.append('authentication')
        if any(p in route_lower for p in ['/payment', '/checkout', '/billing', '/card', '/stripe', '/paypal']):
            risks.append('payment_processing')
        if any(p in route_lower for p in ['/admin', '/manage', '/config', '/settings', '/dashboard']):
            risks.append('admin_access')
        if any(p in route_lower for p in ['/upload', '/file', '/import', '/export', '/download']):
            risks.append('file_handling')
        if any(p in route_lower for p in ['/user', '/profile', '/account', '/me']):
            risks.append('pii_handling')
        if any(p in route_lower for p in ['/api/v', '/graphql', '/webhook']):
            risks.append('api_endpoint')

        # Dynamic routing detection
        if '{' in route or ':' in route or '<' in route:
            risks.append('dynamic_routing')

        # State modification
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            risks.append('state_modification')

        return risks

    def _find_sensitive_data(self, path: str) -> List[Dict[str, Any]]:
        """Find sensitive data field definitions"""
        sensitive_fields = []
        seen = set()

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRECTORIES]

            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.go', '.cs')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            for name, config in self.SENSITIVE_PATTERNS.items():
                                pattern = config['pattern']
                                matches = re.finditer(
                                    rf'({pattern})\s*[:=]',
                                    content,
                                    re.IGNORECASE
                                )

                                for match in matches:
                                    field = match.group(1)
                                    # Avoid duplicates
                                    key = f"{filepath}:{field}"
                                    if key in seen:
                                        continue
                                    seen.add(key)

                                    line_num = content[:match.start()].count('\n') + 1

                                    sensitive_fields.append({
                                        'field': field,
                                        'category': config['category'],
                                        'severity': config['severity'],
                                        'file': filepath.replace(path, '').lstrip('/\\'),
                                        'line': line_num,
                                        'type': name
                                    })
                    except Exception:
                        pass

        return sensitive_fields[:200]  # Limit results

    def _detect_auth_mechanisms(self, path: str) -> List[str]:
        """Detect authentication mechanisms used in the project"""
        auth_patterns = {
            'JWT': [r'jwt', r'jsonwebtoken', r'python-jose', r'PyJWT'],
            'OAuth2': [r'oauth2?', r'authlib', r'passport-oauth'],
            'Session': [r'session', r'express-session', r'flask-login'],
            'API Key': [r'api[_-]?key', r'x-api-key'],
            'Basic Auth': [r'basic[_-]?auth', r'HTTPBasicCredentials'],
            'Bearer Token': [r'bearer', r'Authorization.*Bearer'],
            'SAML': [r'saml', r'python3-saml'],
            'LDAP': [r'ldap', r'ldap3'],
            'Passport': [r'passport'],
            'Auth0': [r'auth0'],
            'Firebase Auth': [r'firebase.*auth'],
            'Cognito': [r'cognito', r'amazon-cognito'],
        }

        detected = set()

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRECTORIES]

            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.go', '.json', '.yaml', '.yml')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().lower()

                            for auth_type, patterns in auth_patterns.items():
                                for pattern in patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        detected.add(auth_type)
                                        break
                    except Exception:
                        pass

        return list(detected)

    def _detect_integrations(self, path: str) -> Dict[str, List[str]]:
        """Detect external service integrations"""
        services = set()
        cloud_providers = set()

        # Cloud provider patterns
        cloud_patterns = {
            'AWS': [r'aws', r'boto3', r's3://', r'amazonaws\.com'],
            'GCP': [r'google-cloud', r'@google-cloud', r'googleapis'],
            'Azure': [r'azure', r'@azure', r'blob\.core\.windows\.net'],
            'Heroku': [r'heroku'],
            'Vercel': [r'vercel'],
            'Netlify': [r'netlify'],
            'DigitalOcean': [r'digitalocean', r'spaces\.'],
        }

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRECTORIES]

            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.go', '.json', '.yaml', '.yml', '.env', '.env.example')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            # Check for integrations
                            for service, config in self.INTEGRATION_PATTERNS.items():
                                if 'imports' in config:
                                    for imp in config['imports']:
                                        if imp.lower() in content.lower():
                                            services.add(f"{service.replace('_', ' ').title()} ({config['type']})")
                                            break
                                if 'env_vars' in config:
                                    for env_var in config['env_vars']:
                                        if env_var in content:
                                            services.add(f"{service.replace('_', ' ').title()} ({config['type']})")
                                            break

                            # Check for cloud providers
                            for provider, patterns in cloud_patterns.items():
                                for pattern in patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        cloud_providers.add(provider)
                                        break
                    except Exception:
                        pass

        return {
            'services': list(services),
            'cloud': list(cloud_providers)
        }

    def _calculate_security_score(self, profile: Dict) -> Tuple[float, str]:
        """Calculate overall security score and risk level"""
        score = 100.0
        deductions = []

        # Deductions for sensitive data handling
        critical_sensitive = sum(1 for f in profile['sensitive_data_fields'] if f.get('severity') == 'critical')
        high_sensitive = sum(1 for f in profile['sensitive_data_fields'] if f.get('severity') == 'high')

        if critical_sensitive > 5:
            score -= 15
            deductions.append(f"Many critical sensitive data fields ({critical_sensitive})")
        elif critical_sensitive > 0:
            score -= critical_sensitive * 2
            deductions.append(f"Critical sensitive data fields found ({critical_sensitive})")

        if high_sensitive > 10:
            score -= 10
        elif high_sensitive > 0:
            score -= high_sensitive

        # Deductions for risky endpoints
        auth_endpoints = sum(1 for e in profile['entry_points'] if 'authentication' in e.get('risk_indicators', []))
        payment_endpoints = sum(1 for e in profile['entry_points'] if 'payment_processing' in e.get('risk_indicators', []))
        admin_endpoints = sum(1 for e in profile['entry_points'] if 'admin_access' in e.get('risk_indicators', []))
        file_endpoints = sum(1 for e in profile['entry_points'] if 'file_handling' in e.get('risk_indicators', []))

        if auth_endpoints > 0 and 'JWT' not in profile['auth_mechanisms'] and 'OAuth2' not in profile['auth_mechanisms']:
            score -= 10
            deductions.append("Auth endpoints without modern auth mechanisms")

        if payment_endpoints > 0:
            score -= 5
            deductions.append(f"Payment processing endpoints detected ({payment_endpoints})")

        if admin_endpoints > 5:
            score -= 5
            deductions.append(f"Many admin endpoints ({admin_endpoints})")

        if file_endpoints > 0:
            score -= 3
            deductions.append(f"File handling endpoints detected ({file_endpoints})")

        # Bonus for good practices
        if 'JWT' in profile['auth_mechanisms'] or 'OAuth2' in profile['auth_mechanisms']:
            score = min(100, score + 5)

        if any(fw.get('name', '').lower() == 'pydantic' for fw in profile['frameworks']):
            score = min(100, score + 3)  # Input validation

        # Ensure score is within bounds
        score = max(0, min(100, score))

        # Determine risk level
        if score >= 80:
            risk_level = 'low'
        elif score >= 60:
            risk_level = 'medium'
        elif score >= 40:
            risk_level = 'high'
        else:
            risk_level = 'critical'

        return round(score, 1), risk_level
