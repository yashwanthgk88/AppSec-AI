# GitHub Monitor Demo Files

These files are **intentionally crafted test patterns** used to validate the AppSec Platform's GitHub Commit Monitor feature.

## What each file tests

| File | Risk Level | Rules Triggered |
|------|-----------|-----------------|
| `.env.example` | Sensitive File Alert | `.env` file pattern detection |
| `demo_credentials.py` | HIGH | Hardcoded AWS keys, credentials in logs |
| `demo_backdoor.py` | CRITICAL | Base64 exec, hidden routes, command injection |
| `demo_exfiltration.py` | HIGH | HTTP exfil, audit log deletion, PII in response |

## How to test

1. Go to **GitHub Monitor** in the sidebar
2. Navigate to **Monitored Repos** tab
3. Add `yashwanthgk88/AppSec-AI` and click **Scan Now**
4. Switch to **Commit Feed** — you should see these commits with risk badges
5. Click a high/critical commit to expand and see SAST findings
6. Check **Sensitive File Alerts** tab for the `.env.example` alert

## Expected results

- Commit #1: risk_level=`high`, sensitive_file alert for `.env.example`
- Commit #2: risk_level=`critical`, 3 SAST findings
- Commit #3: risk_level=`high`, 4 SAST findings
- Commit #4 (this README): risk_level=`clean`
