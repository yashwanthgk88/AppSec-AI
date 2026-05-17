# Railway: SQLite → PostgreSQL Cutover Runbook

> **Branch:** `feat/postgres-migration` ← this is the branch to deploy.
> **Estimated downtime:** under 5 minutes for the prod cutover (Phase D).
> **Data migration needed?** No — existing SQLite data is regeneratable test data.

This runbook lives next to the migration. Update it as you learn things during the staging dry run.

---

## Phase C — Staging dry run (zero prod impact)

Goal: prove the migration works end-to-end against your `postgres-staging` Railway instance before touching prod.

### C.1  Deploy the migration branch to staging

In the Railway dashboard:

1. Go to the `staging` environment.
2. Open the backend service → **Settings → Source**.
3. Change the deploy branch to `feat/postgres-migration`.
4. Open **Variables** and confirm `DATABASE_URL` is bound to `${{Postgres.DATABASE_URL}}` (the `postgres-staging` service's URL).
5. Trigger a redeploy.

Watch the deploy logs. Expected output during startup:
- `init_db()` issues `CREATE TABLE` for every SQLAlchemy model
- `_migrate_github_monitor_tables`, `_migrate_security_controls_tables`, etc. run their raw `CREATE TABLE IF NOT EXISTS` blocks (translated to Postgres-compatible SQL by the compat layer)
- The PRAGMA → `information_schema` translation runs once; on first deploy the ALTER TABLE branches add `false_positive`, `diff_snippet`, `files_detail`, etc. columns
- Uvicorn/gunicorn boots clean — no exceptions

If you see errors, see [Troubleshooting](#troubleshooting) at the bottom.

### C.2  Populate demo data

Once the service is live, populate test data:

```bash
# from your local machine, using Railway's CLI
railway link             # link to project
railway environment staging
railway run -s backend -- python3 seed_apex_banking.py
railway run -s backend -- python3 seed_github_monitor_demo.py
```

Both scripts pick up Railway's injected `DATABASE_URL` automatically (no config needed).

Expected output from `seed_github_monitor_demo.py`:

```
[seed] Connecting to /app/data/appsec.db   ← path arg is ignored in Postgres mode
[seed] Wiping any previous GitHub Monitor seed data
[seed] Inserting 3 monitored repositories
[seed] Inserting 6 developer profiles
[seed] Inserting baselines for 5 developers
[seed] Inserting 18 commit scans with findings/alerts/anomalies

┌─ GitHub Monitor demo data ─────────────────────────────────
│  Repositories:           3
│  Developers:             6
│  Commit scans:           18
│  SAST findings:          10+
│  Sensitive-file alerts:  2
│  Behavioural anomalies:  4+
│  AI threat analyses:     1
└────────────────────────────────────────────────────────────
```

### C.3  Smoke-test the UI on staging

Hit the staging URL and walk through each feature. The minimum acceptance set:

- [ ] **Login** works (any seeded user, or create a new admin)
- [ ] **Projects page** lists the "Apex Banking" demo project
- [ ] **Threat Model page** for that project renders STRIDE threats, attack paths, FAIR analysis
- [ ] **Vulnerabilities page** lists scan findings with severity badges
- [ ] **GitHub Monitor → Overview** shows the 3 monitored repos with risk distribution bars
- [ ] **GitHub Monitor → Commit Feed** shows 18 commits across the risk spectrum
- [ ] **GitHub Monitor → Developers** shows 6 profiles with baselines
- [ ] **GitHub Monitor → Anomalies** shows 4+ anomalies including Dana Kim's risk spike
- [ ] **GitHub Monitor → Commit detail** for Dana Kim's `d1e2f3g…` commit shows:
  - The two sensitive-file alerts (.env.production)
  - The three SAST findings
  - The AI threat assessment (threat_level: `intentional_insider`, confidence 0.85)
- [ ] **SecureReq** stories list renders with abuse cases + STRIDE threats
- [ ] **Settings** page loads (custom rules count is non-zero after seed)

Any failure here is a blocker — fix it before Phase D.

---

## Phase D — Production cutover

Goal: switch prod from SQLite to `postgres-prod` with under 5 min downtime.

**Pre-flight:** Phase C is fully green, including the smoke-test checklist.

### D.1  Announce the window

If you have any users in the system, post a maintenance message ahead of time. Pick a low-traffic window.

### D.2  Capture a snapshot of prod SQLite (safety net)

Even though we're regenerating data, take a snapshot before the cutover so we can compare/restore if anything's unexpectedly missing:

```bash
railway environment production
railway run -s backend -- cat /app/data/appsec.db > prod-appsec-$(date +%Y%m%d-%H%M).db
ls -lh prod-appsec-*.db    # should be ~176 MB
```

### D.3  Pause prod traffic

In Railway dashboard → production env → backend service:
- Either set **Replicas** to 0 (kills traffic immediately)
- Or temporarily change the start command to serve a maintenance page

### D.4  Deploy migration branch to production

- production env → backend service → **Settings → Source** → change deploy branch to `feat/postgres-migration`
- Confirm **Variables** → `DATABASE_URL` is bound to `${{Postgres.DATABASE_URL}}` (the `postgres-prod` service)
- Trigger redeploy

Wait for the deploy to complete (~2-3 min). Tables get created automatically during the FastAPI startup hooks.

### D.5  Run seeds (only if you want demo data in prod — optional)

```bash
railway run -s backend -- python3 seed_apex_banking.py
railway run -s backend -- python3 seed_github_monitor_demo.py
```

Skip this if prod should start empty. You can always seed later.

### D.6  Smoke-test prod

Run the same C.3 checklist against the prod URL. Three things in particular:

1. Login works.
2. A page that hits the database (e.g., Projects) renders without errors.
3. The Railway service logs show no `psycopg2.OperationalError`, no `UndefinedTable`, no `relation does not exist`.

### D.7  Bring traffic back

In Railway dashboard:
- Set **Replicas** back to the normal count (usually 1).
- Or revert the maintenance page if you used that approach.

### D.8  Watch the logs for 30 minutes

Tail the prod logs in Railway. Expected:
- Query response times comparable to or better than SQLite (Postgres is faster on most ops once the cache warms)
- Zero `UndefinedColumn`, `UndefinedTable`, `InFailedSqlTransaction`
- No deadlocks (the write-heavy github_* tables are most at risk)

---

## Rollback (if something goes sideways post-cutover)

If a problem surfaces in the 30-minute watch window:

1. **Revert** `DATABASE_URL` to the SQLite path: in Railway → backend Variables → temporarily delete the `DATABASE_URL` reference, so the code falls back to `/app/data/appsec.db` (which is still mounted from the volume).
2. **Redeploy** the previous backend image: Railway → Deployments → click the previous deploy → "Redeploy".
3. App is back on SQLite within ~3 minutes.
4. Investigate offline.

The prod volume mount stays in place during the migration, so SQLite is always one variable-flip away.

---

## Post-cutover (within 24 hours)

- [ ] **Rotate both Postgres passwords** in Railway (Postgres service → Variables → regenerate). Railway will auto-update `DATABASE_URL` for the backend.
- [ ] **Delete** the `prod-appsec-*.db` local snapshots once you're confident (keep for 30 days minimum).
- [ ] **Document** any issues you hit and add them to this runbook for next time.

---

## Troubleshooting

### "relation \"X\" does not exist"

The CREATE TABLE for table `X` didn't run. Either:
- The startup hook in `main.py` didn't reach that table's migration function (check logs for the order of operations)
- A column-existence ALTER ran before the table existed (rare; the order in main.py prevents this)

Manually run the migration:
```bash
railway run -s backend -- python3 -c "from main import _migrate_github_monitor_tables; _migrate_github_monitor_tables()"
```

### "InFailedSqlTransaction" after an early error

Postgres aborts a transaction on the first error and refuses further statements until a `ROLLBACK`. SQLite was lazier about this. If you see this, the underlying error is in the lines just above. Find that, fix it, redeploy.

### Seeds fail with "UNIQUE constraint" or "duplicate key"

The seed scripts are idempotent — they wipe existing seed rows first. If you see a unique-constraint error, the wipe step failed silently. Run the seed twice, or manually `DELETE FROM github_monitored_repos WHERE 1=1;` etc.

### "module 'utils.db_compat' has no attribute X"

You're running a seed script from a working tree that doesn't include `utils/db_compat.py` yet. Pull `feat/postgres-migration` first.

### Cursor returns rows but `row[0]` raises a `KeyError`

You're hitting `RealDictCursor` instead of `DictCursor`. They're different — only `DictCursor` supports positional access. The compat layer uses `DictCursor` deliberately. If you've edited the helper, double-check `cursor_factory=DictCursor` in `_PgConnection.__init__`.

---

## Quick reference — what changes between SQLite and Postgres for this app

| Concern | SQLite (before) | Postgres (after) |
|---|---|---|
| Connection | `sqlite3.connect("/app/data/appsec.db")` | `psycopg2.connect(DATABASE_URL)` via `utils.db_compat.connect()` |
| Schema | `Base.metadata.create_all()` + raw CREATE TABLE in `main.py` | Same — `CREATE TABLE IF NOT EXISTS` works on both |
| Parameters | `?` | Translated to `%s` by compat layer |
| `datetime('now')` | Native | Translated to `CURRENT_TIMESTAMP` |
| `PRAGMA table_info(t)` | Native | Translated to `information_schema.columns` query |
| `INSERT OR IGNORE` | Native | Translated to `INSERT ... ON CONFLICT DO NOTHING` |
| Row access | `row['col']` and `row[0]` both work | Same — `DictCursor` preserves both forms |
| Booleans | `0` / `1` integers | Same `0`/`1` integers in raw SQL (Postgres auto-casts to BOOLEAN where typed) |
| JSON columns | `TEXT` with `json.dumps()` | `TEXT` with `json.dumps()` — works as-is. (Optional follow-up: convert to native `JSONB` for queryability.) |

This is the "go fast" cut. A future "go careful" pass would migrate raw-SQL routes to SQLAlchemy ORM and convert JSON columns to native `JSONB` — both improvements but not blocking for production readiness.
