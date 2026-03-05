"""
Developer Behavioral Baseline Engine

Computes rolling behavioral baselines per developer from commit history
and detects anomalies when new commits deviate from established patterns.

Baseline metrics (requires ≥5 commits to activate, ≥20 for full confidence):
  - Commit timing:   mean hour, std dev → normal working window
  - Commit size:     avg/p90 additions, deletions, files changed
  - Risk pattern:    average historical risk score
  - Activity rate:   avg commits per week

Anomaly types detected:
  - off_hours_deviation:    commit outside developer's normal hours
  - large_commit_additions: lines added >> baseline (>5x avg)
  - large_commit_deletions: lines deleted >> baseline (>5x avg)
  - risk_spike:             risk score >> baseline avg (>3x avg)
"""
import math
import sqlite3
import logging
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Baseline thresholds
MIN_COMMITS_PARTIAL = 5       # enough for basic timing/size stats
MIN_COMMITS_ESTABLISHED = 20  # enough for z-score timing analysis
BASELINE_WINDOW = 60          # rolling window: use last N commits

# Anomaly detection sensitivity
SIZE_MULTIPLIER = 5.0         # flag additions/deletions > 5× baseline avg
SIZE_MIN_BASELINE = 20        # only flag if baseline avg > this (avoids noise on tiny commits)
TIMING_Z_MEDIUM = 2.0         # z-score for medium severity timing anomaly
TIMING_Z_HIGH = 3.0           # z-score for high severity timing anomaly
RISK_MULTIPLIER = 3.0         # flag if risk_score > 3× baseline avg
RISK_MIN_SCORE = 2.5          # only flag if new commit risk score is meaningful


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _std(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(sum((x - m) ** 2 for x in values) / len(values))


def _percentile(values: List[float], p: int) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(int(len(s) * p / 100), len(s) - 1)
    return s[idx]


class BaselineEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _conn(self):
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        return c

    # ------------------------------------------------------------------
    # Baseline computation
    # ------------------------------------------------------------------

    def compute_and_store(self, author_email: str) -> Dict:
        """
        Recompute baseline from the last BASELINE_WINDOW commits for this
        developer and upsert into github_developer_baselines.
        """
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """SELECT committed_at, additions, deletions, files_changed, risk_score
                   FROM github_commit_scans
                   WHERE author_email = ?
                   ORDER BY committed_at DESC LIMIT ?""",
                (author_email, BASELINE_WINDOW),
            )
            rows = [dict(r) for r in cur.fetchall()]
            n = len(rows)

            status = (
                "insufficient" if n < MIN_COMMITS_PARTIAL
                else "partial" if n < MIN_COMMITS_ESTABLISHED
                else "established"
            )

            # --- Timing --------------------------------------------------
            hours: List[float] = []
            for r in rows:
                try:
                    dt = datetime.fromisoformat(r["committed_at"].replace("Z", "+00:00"))
                    hours.append(float(dt.hour))
                except Exception:
                    pass

            mean_hour = _mean(hours) if hours else 12.0
            std_hour = max(_std(hours), 1.0)  # floor at 1 to avoid div-by-zero
            # Normal window: mean ± 1.5σ, clamped to 0-23
            hour_start = max(0, int(mean_hour - 1.5 * std_hour))
            hour_end = min(23, int(mean_hour + 1.5 * std_hour))

            # --- Size ----------------------------------------------------
            additions = [float(r["additions"] or 0) for r in rows]
            deletions = [float(r["deletions"] or 0) for r in rows]
            files = [float(r["files_changed"] or 0) for r in rows]

            avg_add = _mean(additions)
            avg_del = _mean(deletions)
            avg_files = _mean(files)
            p90_add = _percentile(additions, 90)
            p90_del = _percentile(deletions, 90)

            # --- Risk ----------------------------------------------------
            risks = [float(r["risk_score"] or 0) for r in rows]
            avg_risk = _mean(risks)

            # --- Activity frequency (commits / week) ---------------------
            avg_per_week = 1.0
            if n >= 2:
                try:
                    dates = [
                        datetime.fromisoformat(r["committed_at"].replace("Z", "+00:00"))
                        for r in rows
                        if r.get("committed_at")
                    ]
                    if dates:
                        span_days = max(1, (max(dates) - min(dates)).days)
                        avg_per_week = round(n / (span_days / 7.0), 2)
                except Exception:
                    pass

            cur.execute(
                """INSERT INTO github_developer_baselines
                       (author_email, typical_hour_start, typical_hour_end,
                        mean_commit_hour, std_commit_hour,
                        avg_additions, avg_deletions, avg_files_changed,
                        p90_additions, p90_deletions,
                        avg_risk_score, avg_commits_per_week,
                        commit_count_used, baseline_status,
                        computed_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))
                   ON CONFLICT(author_email) DO UPDATE SET
                       typical_hour_start=excluded.typical_hour_start,
                       typical_hour_end=excluded.typical_hour_end,
                       mean_commit_hour=excluded.mean_commit_hour,
                       std_commit_hour=excluded.std_commit_hour,
                       avg_additions=excluded.avg_additions,
                       avg_deletions=excluded.avg_deletions,
                       avg_files_changed=excluded.avg_files_changed,
                       p90_additions=excluded.p90_additions,
                       p90_deletions=excluded.p90_deletions,
                       avg_risk_score=excluded.avg_risk_score,
                       avg_commits_per_week=excluded.avg_commits_per_week,
                       commit_count_used=excluded.commit_count_used,
                       baseline_status=excluded.baseline_status,
                       updated_at=datetime('now')""",
                (
                    author_email, hour_start, hour_end,
                    round(mean_hour, 2), round(std_hour, 2),
                    round(avg_add, 1), round(avg_del, 1), round(avg_files, 1),
                    round(p90_add, 1), round(p90_del, 1),
                    round(avg_risk, 2), avg_per_week,
                    n, status,
                ),
            )
            conn.commit()

            return {
                "author_email": author_email,
                "baseline_status": status,
                "typical_hour_start": hour_start,
                "typical_hour_end": hour_end,
                "mean_commit_hour": round(mean_hour, 2),
                "std_commit_hour": round(std_hour, 2),
                "avg_additions": round(avg_add, 1),
                "avg_deletions": round(avg_del, 1),
                "avg_files_changed": round(avg_files, 1),
                "p90_additions": round(p90_add, 1),
                "p90_deletions": round(p90_del, 1),
                "avg_risk_score": round(avg_risk, 2),
                "avg_commits_per_week": avg_per_week,
                "commit_count_used": n,
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def detect_and_store(
        self,
        scan_id: int,
        author_email: str,
        committed_at: str,
        additions: int,
        deletions: int,
        files_changed: int,
        risk_score: float,
    ) -> List[Dict]:
        """
        Compare the new commit against the stored (pre-update) baseline.
        Detected anomalies are written to github_developer_anomalies.
        Returns the list of anomaly dicts.
        """
        conn = self._conn()
        anomalies: List[Dict] = []
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM github_developer_baselines WHERE author_email=?",
                (author_email,),
            )
            row = cur.fetchone()
            if not row:
                return []

            bl = dict(row)
            if bl["baseline_status"] == "insufficient":
                return []  # not enough data yet

            # --- 1. Timing anomaly ---------------------------------------
            try:
                dt = datetime.fromisoformat(committed_at.replace("Z", "+00:00"))
                hour = dt.hour
                mean_h = bl["mean_commit_hour"] or 12.0
                std_h = max(bl["std_commit_hour"] or 2.0, 1.0)
                z = abs(hour - mean_h) / std_h

                if bl["baseline_status"] == "established" and z >= TIMING_Z_MEDIUM:
                    severity = "high" if z >= TIMING_Z_HIGH else "medium"
                    anomalies.append({
                        "anomaly_type": "off_hours_deviation",
                        "description": (
                            f"Committed at {hour:02d}:00 — outside normal window "
                            f"({bl['typical_hour_start']:02d}:00–{bl['typical_hour_end']:02d}:00), "
                            f"z-score {z:.1f}"
                        ),
                        "baseline_value": mean_h,
                        "observed_value": float(hour),
                        "severity": severity,
                    })
                elif bl["baseline_status"] == "partial":
                    if hour < bl["typical_hour_start"] or hour > bl["typical_hour_end"]:
                        anomalies.append({
                            "anomaly_type": "off_hours_deviation",
                            "description": (
                                f"Committed at {hour:02d}:00 — outside typical window "
                                f"({bl['typical_hour_start']:02d}:00–{bl['typical_hour_end']:02d}:00)"
                            ),
                            "baseline_value": mean_h,
                            "observed_value": float(hour),
                            "severity": "low",
                        })
            except Exception:
                pass

            # --- 2. Large additions --------------------------------------
            avg_add = bl["avg_additions"] or 0
            if avg_add > SIZE_MIN_BASELINE and additions > avg_add * SIZE_MULTIPLIER:
                ratio = additions / avg_add
                anomalies.append({
                    "anomaly_type": "large_commit_additions",
                    "description": (
                        f"+{additions} lines added — {ratio:.1f}× above baseline avg "
                        f"(+{avg_add:.0f} lines)"
                    ),
                    "baseline_value": avg_add,
                    "observed_value": float(additions),
                    "severity": "high" if ratio > 10 else "medium",
                })

            # --- 3. Large deletions --------------------------------------
            avg_del = bl["avg_deletions"] or 0
            if avg_del > SIZE_MIN_BASELINE and deletions > avg_del * SIZE_MULTIPLIER:
                ratio = deletions / avg_del
                anomalies.append({
                    "anomaly_type": "large_commit_deletions",
                    "description": (
                        f"-{deletions} lines deleted — {ratio:.1f}× above baseline avg "
                        f"(-{avg_del:.0f} lines)"
                    ),
                    "baseline_value": avg_del,
                    "observed_value": float(deletions),
                    "severity": "high" if ratio > 10 else "medium",
                })

            # --- 4. Risk spike -------------------------------------------
            avg_risk = bl["avg_risk_score"] or 0
            if avg_risk > 0.5 and risk_score >= RISK_MIN_SCORE and risk_score > avg_risk * RISK_MULTIPLIER:
                ratio = risk_score / avg_risk
                anomalies.append({
                    "anomaly_type": "risk_spike",
                    "description": (
                        f"Risk score {risk_score:.1f} — {ratio:.1f}× above baseline avg "
                        f"({avg_risk:.1f})"
                    ),
                    "baseline_value": avg_risk,
                    "observed_value": risk_score,
                    "severity": "high",
                })

            # --- Store ---------------------------------------------------
            for a in anomalies:
                cur.execute(
                    """INSERT INTO github_developer_anomalies
                           (author_email, scan_id, anomaly_type, description,
                            baseline_value, observed_value, severity)
                       VALUES (?,?,?,?,?,?,?)""",
                    (
                        author_email, scan_id,
                        a["anomaly_type"], a["description"],
                        a.get("baseline_value"), a.get("observed_value"),
                        a["severity"],
                    ),
                )
            conn.commit()
            return anomalies

        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def get_baseline(self, author_email: str) -> Optional[Dict]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM github_developer_baselines WHERE author_email=?",
                (author_email,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_anomalies(self, author_email: str, limit: int = 50) -> List[Dict]:
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT da.*, gcs.sha, gcs.commit_message, gcs.risk_level
                   FROM github_developer_anomalies da
                   LEFT JOIN github_commit_scans gcs ON da.scan_id = gcs.id
                   WHERE da.author_email = ?
                   ORDER BY da.created_at DESC LIMIT ?""",
                (author_email, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
