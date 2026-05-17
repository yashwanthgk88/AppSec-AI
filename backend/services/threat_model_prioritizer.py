"""
Threat-Model-Driven SAST Prioritizer
=====================================

Uses an existing STRIDE threat model (produced by ThreatModelingService) as a
"prior" over raw SAST findings. For each finding it:

  1. Matches the finding's file path to one or more threat model components.
  2. Looks up threats on those components (STRIDE + CWE overlap).
  3. Reranks severity: bumps findings on untrusted / internet-facing components,
     and on findings whose CWE is explicitly called out in the threat model.
  4. Tags each finding with a `threat_model_context` dict so reviewers see
     *why* it was reprioritized.

This is a reranker, not a filter: by default no findings are dropped. Pass
`suppress_trusted_low=True` to drop low/info findings on trusted components.

Only depends on plain dicts — safe to unit test without a DB.
"""

from typing import Any, Dict, List, Tuple
import re


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Generic directory/extension tokens we don't want to match on.
_STOPWORDS = {
    "src", "app", "lib", "internal", "pkg", "core", "main", "index",
    "test", "tests", "spec", "common", "utils", "util", "helpers",
    "backend", "frontend", "server", "client", "api", "v1", "v2",
    "py", "js", "ts", "java", "go", "php", "rb",
}

# Category → file-path keyword hints (coarse but useful).
_CATEGORY_HINTS: Dict[str, List[str]] = {
    "api": ["route", "router", "handler", "endpoint", "controller", "view"],
    "api_gateway": ["gateway", "route", "router", "proxy", "ingress"],
    "web_app": ["ui", "template", "page", "component", "view"],
    "frontend": ["ui", "template", "page", "component", "view", "dashboard"],
    "backend": ["service", "handler", "worker", "job"],
    "database": ["database", "model", "repository", "dao", "orm", "sql", "schema"],
    "datastore": ["database", "model", "repository", "dao", "store", "document"],
    "storage": ["store", "storage", "document", "blob", "bucket", "s3", "upload", "file"],
    "queue": ["queue", "worker", "task", "consumer", "producer", "kafka", "rabbit", "topic"],
    "messaging": ["queue", "worker", "topic", "pubsub", "kafka", "rabbit", "event", "message"],
    "cache": ["cache", "redis", "memcache"],
    "auth": ["auth", "login", "session", "token", "jwt", "oauth", "saml", "signup", "logout"],
    "file_storage": ["upload", "file", "storage", "s3", "blob"],
    "payment": ["payment", "billing", "checkout", "stripe", "invoice", "charge", "refund"],
}

# Keyword-in-name → file-path hints. Component names are usually more specific
# than categories ("Authentication Service" tells us more than "backend") so we
# expand based on keywords found anywhere in the component name.
_NAME_KEYWORD_HINTS: Dict[str, List[str]] = {
    "auth": ["auth", "login", "session", "token", "signup", "logout", "credential"],
    "authentication": ["auth", "login", "session", "token", "signup", "logout"],
    "login": ["login", "session", "auth", "signup"],
    "session": ["session", "login", "token"],
    "payment": ["payment", "billing", "checkout", "charge", "invoice", "stripe"],
    "billing": ["billing", "invoice", "charge", "subscription"],
    "checkout": ["checkout", "cart", "order"],
    "admin": ["admin", "dashboard", "management", "console"],
    "portal": ["portal", "dashboard", "home", "index"],
    "dashboard": ["dashboard", "home", "overview"],
    "banking": ["account", "transaction", "transfer", "balance", "contribution", "allocation"],
    "account": ["account", "profile", "user"],
    "user": ["user", "profile", "account"],
    "profile": ["profile", "user", "account"],
    "gateway": ["gateway", "route", "router", "proxy"],
    "api": ["route", "handler", "endpoint", "controller"],
    "web": ["view", "page", "template", "ui"],
    "mobile": ["mobile", "app"],
    "compliance": ["compliance", "audit", "policy", "rule"],
    "kyc": ["kyc", "identity", "verify", "document"],
    "document": ["document", "upload", "file", "attachment"],
    "kafka": ["kafka", "topic", "event", "message", "producer", "consumer"],
    "event": ["event", "message", "topic", "queue"],
    "engine": ["engine", "service", "processor", "worker"],
    "store": ["store", "storage", "repository", "dao"],
    "storage": ["storage", "store", "blob", "bucket"],
}


def _bump(severity: str, delta: int) -> str:
    severity = (severity or "medium").lower()
    if severity not in SEVERITY_ORDER:
        return severity
    idx = SEVERITY_ORDER.index(severity)
    return SEVERITY_ORDER[max(0, min(len(SEVERITY_ORDER) - 1, idx + delta))]


def _tokenize(text: str) -> List[str]:
    if not text:
        return []
    tokens = re.split(r"[^a-zA-Z0-9]+", text.lower())
    return [t for t in tokens if t and t not in _STOPWORDS and not t.isdigit()]


def build_component_index(threat_model: Any) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate per-component signals from a ThreatModel ORM row.

    Returns: { component_name: {
        "name", "category", "type", "internet_facing", "trust_level",
        "handles_sensitive_data", "max_severity", "cwes", "stride_categories",
        "threats", "name_tokens"
    } }
    """
    index: Dict[str, Dict[str, Any]] = {}

    stride = getattr(threat_model, "stride_analysis", None) or {}
    if not isinstance(stride, dict):
        return index

    for stride_cat, threats in stride.items():
        if not isinstance(threats, list):
            continue
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            comp_name = threat.get("component") or "Unknown"
            entry = index.setdefault(
                comp_name,
                {
                    "name": comp_name,
                    "category": threat.get("component_category", ""),
                    "type": threat.get("component_type", ""),
                    "internet_facing": False,
                    "trust_level": "unknown",
                    "handles_sensitive_data": False,
                    "max_severity": "info",
                    "cwes": set(),
                    "stride_categories": set(),
                    "threats": [],
                    "name_tokens": set(_tokenize(comp_name)),
                },
            )
            entry["stride_categories"].add(stride_cat)
            if threat.get("cwe"):
                entry["cwes"].add(str(threat["cwe"]).upper())
            sev = (threat.get("severity") or "info").lower()
            if SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index(entry["max_severity"]):
                entry["max_severity"] = sev
            # Some pipelines embed these at the threat level; accept them if present.
            if threat.get("internet_facing"):
                entry["internet_facing"] = True
            if threat.get("handles_sensitive_data"):
                entry["handles_sensitive_data"] = True
            if threat.get("trust_level"):
                entry["trust_level"] = threat["trust_level"]
            entry["threats"].append(
                {
                    "stride": stride_cat,
                    "threat": threat.get("threat", ""),
                    "severity": sev,
                    "cwe": threat.get("cwe", ""),
                }
            )

    # Merge in DFD-level trust/exposure hints if available.
    dfd = getattr(threat_model, "dfd_data", None) or {}
    nodes = dfd.get("nodes", []) if isinstance(dfd, dict) else []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        name = node.get("name") or node.get("label")
        if not name or name not in index:
            continue
        if node.get("internet_facing"):
            index[name]["internet_facing"] = True
        if node.get("trust_level"):
            index[name]["trust_level"] = node["trust_level"]
        if node.get("handles_sensitive_data"):
            index[name]["handles_sensitive_data"] = True

    return index


# Test / fixture path markers — these files are never runtime attack surface
# and must not inherit trust or severity from a runtime component.
_TEST_PATH_MARKERS = (
    "/test/", "/tests/", "/spec/", "/__tests__/", "/e2e/",
    "/__mocks__/", "/fixtures/", "/testdata/", "/mock/", "/mocks/",
)
_TEST_PATH_PREFIXES = (
    "test/", "tests/", "spec/", "e2e/",
)
_TEST_FILENAME_SUFFIXES = (
    "_test", "_spec", ".test", ".spec", "-test", "-spec",
)

# A name token must be at least this long to count for matching. Filters out
# generic words like "api", "web", "ui", "db" that match hundreds of files.
_MIN_STRONG_TOKEN_LEN = 5


def _is_test_file(file_path: str) -> bool:
    lp = file_path.lower().replace("\\", "/")
    if any(marker in lp for marker in _TEST_PATH_MARKERS):
        return True
    if any(lp.startswith(pfx) for pfx in _TEST_PATH_PREFIXES):
        return True
    base = lp.rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0] if "." in base else base
    return any(stem.endswith(sfx) for sfx in _TEST_FILENAME_SUFFIXES)


def _expand_component_hints(comp: Dict[str, Any]) -> set:
    """Build the set of weak hint tokens for a component (category + name-keyword).

    This is ONLY used for low-confidence tier matches. Uses exact token equality,
    never substring matching, to avoid spurious hits.
    """
    hints: set = set()
    category = (comp.get("category") or "").lower()
    hints.update(_CATEGORY_HINTS.get(category, []))
    comp_type = (comp.get("type") or "").lower()
    hints.update(_CATEGORY_HINTS.get(comp_type, []))
    # Name-keyword expansion: only trigger when a keyword is an EXACT token in
    # the component name. No substring matching — "authentication" will not
    # silently pull in hints from the "auth" key.
    for name_token in comp["name_tokens"]:
        extras = _NAME_KEYWORD_HINTS.get(name_token)
        if extras:
            hints.update(extras)
    return hints


def _match_components(
    finding: Dict[str, Any], index: Dict[str, Dict[str, Any]]
) -> List[Tuple[Dict[str, Any], str]]:
    """
    Return a list of (component, confidence) tuples the finding plausibly belongs to.

    Confidence tiers:
      * "high"   — explicit affected_paths mapping in the TM, OR
                   ≥2 strong (≥5 char) name-token overlaps with the file path.
      * "medium" — exactly 1 strong name-token overlap, token length ≥ 6.
      * "low"    — no name overlap, but ≥2 distinct category/name-keyword hint
                   tokens match. Tagging only — never drives severity change.

    Test / fixture files are never matched to runtime components at all.
    """
    file_path = finding.get("file_path") or ""
    if not file_path:
        return []
    if _is_test_file(file_path):
        return []

    path_tokens = set(_tokenize(file_path))
    if not path_tokens or not index:
        return []

    high: List[Tuple[int, Dict[str, Any]]] = []
    medium: List[Tuple[int, Dict[str, Any]]] = []
    low: List[Tuple[int, Dict[str, Any]]] = []

    for comp in index.values():
        # Tier 1a: explicit path mapping from the threat model (ground truth).
        explicit_paths = comp.get("affected_paths") or []
        if explicit_paths and any(
            file_path == p or file_path.startswith(p.rstrip("/") + "/")
            for p in explicit_paths
        ):
            high.append((1000, comp))
            continue

        # Tier 1b/2: name-token overlap. Only strong (≥5 char) tokens count to
        # avoid generic-word matches like "api" / "web" / "app".
        strong_tokens = {
            t for t in comp["name_tokens"] if len(t) >= _MIN_STRONG_TOKEN_LEN
        }
        overlap = path_tokens & strong_tokens

        if len(overlap) >= 2:
            high.append((10 * len(overlap), comp))
            continue
        if len(overlap) == 1:
            only = next(iter(overlap))
            if len(only) >= 6:
                medium.append((5, comp))
                continue
            # 5-char overlap alone isn't enough — fall through to low tier.

        # Tier 3: hint-only match. Require at least 2 distinct hint hits to
        # reduce noise, and only use this for tagging (not severity changes).
        hints = _expand_component_hints(comp)
        hint_hits = path_tokens & hints
        if len(hint_hits) >= 2:
            low.append((len(hint_hits), comp))

    # Return the strongest tier only — do not mix confidences on one finding.
    if high:
        high.sort(key=lambda x: x[0], reverse=True)
        return [(c, "high") for _, c in high[:3]]
    if medium:
        medium.sort(key=lambda x: x[0], reverse=True)
        return [(c, "medium") for _, c in medium[:3]]
    if low:
        low.sort(key=lambda x: x[0], reverse=True)
        return [(c, "low") for _, c in low[:3]]
    return []


def prioritize_findings(
    findings: List[Dict[str, Any]],
    threat_model: Any,
    suppress_trusted_low: bool = False,
) -> List[Dict[str, Any]]:
    """
    Rerank/annotate SAST findings against a threat model.

    Confidence-gated rules:
      * "high" or "medium" match, CWE overlap with a threat on the matched
        component → +2 tiers (capped), confidence recorded.
      * "high" or "medium" match, matched component is internet-facing or
        untrusted → +1 tier.
      * "high" match ONLY, matched component is explicitly trusted/internal
        AND original severity ≤ medium → -1 tier. Never downgrades high/critical.
      * "low" (hint-only) match → tag with context, NEVER change severity.
      * No match (including all test files) → leave finding untouched.
    """
    if not threat_model or not findings:
        return findings

    index = build_component_index(threat_model)
    if not index:
        return findings

    out: List[Dict[str, Any]] = []
    for finding in findings:
        original_severity = (finding.get("severity") or "medium").lower()
        new_severity = original_severity
        reasons: List[str] = []
        matches = _match_components(finding, index)

        if not matches:
            finding["threat_model_context"] = {
                "matched": False,
                "reason": (
                    "test/fixture file excluded from runtime match"
                    if _is_test_file(finding.get("file_path") or "")
                    else "no matching component in threat model"
                ),
            }
            out.append(finding)
            continue

        # All entries in `matches` share the same confidence tier by design.
        confidence = matches[0][1]
        matched_comps = [c for c, _ in matches]

        finding_cwe = str(finding.get("cwe_id") or "").upper()
        cwe_confirmed = False
        untrusted_hit = False
        trusted_hit = False

        for comp in matched_comps:
            if finding_cwe and finding_cwe in comp["cwes"]:
                cwe_confirmed = True
            if comp["internet_facing"] or comp["trust_level"] == "untrusted":
                untrusted_hit = True
            if comp["trust_level"] in ("trusted", "internal", "internal-only"):
                trusted_hit = True

        severity_changed = False
        if confidence in ("high", "medium"):
            if cwe_confirmed:
                new_severity = _bump(new_severity, 2)
                reasons.append(
                    f"CWE {finding_cwe} explicitly listed as a threat on matched component"
                )
                severity_changed = True
            if untrusted_hit:
                new_severity = _bump(new_severity, 1)
                reasons.append("matched component is internet-facing / untrusted")
                severity_changed = True

        # Downgrades are ONLY applied on "high" confidence matches, and only
        # for findings whose original severity is low/medium/info. Stale or
        # weak TM data must never hide a high/critical finding.
        can_downgrade = (
            confidence == "high"
            and original_severity in ("info", "low", "medium")
            and trusted_hit
            and not untrusted_hit
            and not cwe_confirmed
        )
        if can_downgrade:
            new_severity = _bump(new_severity, -1)
            reasons.append("matched component is trusted / internal-only")
            severity_changed = True

        if (
            suppress_trusted_low
            and confidence == "high"
            and trusted_hit
            and not cwe_confirmed
            and new_severity in ("info", "low")
        ):
            continue

        finding["severity"] = new_severity
        finding["threat_model_context"] = {
            "matched": True,
            "confidence": confidence,
            "matched_components": [c["name"] for c in matched_comps],
            "stride_categories": sorted(
                {s for c in matched_comps for s in c["stride_categories"]}
            ),
            "cwe_confirmed": cwe_confirmed,
            "original_severity": original_severity,
            "severity_changed": severity_changed,
            "rerank_reasons": reasons,
        }
        if cwe_confirmed and confidence in ("high", "medium"):
            finding["confidence"] = "high"
        out.append(finding)

    return out
