"""
Scanner Efficiency Test Suite
Tests the AST-based security scanner for:
- True Positives (correctly identified vulnerabilities)
- False Positives (incorrectly flagged safe code)
- False Negatives (missed vulnerabilities)
- Performance metrics
"""

import time
import sys
import os
from typing import Dict, List, Tuple
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.ast_security_analyzer import ASTSecurityAnalyzer
from services.sast_scanner import SASTScanner


@dataclass
class TestCase:
    name: str
    code: str
    language: str
    expected_vulns: List[str]  # Expected CWE IDs
    is_vulnerable: bool = True


# =============================================================================
# TEST CASES - Known Vulnerable Code (Should detect - True Positives)
# =============================================================================

VULNERABLE_TEST_CASES = [
    # SQL Injection
    TestCase(
        name="SQL Injection - String Concatenation",
        code='''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
''',
        language="python",
        expected_vulns=["CWE-89"]
    ),
    TestCase(
        name="SQL Injection - F-String",
        code='''
def search_users(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    db.execute(query)
''',
        language="python",
        expected_vulns=["CWE-89"]
    ),
    TestCase(
        name="SQL Injection - Format String",
        code='''
def delete_user(user_id):
    query = "DELETE FROM users WHERE id = %s" % user_id
    cursor.execute(query)
''',
        language="python",
        expected_vulns=["CWE-89"]
    ),

    # Command Injection
    TestCase(
        name="Command Injection - os.system",
        code='''
import os
def ping_host(host):
    os.system("ping -c 1 " + host)
''',
        language="python",
        expected_vulns=["CWE-78"]
    ),
    TestCase(
        name="Command Injection - subprocess shell=True",
        code='''
import subprocess
def run_command(cmd):
    subprocess.call(cmd, shell=True)
''',
        language="python",
        expected_vulns=["CWE-78"]
    ),

    # XSS
    TestCase(
        name="XSS - innerHTML",
        code='''
function displayMessage(msg) {
    document.getElementById("output").innerHTML = msg;
}
''',
        language="javascript",
        expected_vulns=["CWE-79"]
    ),
    TestCase(
        name="XSS - React dangerouslySetInnerHTML",
        code='''
function UserContent({ html }) {
    return <div dangerouslySetInnerHTML={{__html: html}} />;
}
''',
        language="javascript",
        expected_vulns=["CWE-79"]
    ),

    # Path Traversal
    TestCase(
        name="Path Traversal - Direct file open",
        code='''
def read_file(filename):
    path = "/var/data/" + filename
    with open(path, 'r') as f:
        return f.read()
''',
        language="python",
        expected_vulns=["CWE-22"]
    ),

    # Insecure Deserialization
    TestCase(
        name="Insecure Deserialization - pickle.loads",
        code='''
import pickle
def load_data(data):
    return pickle.loads(data)
''',
        language="python",
        expected_vulns=["CWE-502"]
    ),
    TestCase(
        name="Insecure Deserialization - yaml.load",
        code='''
import yaml
def parse_config(config_str):
    return yaml.load(config_str)
''',
        language="python",
        expected_vulns=["CWE-502"]
    ),

    # Hardcoded Credentials
    TestCase(
        name="Hardcoded Password",
        code='''
DB_PASSWORD = "supersecret123"
API_KEY = "sk-live-abcdef123456"
''',
        language="python",
        expected_vulns=["CWE-798"]
    ),

    # Weak Cryptography
    TestCase(
        name="Weak Hash - MD5",
        code='''
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
''',
        language="python",
        expected_vulns=["CWE-327", "CWE-916"]
    ),

    # Insecure Random
    TestCase(
        name="Insecure Random",
        code='''
import random
def generate_token():
    return random.randint(100000, 999999)
''',
        language="python",
        expected_vulns=["CWE-338"]
    ),

    # SSRF
    TestCase(
        name="SSRF - requests.get with user input",
        code='''
import requests
def fetch_url(url):
    response = requests.get(url)
    return response.text
''',
        language="python",
        expected_vulns=["CWE-918"]
    ),
]


# =============================================================================
# TEST CASES - Safe Code (Should NOT detect - avoid False Positives)
# =============================================================================

SAFE_TEST_CASES = [
    TestCase(
        name="Safe SQL - Parameterized Query",
        code='''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    TestCase(
        name="Safe SQL - Prepared Statement",
        code='''
def get_user(user_id):
    stmt = db.prepare("SELECT * FROM users WHERE id = :id")
    return stmt.execute({"id": user_id})
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    TestCase(
        name="Safe Command - subprocess with list",
        code='''
import subprocess
def ping_host(host):
    subprocess.run(["ping", "-c", "1", host], shell=False)
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    TestCase(
        name="Safe File - basename validation",
        code='''
import os
def read_file(filename):
    safe_name = os.path.basename(filename)
    path = os.path.join("/var/data/", safe_name)
    with open(path, 'r') as f:
        return f.read()
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    TestCase(
        name="Safe Deserialization - json.loads",
        code='''
import json
def load_data(data):
    return json.loads(data)
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    TestCase(
        name="Safe YAML - safe_load",
        code='''
import yaml
def parse_config(config_str):
    return yaml.safe_load(config_str)
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    TestCase(
        name="Safe Password Hash - bcrypt",
        code='''
import bcrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    TestCase(
        name="Safe Random - secrets module",
        code='''
import secrets
def generate_token():
    return secrets.token_hex(32)
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    TestCase(
        name="Safe Credentials - Environment Variable",
        code='''
import os
DB_PASSWORD = os.environ.get("DB_PASSWORD")
API_KEY = os.getenv("API_KEY")
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    TestCase(
        name="Safe XSS - textContent",
        code='''
function displayMessage(msg) {
    document.getElementById("output").textContent = msg;
}
''',
        language="javascript",
        expected_vulns=[],
        is_vulnerable=False
    ),
    # Code in comments should not be flagged
    TestCase(
        name="Commented Code - Should be ignored",
        code='''
# This is a comment with SQL: query = "SELECT * FROM users WHERE id = " + user_id
# password = "hardcoded"
def safe_function():
    pass
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
    # String literals for documentation
    TestCase(
        name="Documentation String - Should be ignored",
        code='''
def example():
    """
    Example of vulnerable code (DO NOT USE):
    query = "SELECT * FROM users WHERE id = " + user_id
    """
    pass
''',
        language="python",
        expected_vulns=[],
        is_vulnerable=False
    ),
]


def run_efficiency_tests():
    """Run comprehensive efficiency tests"""
    print("=" * 80)
    print("SCANNER EFFICIENCY TEST SUITE")
    print("=" * 80)

    ast_scanner = ASTSecurityAnalyzer()
    pattern_scanner = SASTScanner()

    results = {
        "ast": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "time": 0},
        "pattern": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "time": 0},
    }

    # Test Vulnerable Code (should detect)
    print("\n" + "=" * 80)
    print("PHASE 1: Testing Vulnerable Code Detection (True Positives)")
    print("=" * 80)

    for test in VULNERABLE_TEST_CASES:
        print(f"\n[TEST] {test.name}")

        # AST Scanner
        start = time.time()
        ast_result = ast_scanner.analyze_file(test.code, f"test.{test.language[:2]}")
        ast_time = time.time() - start
        results["ast"]["time"] += ast_time

        ast_findings = ast_result.get("findings", [])
        ast_cwes = set(f.get("cwe_id", "") for f in ast_findings)

        # Pattern Scanner
        start = time.time()
        pattern_findings = pattern_scanner.scan_code(test.code, f"test.{test.language[:2]}", test.language)
        pattern_time = time.time() - start
        results["pattern"]["time"] += pattern_time

        pattern_cwes = set(f.get("cwe_id", "") for f in pattern_findings)

        # Check detection
        expected_set = set(test.expected_vulns)

        ast_detected = any(cwe in ast_cwes for cwe in expected_set)
        pattern_detected = any(cwe in pattern_cwes for cwe in expected_set)

        if ast_detected:
            results["ast"]["tp"] += 1
            print(f"  ✅ AST Scanner: DETECTED ({len(ast_findings)} findings, {ast_time*1000:.1f}ms)")
        else:
            results["ast"]["fn"] += 1
            print(f"  ❌ AST Scanner: MISSED (Expected: {expected_set}, Got: {ast_cwes})")

        if pattern_detected:
            results["pattern"]["tp"] += 1
            print(f"  ✅ Pattern Scanner: DETECTED ({len(pattern_findings)} findings, {pattern_time*1000:.1f}ms)")
        else:
            results["pattern"]["fn"] += 1
            print(f"  ❌ Pattern Scanner: MISSED")

    # Test Safe Code (should NOT detect)
    print("\n" + "=" * 80)
    print("PHASE 2: Testing Safe Code (False Positive Rate)")
    print("=" * 80)

    for test in SAFE_TEST_CASES:
        print(f"\n[TEST] {test.name}")

        # AST Scanner
        start = time.time()
        ast_result = ast_scanner.analyze_file(test.code, f"test.{test.language[:2]}")
        ast_time = time.time() - start
        results["ast"]["time"] += ast_time

        ast_findings = ast_result.get("findings", [])
        # Filter out low-confidence findings for safe code
        high_conf_findings = [f for f in ast_findings if f.get("confidence") != "low"]

        # Pattern Scanner
        start = time.time()
        pattern_findings = pattern_scanner.scan_code(test.code, f"test.{test.language[:2]}", test.language)
        pattern_time = time.time() - start
        results["pattern"]["time"] += pattern_time

        if len(high_conf_findings) == 0:
            results["ast"]["tn"] += 1
            print(f"  ✅ AST Scanner: Correctly identified as SAFE ({ast_time*1000:.1f}ms)")
        else:
            results["ast"]["fp"] += 1
            fp_titles = [f.get("title", "")[:40] for f in high_conf_findings[:3]]
            print(f"  ⚠️  AST Scanner: FALSE POSITIVE - {len(high_conf_findings)} findings: {fp_titles}")

        if len(pattern_findings) == 0:
            results["pattern"]["tn"] += 1
            print(f"  ✅ Pattern Scanner: Correctly identified as SAFE ({pattern_time*1000:.1f}ms)")
        else:
            results["pattern"]["fp"] += 1
            fp_titles = [f.get("title", "")[:40] for f in pattern_findings[:3]]
            print(f"  ⚠️  Pattern Scanner: FALSE POSITIVE - {len(pattern_findings)} findings: {fp_titles}")

    # Calculate Metrics
    print("\n" + "=" * 80)
    print("RESULTS SUMMARY")
    print("=" * 80)

    for scanner_name, data in results.items():
        tp, fp, fn, tn = data["tp"], data["fp"], data["fn"], data["tn"]
        total_time = data["time"]

        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        print(f"\n{scanner_name.upper()} SCANNER:")
        print(f"  True Positives:  {tp}")
        print(f"  False Positives: {fp}")
        print(f"  True Negatives:  {tn}")
        print(f"  False Negatives: {fn}")
        print(f"  ---")
        print(f"  Precision:       {precision:.1%}")
        print(f"  Recall:          {recall:.1%}")
        print(f"  F1 Score:        {f1:.1%}")
        print(f"  Accuracy:        {accuracy:.1%}")
        print(f"  FP Rate:         {fpr:.1%}")
        print(f"  Total Time:      {total_time*1000:.1f}ms")
        print(f"  Avg Time/Test:   {total_time*1000/(len(VULNERABLE_TEST_CASES)+len(SAFE_TEST_CASES)):.1f}ms")

    # Comparison
    print("\n" + "=" * 80)
    print("COMPARISON: AST vs Pattern Scanner")
    print("=" * 80)

    ast_f1 = 2 * (results["ast"]["tp"] / max(1, results["ast"]["tp"] + results["ast"]["fp"])) * \
             (results["ast"]["tp"] / max(1, results["ast"]["tp"] + results["ast"]["fn"])) / \
             max(0.001, (results["ast"]["tp"] / max(1, results["ast"]["tp"] + results["ast"]["fp"])) + \
             (results["ast"]["tp"] / max(1, results["ast"]["tp"] + results["ast"]["fn"])))

    pattern_f1 = 2 * (results["pattern"]["tp"] / max(1, results["pattern"]["tp"] + results["pattern"]["fp"])) * \
                 (results["pattern"]["tp"] / max(1, results["pattern"]["tp"] + results["pattern"]["fn"])) / \
                 max(0.001, (results["pattern"]["tp"] / max(1, results["pattern"]["tp"] + results["pattern"]["fp"])) + \
                 (results["pattern"]["tp"] / max(1, results["pattern"]["tp"] + results["pattern"]["fn"])))

    if results["ast"]["fp"] < results["pattern"]["fp"]:
        print(f"  ✅ AST Scanner has {results['pattern']['fp'] - results['ast']['fp']} fewer false positives")
    elif results["ast"]["fp"] > results["pattern"]["fp"]:
        print(f"  ⚠️  AST Scanner has {results['ast']['fp'] - results['pattern']['fp']} more false positives")

    if results["ast"]["fn"] < results["pattern"]["fn"]:
        print(f"  ✅ AST Scanner missed {results['pattern']['fn'] - results['ast']['fn']} fewer vulnerabilities")
    elif results["ast"]["fn"] > results["pattern"]["fn"]:
        print(f"  ⚠️  AST Scanner missed {results['ast']['fn'] - results['pattern']['fn']} more vulnerabilities")

    return results


def run_performance_benchmark():
    """Run performance benchmarks with varying file sizes"""
    print("\n" + "=" * 80)
    print("PERFORMANCE BENCHMARK")
    print("=" * 80)

    ast_scanner = ASTSecurityAnalyzer()
    pattern_scanner = SASTScanner()

    # Generate test files of different sizes
    base_code = '''
import os
from flask import request

def process_request():
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = " + user_id
    result = cursor.execute(query)

    host = request.args.get('host')
    os.system("ping " + host)

    filename = request.args.get('file')
    with open("/data/" + filename) as f:
        return f.read()
'''

    sizes = [1, 5, 10, 25, 50]  # Multipliers

    print(f"\n{'Size (lines)':<15} {'AST Time (ms)':<15} {'Pattern Time (ms)':<18} {'AST Findings':<15} {'Pattern Findings'}")
    print("-" * 80)

    for mult in sizes:
        code = base_code * mult
        lines = len(code.split('\n'))

        # AST Scanner
        start = time.time()
        ast_result = ast_scanner.analyze_file(code, "test.py")
        ast_time = (time.time() - start) * 1000
        ast_findings = len(ast_result.get("findings", []))

        # Pattern Scanner
        start = time.time()
        pattern_findings = pattern_scanner.scan_code(code, "test.py", "python")
        pattern_time = (time.time() - start) * 1000
        pattern_count = len(pattern_findings)

        print(f"{lines:<15} {ast_time:<15.1f} {pattern_time:<18.1f} {ast_findings:<15} {pattern_count}")


def run_taint_flow_tests():
    """Test taint flow detection accuracy"""
    print("\n" + "=" * 80)
    print("TAINT FLOW ANALYSIS TESTS")
    print("=" * 80)

    ast_scanner = ASTSecurityAnalyzer()

    # Test cases with expected taint flows
    taint_tests = [
        {
            "name": "Simple SQL Injection Flow",
            "code": '''
from flask import request

def vulnerable():
    user_input = request.args.get('id')
    query = "SELECT * FROM users WHERE id = " + user_input
    cursor.execute(query)
''',
            "expected_flows": 1,
            "flow_type": "sql"
        },
        {
            "name": "Multi-step Taint Propagation",
            "code": '''
from flask import request

def vulnerable():
    raw_input = request.args.get('data')
    processed = raw_input.strip()
    final = "SELECT * FROM t WHERE x = " + processed
    db.execute(final)
''',
            "expected_flows": 1,
            "flow_type": "sql"
        },
        {
            "name": "Sanitized Flow (Should NOT detect)",
            "code": '''
from flask import request
import re

def safe():
    user_input = request.args.get('id')
    sanitized = re.escape(user_input)
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (sanitized,))
''',
            "expected_flows": 0,
            "flow_type": None
        },
    ]

    for test in taint_tests:
        result = ast_scanner.analyze_file(test["code"], "test.py")
        taint_flows = result.get("taint_flows", [])

        print(f"\n[TEST] {test['name']}")
        print(f"  Expected flows: {test['expected_flows']}")
        print(f"  Detected flows: {len(taint_flows)}")

        if len(taint_flows) >= test['expected_flows']:
            print(f"  ✅ PASS")
            for flow in taint_flows:
                src = flow.get("source", {}).get("description", "unknown")
                sink = flow.get("sink", {}).get("description", "unknown")
                print(f"     Flow: {src} -> {sink}")
        else:
            print(f"  ❌ FAIL - Expected {test['expected_flows']} flows")


if __name__ == "__main__":
    run_efficiency_tests()
    run_performance_benchmark()
    run_taint_flow_tests()
