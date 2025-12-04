#!/usr/bin/env python3
"""
Script to fine-tune custom security rules to reduce false positives
This improves rule precision by adding better context checks and excluding common false positives
"""
import sqlite3

def fine_tune_rules():
    conn = sqlite3.connect('appsec.db')
    cursor = conn.cursor()

    print("Fine-tuning custom security rules to reduce false positives...\n")

    # Updated rules with better patterns to reduce false positives
    rules_to_update = [
        # Rule 8: Path Traversal - More specific to exclude relative imports
        {
            "id": 8,
            "pattern": r'(\.\.[/\\]){2,}|\.\.%2[fF]|%2[eE]%2[eE][/\\]|path.*\.\..*[/\\]',
            "reason": "More specific pattern to detect actual path traversal attacks, not relative imports"
        },

        # Rule 9: Weak Encryption - Exclude hash functions when used for checksums
        {
            "id": 9,
            "pattern": r'(DES|RC4)\s*\(|Cipher\.(DES|RC4)|hashlib\.(md5|sha1)\([^)]*password|encrypt.*\b(MD5|SHA1)\b',
            "reason": "Only flag weak encryption when used for passwords/encryption, not checksums"
        },

        # Rule 36: Large File Upload - More specific to actual upload handlers
        {
            "id": 36,
            "pattern": r'(request\.files|multipart/form-data|file\.save\(|upload_file\()(?!.*(max_size|size_limit|maxFileSize|max_length|content_length))',
            "reason": "Target actual file upload code without size validation"
        },

        # Rule 43: Hardcoded API Endpoint - Exclude common localhost/docs URLs
        {
            "id": 43,
            "pattern": r'(api_url|base_url|endpoint)\s*=\s*[\'\"](https?://)[a-zA-Z0-9.-]+\.(com|net|org|io)(?!.*(example|test|localhost))',
            "reason": "Only flag actual hardcoded production API endpoints"
        },

        # Rule 28: Logging Sensitive Data - More specific to actual logging statements
        {
            "id": 28,
            "pattern": r'(logger\.|console\.log|print)\s*\([^)]*\b(password|secret|token|api_key|credit_card|ssn)\b',
            "reason": "Target actual logging of sensitive data, not variable names"
        },

        # Rule 7: Missing Authorization Check - More specific to route handlers
        {
            "id": 7,
            "pattern": r'(@app\.route|@router\.|express\.delete|app\.delete|router\.delete).*\bdelete\b(?!.*(auth|permission|login_required|authenticate))',
            "reason": "Check delete routes/endpoints without authorization decorators"
        },

        # Rule 50: Cleartext HTTP - Exclude localhost and common dev URLs
        {
            "id": 50,
            "pattern": r'(fetch|axios|requests\.get|http\.get|urllib\.request)\s*\(\s*[\'\"](http://)(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
            "reason": "Only flag external HTTP requests, not localhost"
        },

        # Rule 26: Insecure Deserialization - More precise patterns
        {
            "id": 26,
            "pattern": r'pickle\.loads\(|yaml\.load\((?!.*Loader=yaml\.SafeLoader)|unserialize\(|eval\(.*input|marshal\.loads\(',
            "reason": "Target unsafe deserialization methods"
        },
    ]

    updated_count = 0
    for rule_update in rules_to_update:
        rule_id = rule_update["id"]
        new_pattern = rule_update["pattern"]
        reason = rule_update["reason"]

        # Get current rule info
        cursor.execute("SELECT name, pattern, total_detections FROM custom_rules WHERE id = ?", (rule_id,))
        rule = cursor.fetchone()

        if rule:
            name, old_pattern, detections = rule
            print(f"Rule #{rule_id}: {name}")
            print(f"  Current detections: {detections}")
            print(f"  Old pattern: {old_pattern[:80]}{'...' if len(old_pattern) > 80 else ''}")
            print(f"  New pattern: {new_pattern[:80]}{'...' if len(new_pattern) > 80 else ''}")
            print(f"  Reason: {reason}")

            # Update the pattern
            cursor.execute(
                "UPDATE custom_rules SET pattern = ? WHERE id = ?",
                (new_pattern, rule_id)
            )
            updated_count += 1
            print(f"  ✓ Updated\n")
        else:
            print(f"Rule #{rule_id} not found\n")

    # Also update the Cloudflare API Key rule in secret scanner to be more specific
    # This requires a stricter pattern
    print("\nAdditional fine-tuning recommendations:")
    print("1. Email Address Detection: Consider this as 'info' severity for non-production code")
    print("2. High Entropy Strings: Increase min_entropy threshold to 5.0 to reduce false positives")
    print("3. IPv4 Address: Consider whitelisting common private IP ranges")

    conn.commit()
    print(f"\n✓ Successfully fine-tuned {updated_count} rules")
    print("\nNext steps:")
    print("1. Test the rules against your codebase")
    print("2. Monitor the new detection rates")
    print("3. Adjust precision thresholds as needed")

    conn.close()

if __name__ == "__main__":
    fine_tune_rules()
