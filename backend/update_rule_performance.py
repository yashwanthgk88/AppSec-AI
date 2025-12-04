#!/usr/bin/env python3
"""
Script to update rule performance statistics based on existing vulnerabilities
"""
import sqlite3

def update_rule_performance():
    conn = sqlite3.connect('appsec.db')
    cursor = conn.cursor()

    print("Updating rule performance statistics...")

    # Get count of vulnerabilities for each rule
    cursor.execute('''
        SELECT rule_id, COUNT(*) as count
        FROM vulnerabilities
        WHERE rule_id IS NOT NULL
        GROUP BY rule_id
    ''')

    rule_counts = cursor.fetchall()

    if not rule_counts:
        print("No vulnerabilities with rule_id found.")
        conn.close()
        return

    print(f"Found {len(rule_counts)} rules with detections")

    # Update each rule's total_detections
    for rule_id, count in rule_counts:
        cursor.execute('''
            UPDATE custom_rules
            SET total_detections = ?
            WHERE id = ?
        ''', (count, rule_id))

        # Get rule name
        cursor.execute('SELECT name FROM custom_rules WHERE id = ?', (rule_id,))
        rule = cursor.fetchone()
        if rule:
            print(f"  Rule #{rule_id} '{rule[0]}': {count} detections")

    conn.commit()
    print(f"\n✓ Successfully updated {len(rule_counts)} rules")

    # Show summary
    cursor.execute('''
        SELECT
            COUNT(*) as total_rules,
            SUM(total_detections) as total_detections,
            AVG(total_detections) as avg_detections
        FROM custom_rules
        WHERE total_detections > 0
    ''')

    summary = cursor.fetchone()
    if summary:
        print(f"\nSummary:")
        print(f"  Rules with detections: {summary[0]}")
        print(f"  Total detections: {summary[1]}")
        print(f"  Average per rule: {summary[2]:.1f}")

    conn.close()

if __name__ == "__main__":
    update_rule_performance()
