#!/usr/bin/env python3
"""
Migration script to add rule_id column to vulnerabilities table
This enables tracking which custom rule detected each vulnerability
"""
import sqlite3
import sys

def run_migration():
    try:
        conn = sqlite3.connect('appsec.db')
        cursor = conn.cursor()

        # Check if column already exists
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = [column[1] for column in cursor.fetchall()]

        if 'rule_id' in columns:
            print("✓ rule_id column already exists in vulnerabilities table")
            conn.close()
            return True

        print("Adding rule_id column to vulnerabilities table...")

        # Add rule_id column
        cursor.execute('''
            ALTER TABLE vulnerabilities
            ADD COLUMN rule_id INTEGER
        ''')

        conn.commit()
        print("✓ Successfully added rule_id column to vulnerabilities table")
        print("✓ Rule performance tracking is now enabled!")

        conn.close()
        return True

    except Exception as e:
        print(f"✗ Migration failed: {e}")
        return False

if __name__ == "__main__":
    success = run_migration()
    sys.exit(0 if success else 1)
