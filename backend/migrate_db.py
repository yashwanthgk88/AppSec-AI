#!/usr/bin/env python3
"""
Database migration script to add AI provider configuration fields
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "appsec.db")

def migrate():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("Starting database migration...")

    try:
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]

        # Add AI provider columns to users table if they don't exist
        if 'ai_provider' not in columns:
            print("Adding ai_provider column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN ai_provider VARCHAR(50) DEFAULT 'anthropic'")

        if 'ai_api_key' not in columns:
            print("Adding ai_api_key column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN ai_api_key TEXT")

        if 'ai_model' not in columns:
            print("Adding ai_model column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN ai_model VARCHAR(100)")

        if 'ai_base_url' not in columns:
            print("Adding ai_base_url column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN ai_base_url VARCHAR(500)")

        if 'ai_api_version' not in columns:
            print("Adding ai_api_version column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN ai_api_version VARCHAR(50)")

        # Check projects table
        cursor.execute("PRAGMA table_info(projects)")
        columns = [col[1] for col in cursor.fetchall()]

        # Add architecture diagram columns to projects table if they don't exist
        if 'architecture_diagram' not in columns:
            print("Adding architecture_diagram column to projects table...")
            cursor.execute("ALTER TABLE projects ADD COLUMN architecture_diagram TEXT")

        if 'diagram_media_type' not in columns:
            print("Adding diagram_media_type column to projects table...")
            cursor.execute("ALTER TABLE projects ADD COLUMN diagram_media_type VARCHAR(50)")

        conn.commit()
        print("✓ Migration completed successfully!")

    except Exception as e:
        print(f"✗ Migration failed: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
