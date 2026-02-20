#!/usr/bin/env python3
"""
Database migration script to add AI provider configuration fields
"""
import sqlite3
import os

def get_db_path():
    """Get database path, preferring persistent storage if available"""
    persistent_path = "/app/data/appsec.db"

    # Check if running in Railway (persistent volume mounted)
    if os.path.exists("/app/data"):
        return persistent_path

    # Local development fallback
    return os.path.join(os.path.dirname(__file__), "appsec.db")

DB_PATH = get_db_path()

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

        # Check threat_models table
        cursor.execute("PRAGMA table_info(threat_models)")
        columns = [col[1] for col in cursor.fetchall()]

        # Add new JSON columns to threat_models table if they don't exist
        if 'fair_risk_analysis' not in columns:
            print("Adding fair_risk_analysis column to threat_models table...")
            cursor.execute("ALTER TABLE threat_models ADD COLUMN fair_risk_analysis JSON")

        if 'attack_trees' not in columns:
            print("Adding attack_trees column to threat_models table...")
            cursor.execute("ALTER TABLE threat_models ADD COLUMN attack_trees JSON")

        if 'kill_chain_analysis' not in columns:
            print("Adding kill_chain_analysis column to threat_models table...")
            cursor.execute("ALTER TABLE threat_models ADD COLUMN kill_chain_analysis JSON")

        if 'eraser_diagrams' not in columns:
            print("Adding eraser_diagrams column to threat_models table...")
            cursor.execute("ALTER TABLE threat_models ADD COLUMN eraser_diagrams JSON")

        # Add incremental threat modeling columns to threat_models table
        if 'architecture_version_id' not in columns:
            print("Adding architecture_version_id column to threat_models table...")
            cursor.execute("ALTER TABLE threat_models ADD COLUMN architecture_version_id INTEGER")

        if 'is_incremental' not in columns:
            print("Adding is_incremental column to threat_models table...")
            cursor.execute("ALTER TABLE threat_models ADD COLUMN is_incremental BOOLEAN DEFAULT 0")

        # Create architecture_versions table for tracking architecture changes
        print("Creating architecture_versions table if not exists...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS architecture_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                version_number INTEGER NOT NULL,
                architecture_hash VARCHAR(64) NOT NULL,
                architecture_snapshot JSON NOT NULL,
                change_summary JSON,
                change_description TEXT,
                impact_score REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)

        # Create index for efficient version lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_arch_versions_project
            ON architecture_versions(project_id, version_number DESC)
        """)

        # Create threat_history table for tracking threat lifecycle
        print("Creating threat_history table if not exists...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                threat_id VARCHAR(100) NOT NULL,
                architecture_version_id INTEGER NOT NULL,
                status VARCHAR(20) NOT NULL,
                threat_data JSON NOT NULL,
                previous_history_id INTEGER,
                change_reason VARCHAR(500),
                affected_components JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (architecture_version_id) REFERENCES architecture_versions(id),
                FOREIGN KEY (previous_history_id) REFERENCES threat_history(id)
            )
        """)

        # Create indexes for efficient threat history queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_history_project
            ON threat_history(project_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_history_threat_id
            ON threat_history(threat_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_history_version
            ON threat_history(architecture_version_id)
        """)

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
