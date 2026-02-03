"""
Database path utility for consistent path resolution across Railway and local dev
"""
import os

def get_db_path():
    """Get database path, preferring persistent storage if available"""
    persistent_path = "/app/data/appsec.db"

    # Check if running in Railway (persistent volume mounted)
    if os.path.exists("/app/data"):
        return persistent_path

    # Local development fallback
    return "appsec.db"
