"""
DEMO FILE - GitHub Monitor Test
Triggers: Hardcoded credential rules (IT: Hardcoded AWS Credentials, etc.)
Risk level: HIGH
"""

# Demo pattern - hardcoded AWS key (not a real key)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "super_secret_password_123"

def connect_to_db():
    # Demo: password hardcoded in source (triggers IT credential rules)
    connection_string = "postgresql://admin:hardcoded_pass@prod-db.example.com/appdb"
    return connection_string

# Demo: logging sensitive data (triggers IT: Credentials Logged to Output)
import logging
password = "demo_password"
logging.warning(f"Connection attempt with password={password}")
