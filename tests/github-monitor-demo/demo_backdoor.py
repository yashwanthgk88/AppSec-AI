"""
DEMO FILE - GitHub Monitor Test
Triggers: Backdoor detection rules, obfuscated code execution rules
Risk level: CRITICAL
"""
import base64
import os

# Demo: encoded payload execution (triggers IT: Obfuscated Payload Execution)
# This is a test pattern — the actual decoded string is benign ("print('hello')")
_demo_encoded = "cHJpbnQoJ2hlbGxvJyk="
exec(base64.b64decode(_demo_encoded))

# Demo: conditional backdoor route (triggers IT: Backdoor - Hidden Endpoint)
MAINTENANCE_MODE = os.getenv("MAINTENANCE_MODE", "false")

def register_routes(app):
    if MAINTENANCE_MODE == "true":
        # Hidden admin endpoint — triggers rule
        @app.route("/internal/admin/reset")
        def hidden_reset():
            return "ok"

# Demo: subprocess with shell expansion (triggers IT: Command Injection via exec)
def run_report(report_name):
    import subprocess
    # Unsafe — user input passed to shell
    subprocess.call("generate_report " + report_name, shell=True)
