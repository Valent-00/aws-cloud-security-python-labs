# Day 6: Modular CloudTrail Analyzer Using Functions

# The reusable security evaluation machine
def evaluate_event_safety(event_name, user_identity):
    """
    This function acts as our core detection rule engine.
    It takes an action and a username, then returns a security assessment.
    """
    if event_name == "DeleteLogStream" or event_name == "StopLogging":
        return f"🚨 CRITICAL: Log Tampering Detected by user '{user_identity}'!"
    
    elif event_name == "DeleteSecurityGroup":
        return f"⚠️ WARNING: Firewall configuration bypass attempted by user '{user_identity}'."
    
    else:
        return f"✅ Safe operational event processed for user '{user_identity}'."


# Simulated batch of incoming live events
live_logs = [
    {"user": "cloud_admin", "event": "DescribeInstances"},
    {"user": "compromised_app", "event": "DeleteSecurityGroup"},
    {"user": "attacker_node", "event": "DeleteLogStream"}
]

print("=== STARTING FUNCTION-BASED COMPLIANCE SCAN ===")

# Loop through our logs and feed them one by one into our function machine
for log in live_logs:
    # Call the function and capture its answer inside a variable
    security_verdict = evaluate_event_safety(log["event"], log["user"])
    print(security_verdict)

print("=== MODULAR COMPLIANCE SCAN COMPLETE ===")