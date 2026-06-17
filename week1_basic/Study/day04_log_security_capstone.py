# Day 7: Log Monitoring Capstone - Advanced Threat Hunting Engine


def analyze_incident(log_entry):
    """
    Analyzes an individual log entry against the attack chain matrix.
    Returns a severity level string and a descriptive action.
    """
    event = log_entry["event"]
    user = log_entry["user"]
    
    if event == "StopLogging" or event == "DeletelogStream":
        return "CRITICAL", f"Blinding Attempt ! User '{user}' tired to disable security camera."
    elif event == "AuthorizeSeucityGroupIngress" or event == "DeleteSecurityGroup":
        return "WARNING", f"Firewall Tampering! User '{user}' modified network access controls."
    elif event == "ConsoleLogin" and user == "root":
        return "CRITICAL", "Unsecure Access! Direct Root account login detected."
    else:
        return "INFO", f"Routine event executed cleanly by user '{user}'."
    
# Simulated Live Corporate Attack Timeline Stream
cloudtrial_stream = [
    {"user": "dev_engineer", "event": "DescribeInstances"},
    {"user": "root", "event": "ConsoleLogin"},
    {"user": "compromised_app", "event": "AuthorizeSecurityGroupIngress"},
    {"user": "compromised_app", "event": "DeleteLogStream"},
    {"user": "dev_engineer", "event": "RunInstances"}
]

print("====================================================")
print("🛡️  STARTING MULTI-STAGE ATTACK TIMELINE AUDIT")
print("====================================================\n")

# Counters to track our security metrics
critical_count = 0
warning_count = 0

# Loop through the streaming logs

for log in cloudtrial_stream:
    
    severity, description = analyze_incident(log)

    print(f"[{severity}] - {description}")

    # Track metrics based on severity results
    if severity == "CRITICAL":
        critical_count = critical_count + 1
    elif severity == "WARNING":
        warning_count = warning_count + 1

print("\n====================================================")
print("🏁 ATTACK TIMELINE ANALYSIS COMPLETE")
print("====================================================")
print(f"⚠️  Total WARNING Violations Flagged: {warning_count}")
print(f"🚨  Total CRITICAL Violations Flagged: {critical_count}")
print("====================================================")

