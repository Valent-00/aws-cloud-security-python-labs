# Day 4: Simulated CloudTrail Log Parsing Engine

# A simulated single event log from AWS CloudTrail
mock_cloudtrail_log = {
    "eventTime": "2026-06-14T19:15:00Z",
    "eventName": "StopLogging",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "198.51.100.77",
    "userIdentity": "compromised_staff"
}

print("=========================================")
print("🔍 INGESTING LIVE CLOUDTRAIL LOG EVENT...")
print("=========================================\n")

# Extract specific security metrics using dictionary keys
trigger_user = mock_cloudtrail_log["userIdentity"]
action_taken = mock_cloudtrail_log["eventName"]
attacker_ip = mock_cloudtrail_log["sourceIPAddress"]

print(f"ALERT: User '{trigger_user}' executed the action '{action_taken}' from IP [{attacker_ip}].")

# High-priority security logic check
if action_taken == "StopLogging":
    print("\n🚨 CRITICAL SECURITY ALERT: An entity is attempting to turn off the security cameras!")
    print("REMEDIATION ACTION: Revoking session tokens for this user immediately.")
else:
    print("\n✅ Activity matches routine API operations.")