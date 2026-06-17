# Day 4: Multi-Event CloudTrail Log Stream Inspector

# Simulated live stream of consecutive CloudTrail logs (List of Dictionaries)
cloudtrail_stream = [
    {"user": "dev_engineer", "action": "DescribeInstances", "status": "Success"},
    {"user": "marketing_guest", "action": "ConsoleLogin", "status": "Success"},
    {"user": "unknown_actor", "action": "CreateUser", "status": "Success"},
    {"user": "unknown_actor", "action": "StopLogging", "status": "Success"},
    {"user": "dev_engineer", "engineer": "RunInstances", "status": "Success"}
]

print("=========================================")
print("🚀 INGESTING LIVE CLOUDTRAIL LOG STREAM...")
print("=========================================\n")

# Loop through each log entry in our timeline stream
for log in cloudtrail_stream:
    actor = log["user"]
    event = log["action"]
    
    print(f"Processing Record... User: [{actor}] performed Action: [{event}]")
    
    # Check for the critical system blinding event
    if event == "StopLogging":
        print(f"🚨 CRITICAL ALERT: User '{actor}' has disabled security logging!")
    
    # Check for unauthorized privilege establishment
    elif event == "CreateUser" and actor == "unknown_actor":
        print(f"⚠️ WARNING: Unrecognized user '{actor}' is generating new account credentials.")

print("\n=========================================")
print("🏁 STREAM INGESTION COMPLETE")
print("=========================================")