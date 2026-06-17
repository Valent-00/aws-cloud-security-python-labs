# Day 3: Week 1 Capstone - Automated Identity Compliance Scanner

# Simulated live security log data containing user information and credential types
user_logins = [
    {"username": "valent_staff", "credential_type": "iam_role"},
    {"username": "marketing_guest", "credential_type": "access_key"},
    {"username": "root", "credential_type": "master_password"},
    {"username": "dev_engineer", "credential_type": "iam_role"},
    {"username": "cloud_analytics_svc", "credential_type": "access_key"}
]

print("=============================================")
print("🛡️  STARTING WEEK 1 CENTRAL COMPLIANCE AUDIT")
print("=============================================")

# Loop through each user record in our login logs
for record in user_logins:
    current_user = record["username"]
    auth_method = record["credential_type"]
    
    print(f"\nEvaluating: User: [{current_user}] | Method: [{auth_method}]")
    
    # Rule 1: Flag the dangerous Root Account
    if current_user == "root":
        print("🚨 CRITICAL ALERT: Root account usage detected! Enforce break-glass protocols.")
        
    # Rule 2: Flag unapproved long-term Access Keys
    elif auth_method == "access_key":
        print("⚠️ WARNING: Long-term Access Key detected. Recommend migration to temporary IAM Roles.")
        
    # Rule 3: Safe configurations
    else:
        print("✅ COMPLIANT: Identity utilizes secure temporary IAM Role permissions.")

print("\n=============================================")
print("🏁 AUDIT COMPLETE: Week 1 baseline environment secure.")
print("=============================================")