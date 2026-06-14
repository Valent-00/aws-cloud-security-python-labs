#Day 2: Automated Bulk IAM User Compliance Scaner


user_directory = ["valent_staff", "cloud_analytics_svc", "marketing_guest", "root", "dev_engineer"]

print("=== STARTING AUTOMATED IAM COMPLIANCE AUDIT ===")
print(f"Total accounts discovered in directory: {len(user_directory)}")
print("Scanning for non-compliant identities...\n")

for user in user_directory:
    if user == "root":
        print(f"🚨 COMPLIANCE CRITICAL ALERT: Forbidden '{user}' identity found in standard user directory!")
    else:
        print(f"✅ Identity Verified: '{user}' matches standard operational profile.")

print("\n=== AUDIT PIPELINE EXECUTION COMPLETE ===")