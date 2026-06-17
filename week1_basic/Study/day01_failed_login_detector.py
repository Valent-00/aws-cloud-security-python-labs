#Day 01: Automated Brute Force Detection System

#Simulated Live telemetry data

failed_login_count = 2;

target_user = "valent_staff"

print("=== LIVE SOC ACCESS MONITOR ===")

# Check if the failed logins breach our security threshold
if failed_login_count > 5:
    print("🚨 ALERT: CRITICAL SECURITY EVENT DETECTED!")
    print(f"User '{target_user}' has {failed_login_count} failed login attempts.")
    print("REMEDIATION: Temporarily locking account and forcing credential reset.")
else:
    print("System status: GREEN. All login patterns within normal thresholds.")