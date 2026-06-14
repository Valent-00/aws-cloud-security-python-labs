# Day 1: Automated Threat Intelligence Firewall

threat_intel_blacklist = ["198.51.100.42", "203.0.113.115", "192.0.2.1"]

incoming_connection = "192.168.1.1"

print("--- CLOUD NETWORK FIREWALL ---")
print(f"Scanning incoming request from IP: {incoming_connection}")

# Check if the incoming IP matches our blacklist
if incoming_connection in threat_intel_blacklist:
    print("❌ ALERT: Connection dropped! Source matches active Threat Intel Blacklist.")
else:
    print("✅ ACCESS GRANTED: Traffic routing normally.")