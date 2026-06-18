import os
import time
import json
import logging
import requests

# 1. Setup Logging
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "scanner_operations.log")
STATE_FILE_PATH = os.path.join(SCRIPT_DIR, "state", "baseline_iam.json")
os.makedirs(os.path.dirname(STATE_FILE_PATH), exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# 2. Configuration Constants
RISK_BASE_SCORES = {"MFA Disabled": 50, "New User Created": 40, "Stale Key": 20, "Role Changed": 60}
KEY_ROTATION_LIMIT_DAYS = 90
ADMIN_ROLE_MULTIPLIER = 1.5
MAX_RISK_SCORE = 99

# 3. Helper Functions (Defined first so they can be called)
def calculate_risk_score(incident_type, user_role, key_age=0):
    score = RISK_BASE_SCORES.get(incident_type, 0)
    if incident_type == "Stale Key" and key_age > KEY_ROTATION_LIMIT_DAYS:
        score += (key_age - KEY_ROTATION_LIMIT_DAYS)
    if user_role == "Administrator":
        score *= ADMIN_ROLE_MULTIPLIER
    return min(round(score), MAX_RISK_SCORE)

def fetch_cloud_inventory():
    return [
        {"username": "admin_root", "mfa_enabled": False, "key_age_days": 115, "role": "Administrator"},
        {"username": "intern_dev01", "mfa_enabled": False, "key_age_days": 12, "role": "Developer"},
        {"username": "stale_deployer", "mfa_enabled": False, "key_age_days": 210, "role": "DevOps"}
    ]

def detect_configuration_drift(current_data):
    if not os.path.exists(STATE_FILE_PATH):
        with open(STATE_FILE_PATH, 'w') as f: json.dump(current_data, f, indent=4)
        return []
    with open(STATE_FILE_PATH, 'r') as f: baseline_data = json.load(f)
    baseline_dict = {user["username"]: user for user in baseline_data}
    drift_alerts = []
    for user in current_data:
        if user["username"] not in baseline_dict:
            drift_alerts.append({"username": user["username"], "alert_type": "New User Created", "risk_score": calculate_risk_score("New User Created", user["role"])})
    return drift_alerts

def scan_iam_posture(users_list):
    findings = []
    for user in users_list:
        if user["mfa_enabled"] is False:
            findings.append({"username": user["username"], "alert_type": "MFA Disabled", "risk_score": calculate_risk_score("MFA Disabled", user["role"])})
    return findings

def generate_ai_summary_local(findings):
    """Generates an executive report using your local Ollama instance."""
    high_risk = [alert for alert in findings if alert.get("risk_score", 0) >= 70]
    if not high_risk: 
        logging.info("No high-risk incidents to summarize.")
        return
    
    prompt = f"Act as a Security Analyst. Review these alerts and write a short, professional incident report: {json.dumps(high_risk)}."
    
    try:
        # 1. Attempt the request
        response = requests.post(
            "http://localhost:11434/api/generate", 
            json={"model": "llama3.2", "prompt": prompt, "stream": False}, 
            timeout=45
        )
        response.raise_for_status() # This triggers the 'except' block if the server returns an error
        
        # 2. Only process results if request was successful
        result = response.json()
        ai_response = result.get("response", "No response generated.")
        
        # 3. Output and Save
        print("\n" + "="*80 + "\n 🤖 AI REPORT: \n" + ai_response + "\n" + "="*80)
        
        for alert in high_risk:
            save_report_to_disk(ai_response, alert['username'])
            
    except Exception as e:
        # This will now catch the error gracefully without trying to access 'result'
        logging.error(f"AI Engine Error: {e}")
        

def save_report_to_disk(report_content, username):
    """Saves the AI report to a text file for auditing."""
    # Create a directory named 'reports' inside your project folder
    report_dir = os.path.join(SCRIPT_DIR, "reports")
    os.makedirs(report_dir, exist_ok=True)
    
    # Create a filename with a timestamp
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(report_dir, f"incident_{username}_{timestamp}.txt")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_content)
    
    logging.info(f"✅ Report saved to: {filename}")

# 4. Main Execution
if __name__ == "__main__":
    iam_data = fetch_cloud_inventory()
    drift = detect_configuration_drift(iam_data)
    posture = scan_iam_posture(iam_data)
    
    all_findings = drift + posture
    generate_ai_summary_local(all_findings)