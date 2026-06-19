# AWS Cloud Security Automation & Telemetry Lab

A modular, code-driven security automation pipeline designed to ingest, parse, and analyze raw AWS CloudTrail telemetry logs. This system functions as a localized Security Operations Center (SOC) rule engine to detect critical cloud anomalies and generate structured security incident tracking tickets.

## 🚀 Core Features
* **Telemetry Data Generation:** Simulates realistic AWS CloudTrail control-plane event streams containing both safe administrative actions and targeted attack indicators.
* **Modular Rule Engine:** Uses a parameterized Python execution architecture to scan log streams dynamically without hardcoded path dependencies.
* **Threat Detection Signatures:** Monitors for critical defense evasion activities, specifically flagging unauthorized `StopLogging` API requests.
* **Automated SOC Ticketing:** Interacts with the host operating system to dynamically provision data storage and write out persistent JSON case tracking files (`live_alert.json`).
* **AI-Driven Incident Triage:** Decouples heavy data processing from inference by offloading high-risk alerts to a local Llama 3.2 model via Ollama. 
* **Automated Mitigation Playbooks:** Generates human-readable incident response reports, mapping technical alerts (like IAM policy drift) to actionable security recommendations.
* **Operational Resiliency:** Implements a "local-first" design, ensuring that the AI analysis engine remains functional even without internet connectivity or external API access.
---

### 🤖 Local AI Setup
1. [Download Ollama](https://ollama.com/).
2. Run `ollama pull llama3.2` to fetch the model.
3. Start the server: `ollama serve`.
4. Run the scanner, and findings will be automatically analyzed and saved to `reports/`.


## 📂 Repository Architecture

```text
aws-cloud-security-python-labs/
│
├── .gitignore               # Excludes fluid dataset logs & active ticket outputs
├── README.md                # Project documentation and architecture summary
├── alert_engine.py          # Parameterized modular threat scanning engine
├── create_ticket.py         # Automated case management validation script
├── parse_logs.py            # Log deserialization and console visualizer
│
├── telemetry_lab/           # Managed Data Layer
│   ├── generate_mock_telemetry.py
│   └── logs_dataset_source.json
│
├── active_tickets/          # Automated System Outputs (Git ignored)
│   └── live_alert.json
│
└── learning_archive/        # Legacy educational milestones & syntax practice
    └── week1/