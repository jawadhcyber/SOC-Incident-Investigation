SOC Incident Investigation

A Python-based Security Operations Center (SOC) investigation tool that analyzes authentication events, identifies suspicious login activity, assigns severity levels, and generates an incident report.

Features

- Analyzes security event logs
- Detects failed login attempts
- Counts failed and successful logins by IP address
- Identifies possible brute-force attacks
- Assigns severity levels:
  - HIGH — 5 or more failed login attempts
  - MEDIUM — 3–4 failed login attempts
  - LOW — fewer than 3 failed login attempts
- Generates a CSV incident report

Technologies

- Python
- CSV
- Collections Counter
- Google Colab
- GitHub

Project Files

- "soc_incident_investigation.py" — Main SOC investigation script
- "security_events.log" — Sample security event log
- "incident_report.csv" — Generated incident report
- "README.md" — Project documentation

Example Finding

The analyzer identified:

- "192.168.1.50" — 5 failed logins and 1 successful login → HIGH
- "10.0.0.5" — 3 failed logins → MEDIUM

SOC Investigation Workflow

1. Collect security event logs
2. Parse authentication events
3. Count failed and successful login attempts
4. Identify suspicious activity
5. Assign severity
6. Generate an incident report

Skills Demonstrated

- Security log analysis
- Authentication monitoring
- Brute-force detection
- Incident investigation
- Python automation
- CSV report generation
- Basic SOC analysis

Future Improvements

- Add timestamps to incident reports
- Add username-based analysis
- Detect repeated successful logins after multiple failures
- Add IP reputation checking
- Add visualization/dashboard support

Author

Jawad Hussain

Computer Science Graduate | Aspiring Cybersecurity Analyst
