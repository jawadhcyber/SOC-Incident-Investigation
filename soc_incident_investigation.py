import csv
from collections import Counter

LOG_FILE = "security_events.log"
REPORT_FILE = "incident_report.csv"
FAILED_LOGIN_THRESHOLD = 5

failed_logins = Counter()
successful_logins = Counter()

try:
    with open(LOG_FILE, "r") as file:
        for line in file:
            parts = line.strip().split(",")

            if len(parts) < 4:
                continue

            timestamp = parts[0].strip()
            event_type = parts[1].strip()
            username = parts[2].strip()
            ip_address = parts[3].strip()

            if event_type == "FAILED_LOGIN":
                failed_logins[ip_address] += 1

            elif event_type == "SUCCESSFUL_LOGIN":
                successful_logins[ip_address] += 1

except FileNotFoundError:
    print(f"Error: {LOG_FILE} was not found.")
    exit()

print("=== SOC Incident Investigation ===")
print()

incidents = []

for ip, count in failed_logins.items():

    if count >= FAILED_LOGIN_THRESHOLD:
        severity = "HIGH"
        status = "Possible Brute-Force Attack"
    elif count >= 3:
        severity = "MEDIUM"
        status = "Suspicious Login Activity"
    else:
        severity = "LOW"
        status = "Normal"

    incidents.append([
        ip,
        count,
        successful_logins.get(ip, 0),
        severity,
        status
    ])

if incidents:
    print("Security Findings:")
    print()

    for incident in incidents:
        print(f"IP Address: {incident[0]}")
        print(f"Failed Logins: {incident[1]}")
        print(f"Successful Logins: {incident[2]}")
        print(f"Severity: {incident[3]}")
        print(f"Status: {incident[4]}")
        print()
else:
    print("No suspicious login activity detected.")

with open(REPORT_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    writer.writerow([
        "IP Address",
        "Failed Logins",
        "Successful Logins",
        "Severity",
        "Status"
    ])

    writer.writerows(incidents)

print(f"Incident report saved to {REPORT_FILE}")
