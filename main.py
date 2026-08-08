import psutil

suspicious_names = [
    "chrome.exe"
]

print("====================================")
print("       KEYGUARD PROCESS SCANNER")
print("====================================")

for process in psutil.process_iter(['pid', 'name']):

    try:
        pid = process.info['pid']
        name = process.info['name']

        risk_score = 0
        reasons = []

        if name and name.lower() in suspicious_names:
            risk_score += 30
            reasons.append("Suspicious process name")

        if risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        print(f"PID: {pid}    Process: {name}")
        print(f"Risk Score: {risk_score}/100")
        print(f"Risk Level: {risk_level}")

        if reasons:
            print("Reasons:")
            for reason in reasons:
                print(f"- {reason}")

        print("------------------------------------")

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass