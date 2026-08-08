from flask import Flask, jsonify, send_from_directory
import psutil
import winreg
import os


app = Flask(__name__)


# ==========================================
# SUSPICIOUS PROCESS NAMES
# ==========================================

suspicious_names = [
    "keylogger.exe",
    "keylog.exe",
    "logger.exe"
]


# ==========================================
# PROCESS SCANNER
# ==========================================

def scan_processes():

    total_processes = 0
    suspicious_processes = []

    for process in psutil.process_iter(["pid", "name"]):

        try:

            total_processes += 1

            pid = process.info["pid"]
            name = process.info["name"]

            risk_score = 0
            reasons = []

            # Get process location
            try:

                process_path = process.exe()

            except (psutil.AccessDenied, psutil.NoSuchProcess):

                process_path = "Unknown"

            # Check suspicious name
            if name and name.lower() in suspicious_names:

                risk_score += 30

                reasons.append(
                    "Suspicious process name"
                )

            # Check unusual location
            if process_path != "Unknown":

                path_lower = process_path.lower()

                if "\\temp\\" in path_lower:

                    risk_score += 20

                    reasons.append(
                        "Process running from Temp folder"
                    )

                elif "\\downloads\\" in path_lower:

                    risk_score += 20

                    reasons.append(
                        "Process running from Downloads folder"
                    )

            # Risk level
            if risk_score >= 60:

                risk_level = "HIGH"

            elif risk_score >= 30:

                risk_level = "MEDIUM"

            else:

                risk_level = "LOW"

            # Save suspicious process
            if risk_score > 0:

                suspicious_processes.append({

                    "pid": pid,
                    "name": name,
                    "location": process_path,
                    "score": risk_score,
                    "level": risk_level,
                    "reasons": reasons

                })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):

            pass

    return total_processes, suspicious_processes


# ==========================================
# STARTUP SCANNER
# ==========================================

def scan_startup():

    startup_programs = []

    startup_locations = [

        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        ),

        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        )

    ]

    for root, path in startup_locations:

        try:

            key = winreg.OpenKey(root, path)

            i = 0

            while True:

                try:

                    name, value, value_type = winreg.EnumValue(
                        key,
                        i
                    )

                    startup_programs.append({

                        "name": name,
                        "command": value

                    })

                    i += 1

                except OSError:

                    break

            winreg.CloseKey(key)

        except (
            PermissionError,
            FileNotFoundError
        ):

            pass

    return startup_programs


# ==========================================
# CALCULATE OVERALL RISK
# ==========================================

def calculate_overall_risk(suspicious_processes):

    if not suspicious_processes:

        return "LOW"

    highest_score = max(
        process["score"]
        for process in suspicious_processes
    )

    if highest_score >= 60:

        return "HIGH"

    elif highest_score >= 30:

        return "MEDIUM"

    else:

        return "LOW"


# ==========================================
# API ROUTE
# ==========================================

@app.route("/scan")
def scan():

    total_processes, suspicious = scan_processes()

    startup = scan_startup()

    overall_risk = calculate_overall_risk(
        suspicious
    )

    return jsonify({

    "processes": total_processes,

    "suspicious": len(suspicious),

    "startup": len(startup),

    "risk": overall_risk,

    "suspicious_processes": suspicious,

    "startup_programs": startup

})


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():

    return send_from_directory(
        "web",
        "index.html"
    )
@app.route("/report")
def report():

    reports_folder = "reports"

    if not os.path.exists(reports_folder):
        return "No report available yet."

    files = os.listdir(reports_folder)

    report_files = [
        file for file in files
        if file.endswith(".txt")
    ]

    if not report_files:
        return "No report available yet."

    latest_report = max(
        report_files,
        key=lambda file: os.path.getmtime(
            os.path.join(reports_folder, file)
        )
    )

    return send_from_directory(
        reports_folder,
        latest_report
    )


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    print()
    print("==========================================")
    print("       KEYGUARD WEB SERVER")
    print("==========================================")

    print()
    print("Server running at:")
    print("http://127.0.0.1:5000")

    print()
    print("Press CTRL+C to stop the server.")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )