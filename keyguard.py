import psutil
import winreg
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import os


# ==========================================
# KEYGUARD SETTINGS
# ==========================================

suspicious_names = [
    "keylogger.exe",
    "keylog.exe",
    "logger.exe"
]


# ==========================================
# REPORT DATA
# ==========================================

scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

report_processes = []
report_startup = []


# ==========================================
# ALERT FUNCTION
# ==========================================

def show_alert(process_name, risk_score, risk_level):

    root = tk.Tk()
    root.withdraw()

    messagebox.showwarning(
        "KeyGuard Warning",
        "Suspicious activity detected!\n\n"
        "Process: " + str(process_name) + "\n"
        "Risk Score: " + str(risk_score) + "/100\n"
        "Risk Level: " + str(risk_level)
    )

    root.destroy()


# ==========================================
# PROCESS SCANNER
# ==========================================

def scan_processes():

    print()
    print("==========================================")
    print("           PROCESS SCANNER")
    print("==========================================")

    suspicious_processes = []

    for process in psutil.process_iter(["pid", "name"]):

        try:

            pid = process.info["pid"]
            name = process.info["name"]

            risk_score = 0
            reasons = []

            # Get process location
            try:

                process_path = process.exe()

            except (psutil.AccessDenied, psutil.NoSuchProcess):

                process_path = "Unknown"

            # ----------------------------------
            # RULE 1: Suspicious process name
            # ----------------------------------

            if name and name.lower() in suspicious_names:

                risk_score = risk_score + 30

                reasons.append(
                    "Suspicious process name"
                )

            # ----------------------------------
            # RULE 2: Unusual process location
            # ----------------------------------

            if process_path != "Unknown":

                path_lower = process_path.lower()

                if "\\temp\\" in path_lower:

                    risk_score = risk_score + 20

                    reasons.append(
                        "Process running from Temp folder"
                    )

                elif "\\downloads\\" in path_lower:

                    risk_score = risk_score + 20

                    reasons.append(
                        "Process running from Downloads folder"
                    )

            # ----------------------------------
            # Risk level
            # ----------------------------------

            if risk_score >= 60:

                risk_level = "HIGH"

            elif risk_score >= 30:

                risk_level = "MEDIUM"

            else:

                risk_level = "LOW"

            # ----------------------------------
            # Display
            # ----------------------------------

            print()
            print("PID:", pid)
            print("Process:", name)
            print("Location:", process_path)
            print("Risk Score:", str(risk_score) + "/100")
            print("Risk Level:", risk_level)

            if reasons:

                print("Reasons:")

                for reason in reasons:

                    print("-", reason)

            print("------------------------------------------")

            # Save suspicious processes
            if risk_score > 0:

                suspicious_processes.append({
                    "pid": pid,
                    "name": name,
                    "location": process_path,
                    "score": risk_score,
                    "level": risk_level,
                    "reasons": reasons
                })

            # ----------------------------------
            # Save ALL processes for report
            # ----------------------------------

            report_processes.append({
                "pid": pid,
                "name": name,
                "location": process_path,
                "score": risk_score,
                "level": risk_level
            })

            # ----------------------------------
            # Alert
            # ----------------------------------

            if risk_score >= 60:

                show_alert(
                    name,
                    risk_score,
                    risk_level
                )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):

            pass

    return suspicious_processes


# ==========================================
# STARTUP SCANNER
# ==========================================

def scan_startup():

    print()
    print("==========================================")
    print("           STARTUP SCANNER")
    print("==========================================")

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

            print()
            print("Startup Location:")
            print(path)

            print("------------------------------------------")

            i = 0

            while True:

                try:

                    name, value, value_type = winreg.EnumValue(
                        key,
                        i
                    )

                    print("Program:", name)
                    print("Command:", value)

                    startup_programs.append({
                        "name": name,
                        "command": value
                    })

                    report_startup.append({
                        "name": name,
                        "command": value
                    })

                    i = i + 1

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
# CREATE REPORT
# ==========================================

def create_report(
    suspicious_processes,
    startup_programs
):

    # Create reports folder
    reports_folder = "reports"

    if not os.path.exists(reports_folder):

        os.makedirs(reports_folder)

    # Create unique filename
    report_name = (
        "scan_report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".txt"
    )

    report_path = os.path.join(
        reports_folder,
        report_name
    )

    # Determine overall risk
    if len(suspicious_processes) > 0:

        highest_score = max(
            item["score"]
            for item in suspicious_processes
        )

        if highest_score >= 60:

            overall_risk = "HIGH"

        elif highest_score >= 30:

            overall_risk = "MEDIUM"

        else:

            overall_risk = "LOW"

    else:

        overall_risk = "LOW"

    # Write report
    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as report:

        report.write(
            "==========================================\n"
        )

        report.write(
            "           KEYGUARD SCAN REPORT\n"
        )

        report.write(
            "==========================================\n\n"
        )

        report.write(
            "Scan Date: "
            + scan_time
            + "\n\n"
        )

        report.write(
            "------------------------------------------\n"
        )

        report.write(
            "PROCESS SCAN RESULTS\n"
        )

        report.write(
            "------------------------------------------\n\n"
        )

        report.write(
            "Total Processes Checked: "
            + str(len(report_processes))
            + "\n"
        )

        report.write(
            "Suspicious Processes: "
            + str(len(suspicious_processes))
            + "\n\n"
        )

        if suspicious_processes:

            for item in suspicious_processes:

                report.write(
                    "PID: "
                    + str(item["pid"])
                    + "\n"
                )

                report.write(
                    "Process: "
                    + str(item["name"])
                    + "\n"
                )

                report.write(
                    "Location: "
                    + str(item["location"])
                    + "\n"
                )

                report.write(
                    "Risk Score: "
                    + str(item["score"])
                    + "/100\n"
                )

                report.write(
                    "Risk Level: "
                    + str(item["level"])
                    + "\n"
                )

                report.write("Reasons:\n")

                for reason in item["reasons"]:

                    report.write(
                        "- "
                        + reason
                        + "\n"
                    )

                report.write("\n")

        else:

            report.write(
                "No suspicious processes detected.\n\n"
            )

        report.write(
            "------------------------------------------\n"
        )

        report.write(
            "STARTUP PROGRAMS\n"
        )

        report.write(
            "------------------------------------------\n\n"
        )

        report.write(
            "Startup Programs Found: "
            + str(len(startup_programs))
            + "\n\n"
        )

        for program in startup_programs:

            report.write(
                "Program: "
                + str(program["name"])
                + "\n"
            )

            report.write(
                "Command: "
                + str(program["command"])
                + "\n\n"
            )

        report.write(
            "------------------------------------------\n"
        )

        report.write(
            "OVERALL RISK LEVEL: "
            + overall_risk
            + "\n"
        )

        report.write(
            "------------------------------------------\n"
        )

    return report_path


# ==========================================
# MAIN PROGRAM
# ==========================================

print()
print("==========================================")
print("       KEYGUARD SECURITY TOOL")
print("==========================================")

print(
    "Intelligent Keylogger Detection System"
)

print("==========================================")


# Run process scanner
process_results = scan_processes()


# Run startup scanner
startup_results = scan_startup()


# Create report
report_file = create_report(
    process_results,
    startup_results
)


# ==========================================
# FINAL SUMMARY
# ==========================================

print()
print("==========================================")
print("              SCAN COMPLETE")
print("==========================================")

print(
    "Suspicious processes:",
    len(process_results)
)

print(
    "Startup programs found:",
    len(startup_results)
)

print()
print("Report created:")
print(report_file)

print()
print("KeyGuard scan finished.")

print("==========================================")