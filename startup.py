import winreg

print("====================================")
print("       KEYGUARD STARTUP SCANNER")
print("====================================")

startup_locations = [
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),

    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run")
]

for root, path in startup_locations:

    try:
        key = winreg.OpenKey(root, path)

        print(f"\nStartup Location: {path}")
        print("------------------------------------")

        i = 0

        while True:
            try:
                name, value, value_type = winreg.EnumValue(key, i)

                print(f"Program: {name}")
                print(f"Command: {value}")
                print()

                i += 1

            except OSError:
                break

        winreg.CloseKey(key)

    except PermissionError:
        print(f"Permission denied: {path}")

    except FileNotFoundError:
        print(f"Startup location not found: {path}")