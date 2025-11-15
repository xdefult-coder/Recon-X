import os
import sys
import requests
import json
from zipfile import ZipFile
from datetime import datetime
import platform
from sublist3r import main as sublist3r_main

# -----------------------------
# Colors
# -----------------------------
class color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# -----------------------------
# Banner
# -----------------------------
def banner():
    print(color.HEADER + """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝
                                                
          """ + color.ENDC)
    print(color.BOLD + color.OKCYAN + "             Recon X - Advanced Passive Recon Tool\n" + color.ENDC)

banner()

# -----------------------------
# Passive Intel: crt.sh
# -----------------------------
def intel(domain, output_file):
    print(color.OKBLUE + f"[*] Running passive intel for {domain}..." + color.ENDC)
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url)
        r.raise_for_status()
        data = r.json()
        results = set()
        for entry in data:
            names = entry.get("name_value", "")
            for n in names.split("\n"):
                results.add(n.strip())
        with open(output_file, "w") as f:
            for rline in sorted(results):
                f.write(rline + "\n")
        print(color.OKGREEN + f"[+] Intel done. {len(results)} entries saved in {output_file}" + color.ENDC)
    except Exception as e:
        print(color.FAIL + f"[!] Intel error: {e}" + color.ENDC)

# -----------------------------
# Passive Enum: Sublist3r
# -----------------------------
def enum(domain, output_file):
    print(color.OKBLUE + f"[*] Running passive enumeration for {domain}..." + color.ENDC)
    try:
        sublist3r_main(domain, 40, output_file, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                lines = f.readlines()
            print(color.OKGREEN + f"[+] Enum done. {len(lines)} subdomains saved in {output_file}" + color.ENDC)
        else:
            print(color.WARNING + "[!] Enum finished but output file not found." + color.ENDC)
    except Exception as e:
        print(color.FAIL + f"[!] Enum error: {e}" + color.ENDC)

# -----------------------------
# Main
# -----------------------------
def main():
    domain = input(color.OKCYAN + "Enter target domain (e.g. example.com): " + color.ENDC).strip()
    output_file = input(color.OKCYAN + "Enter output file name [default: output.txt]: " + color.ENDC).strip()
    if not output_file:
        output_file = "output.txt"

    print(color.OKCYAN + "\nChoose Recon X module:" + color.ENDC)
    print("1. intel  - Passive intelligence gathering")
    print("2. enum   - Passive enumeration")
    choice = input("\nEnter choice [1/2]: ").strip()

    start_time = datetime.now()

    if choice == "1":
        intel(domain, output_file)
    elif choice == "2":
        enum(domain, output_file)
    else:
        print(color.FAIL + "Invalid choice!" + color.ENDC)
        sys.exit(1)

    # -----------------------------
    # Create ZIP
    # -----------------------------
    zip_name = "ReconX.zip"
    print(color.OKBLUE + f"\n[*] Creating zip file {zip_name}..." + color.ENDC)
    folder_path = os.getcwd()
    with ZipFile(zip_name, 'w') as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file != zip_name:
                    filepath = os.path.join(root, file)
                    arcname = os.path.relpath(filepath, folder_path)
                    zipf.write(filepath, arcname)
    print(color.OKGREEN + f"✔️  Zip file {zip_name} created." + color.ENDC)

    end_time = datetime.now()
    print(color.BOLD + color.OKCYAN + f"\n🎉 Recon X completed in {end_time - start_time}\n" + color.ENDC)

if __name__ == "__main__":
    main()
