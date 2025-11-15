import os
import sys
import subprocess
import platform
from zipfile import ZipFile

# -----------------------------
# Colors for terminal
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
    print(color.BOLD + color.OKCYAN + "             Recon X - Advanced Recon Tool\n" + color.ENDC)

banner()

# -----------------------------
# 1. Setup paths
# -----------------------------
folder_path = os.getcwd()
venv_name = "reconx-venv"
venv_path = os.path.join(folder_path, venv_name)

# OS specific paths
if platform.system() == "Windows":
    python_exe = os.path.join(venv_path, "Scripts", "python.exe")
    pip_exe = os.path.join(venv_path, "Scripts", "pip.exe")
else:
    python_exe = os.path.join(venv_path, "bin", "python")
    pip_exe = os.path.join(venv_path, "bin", "pip")

# -----------------------------
# 2. Create virtual environment
# -----------------------------
if not os.path.exists(venv_path):
    print(color.OKBLUE + "[*] Creating virtual environment..." + color.ENDC)
    subprocess.run([sys.executable, "-m", "venv", venv_name])

# -----------------------------
# 3. Upgrade pip
# -----------------------------
print(color.OKBLUE + "[*] Upgrading pip..." + color.ENDC)
subprocess.run([python_exe, "-m", "pip", "install", "--upgrade", "pip"], stdout=subprocess.DEVNULL)

# -----------------------------
# 4. Install requirements
# -----------------------------
if os.path.exists("requirements.txt"):
    print(color.OKBLUE + "[*] Installing dependencies..." + color.ENDC)
    subprocess.run([pip_exe, "install", "-r", "requirements.txt"], stdout=subprocess.DEVNULL)
else:
    print(color.WARNING + "[!] requirements.txt not found. Skipping dependency install." + color.ENDC)

# -----------------------------
# 5. Select Recon X module
# -----------------------------
print(color.OKCYAN + "\nChoose Recon X module:\n" + color.ENDC)
print(color.BOLD + "1. intel  - Passive intelligence gathering")
print("2. enum   - Passive enumeration" + color.ENDC)

choice = input("\nEnter choice [1/2]: ").strip()
domain = input(color.OKCYAN + "Enter target domain (e.g. example.com): " + color.ENDC).strip()
output_file = input(color.OKCYAN + "Enter output file name [default: output.txt]: " + color.ENDC).strip()
if not output_file:
    output_file = "output.txt"

if choice == "1":
    cmd = [python_exe, "reconx.py", "intel", "-d", domain, "-o", output_file]
elif choice == "2":
    cmd = [python_exe, "reconx.py", "enum", "-d", domain, "-o", output_file]
else:
    print(color.FAIL + "Invalid choice!" + color.ENDC)
    sys.exit(1)

# -----------------------------
# 6. Run Recon X
# -----------------------------
print(color.OKGREEN + f"\n[*] Running Recon X on {domain}...\n" + color.ENDC)
subprocess.run(cmd)

# -----------------------------
# 7. Show summary
# -----------------------------
if os.path.exists(output_file):
    with open(output_file, 'r') as f:
        lines = f.readlines()
    print(color.OKGREEN + f"\n✔️  Recon X completed. {len(lines)} results saved to {output_file}" + color.ENDC)
else:
    print(color.WARNING + f"\n⚠️  Output file {output_file} not found!" + color.ENDC)

# -----------------------------
# 8. Create ZIP
# -----------------------------
zip_name = "ReconX.zip"
print(color.OKBLUE + f"\n[*] Creating zip file {zip_name}..." + color.ENDC)
with ZipFile(zip_name, 'w') as zipf:
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file != zip_name:
                filepath = os.path.join(root, file)
                arcname = os.path.relpath(filepath, folder_path)
                zipf.write(filepath, arcname)

print(color.OKGREEN + f"✔️  Zip file {zip_name} created." + color.ENDC)

# -----------------------------
# 9. Optional GitHub Push
# -----------------------------
push_github = input(color.OKCYAN + "\nDo you want to push Recon X to GitHub? [y/N]: " + color.ENDC).strip().lower() == "y"
if push_github:
    github_url = input(color.OKCYAN + "Enter GitHub repository URL: " + color.ENDC).strip()
    commit_msg = input(color.OKCYAN + "Enter commit message [default: 'Update Recon X results']: " + color.ENDC).strip()
    if not commit_msg:
        commit_msg = "Update Recon X results"
    
    print(color.OKBLUE + "[*] Pushing to GitHub..." + color.ENDC)
    subprocess.run(["git", "init"], cwd=folder_path)
    subprocess.run(["git", "remote", "remove", "origin"], cwd=folder_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "remote", "add", "origin", github_url], cwd=folder_path)
    subprocess.run(["git", "add", "."], cwd=folder_path)
    subprocess.run(["git", "commit", "-m", commit_msg], cwd=folder_path)
    subprocess.run(["git", "branch", "-M", "main"], cwd=folder_path)
    subprocess.run(["git", "push", "-u", "origin", "main"], cwd=folder_path)
    print(color.OKGREEN + "✔️  Recon X pushed to GitHub successfully!" + color.ENDC)

print(color.BOLD + color.OKCYAN + "\n🎉 Workflow completed. Your Recon X results and zip are ready!" + color.ENDC)
