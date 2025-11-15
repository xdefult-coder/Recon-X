# Recon X

Advanced Passive Reconnaissance Framework for Bug Bounty Hunters.

## Features
- Passive subdomain enumeration (crt.sh, Wayback, GitHub, URLScan)
- Async, fast enumeration
- Merged and grouped output
- Cross-platform: Kali Linux, Termux, Windows


# Recon X - Advanced Recon Tool

Recon X is a professional-level recon & OSINT automation tool. It works on:

- Kali Linux
- Termux
- Windows

## Features

- Banner display
- Module selection: intel / enum
- Virtual environment auto-setup
- Dependency installation from requirements.txt
- Output summary & file
- Automatic zip creation (ReconX.zip)
- Optional GitHub push

## Installation & Usage

1. Clone or download the repository.
2. Ensure Python 3 is installed.
3. Open terminal / CMD in the folder.
4. Run:

5. Quick Install Without Virtual Environment
If not using a virtual environment:
Agar virtual env nahi use karna:

   sudo apt install python3-requests
sudo pip3 install sublist3r --break-system-packages
 
```bash
python3 reconx.py

## Installation
```bash
# 1. Create a virtual environment
python3 -m venv reconx-venv

# 2. Activate the virtual environment
source reconx-venv/bin/activate      # Linux / Termux
# .\reconx-venv\Scripts\activate     # Windows

# 3. Upgrade pip
pip install --upgrade pip

# 4. Install required modules
pip install -r requirements.txt

python3 reconx.py

If you're done, deactivate it:
   deactivate



