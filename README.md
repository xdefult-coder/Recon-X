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

```bash
python3 reconx.py

## Installation
```bash
pip install -r requirements.txt

## Installation
```bash

python3 reconx.py intel -d example.com -o intel.txt
python3 reconx.py enum -d example.com -o enum.txt

