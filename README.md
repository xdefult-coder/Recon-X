# Recon X

Advanced Passive Reconnaissance Framework for Bug Bounty Hunters.

## Features
- Passive subdomain enumeration (crt.sh, Wayback, GitHub, URLScan)
- Async, fast enumeration
- Merged and grouped output
- Cross-platform: Kali Linux, Termux, Windows

## Installation
```bash
pip install -r requirements.txt

## Installation
```bash

python3 reconx.py intel -d example.com -o intel.txt
python3 reconx.py enum -d example.com -o enum.txt

