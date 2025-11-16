📖 Overview

ReconX Pro ek advanced reconnaissance tool hai jo Amass se bhi powerful hai. Ye tool intelligence gathering, enumeration, aur vulnerability assessment ek hi platform par provide karta hai. Pure tarah se Python mein built aur Go tools ke saath integrated.
text

██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝
              R E C O N   M A S T E R

✨ Features
🔍 Intelligence Gathering

    Threat Intelligence (VirusTotal, AlienVault, RiskIQ)

    Cloud Recon (AWS, Azure, GCP, DigitalOcean)

    GitHub Intelligence (Code, Repos, Users)

    Social Media Recon (LinkedIn, Twitter, Facebook)

    Employee Discovery

    Dark Web Monitoring

🎯 Advanced Enumeration

    Certificate Transparency Logs

    DNS Bruteforce (Multi-resolver)

    Subdomain Permutations

    Web Archives Analysis

    JavaScript File Analysis

    DNS Zone Walking

🔓 Vulnerability Assessment

    Security Headers Analysis

    CORS Misconfiguration

    Subdomain Takeover Checks

    SSL/TLS Scanning

    Exposed File Discovery

⚡ Performance

    Multi-threading (Up to 150 threads)

    Async Operations

    Go Tools Integration

    Smart Rate Limiting

🛠 Installation
Prerequisites

    Python 3.8+

    pip (Python package manager)

Step 1: Download ReconX
bash

# Kali Linux / Termux
git clone https://github.com/reconxpro/reconx.git
cd reconx

# Windows
# Download ZIP from GitHub aur extract karein

Step 2: Install Dependencies
bash

pip install -r requirements.txt

Step 3: Verify Installation
bash

python reconx.py --version

📖 Usage Guide
Basic Help
bash

python reconx.py -h
python reconx.py --help

🕵️ Intelligence Gathering
bash

# Domain intelligence
python reconx.py intel -d example.com

# ASN intelligence
python reconx.py intel -asn 15169,13335

# Organization search
python reconx.py intel -org "Facebook" -whois

# List data sources
python reconx.py intel -list

🔍 Enumeration
bash

# Basic enumeration
python reconx.py enum -d example.com

# Active enumeration with IPs
python reconx.py enum -d example.com -active -ip -src

# Passive enumeration only
python reconx.py enum -d example.com -passive -json results.json

# With custom wordlist
python reconx.py enum -d example.com -aw custom_wordlist.txt

# Save outputs
python reconx.py enum -d example.com -oA all_results.txt -oI ips.txt -json results.json

🚀 Complete Reconnaissance
bash

# Full reconnaissance
python reconx.py -d example.com --full

# Specific modules
python reconx.py -d example.com --intel --enum --vuln

# Stealth mode
python reconx.py -d example.com --full --stealth

# Aggressive mode
python reconx.py -d example.com --full --aggressive

🖥 Platform-Specific Guide
🐧 Kali Linux
bash

# Update system
sudo apt update && sudo apt upgrade

# Install Python and pip
sudo apt install python3 python3-pip

# Install dependencies
pip3 install -r requirements.txt

# Run tool
python3 reconx.py -d target.com --full

📱 Termux (Android)
bash

# Update packages
pkg update && pkg upgrade

# Install Python
pkg install python python-pip

# Install dependencies
pip install -r requirements.txt

# Storage permission
termux-setup-storage

# Run tool
python reconx.py -d target.com --enum

🪟 Windows
bash

# Python download karein from python.org
# System PATH mein Python add karein

# Command Prompt ya PowerShell khol ke
pip install -r requirements.txt

# Run tool
python reconx.py -d target.com --full

🔧 Advanced Usage
Configuration File
ini

# config.ini
[api_keys]
shodan = YOUR_SHODAN_API_KEY
virustotal = YOUR_VIRUSTOTAL_API_KEY
securitytrails = YOUR_SECURITYTRAILS_API_KEY

[settings]
threads = 100
timeout = 15
user_agent = Mozilla/5.0 (ReconX Pro)

With Config File
bash

python reconx.py -d example.com --full -config config.ini

Batch Processing
bash

# domains.txt file banayein
echo "example.com" >> domains.txt
echo "target.com" >> domains.txt

# Batch processing
python reconx.py -df domains.txt --full -oA batch_results/

📊 Output Formats

ReconX multiple output formats support karta hai:

    Text (-o, -oA)

    JSON (-json, -oJ)

    CSV (Automatically generated)

    HTML Report (Coming soon)

🛡 Legal Disclaimer

⚠️ Important:

    Ye tool educational purposes ke liye hai

    Always proper authorization ke bina use na karein

    Responsible disclosure follow karein

    Laws aur regulations ka respect karein

🐛 Troubleshooting
Common Issues

Import Errors:
bash

pip install --upgrade pip
pip install -r requirements.txt --force-reinstall

DNS Resolution Issues:
bash

# Custom DNS resolver use karein
python reconx.py enum -d example.com -r 8.8.8.8,1.1.1.1

Permission Errors (Termux):
bash

termux-setup-storage
pkg install root-repo

Windows SSL Errors:
bash

pip install --upgrade certifi

🔄 Updates

Tool ko update karne ke liye:
bash

git pull origin master
pip install -r requirements.txt --upgrade

🤝 Contributing

ReconX open source project hai. Aap bhi contribute kar sakte hain:

    Fork the repository

    New feature add karein

    Pull request submit karein

📞 Support

    GitHub Issues: ReconX Issues

    Documentation: ReconX Docs

    Tutorial: ReconX Tutorial

📜 License

MIT License - Free for educational and authorized security testing.

🎯 Happy Reconnaissance! Always Hack Responsibly!

ReconX Pro - Advanced Reconnaissance Tool | Made with ❤️ for Security Researchers
This response is AI-generated, for reference only.
