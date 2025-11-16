#!/usr/bin/env python3
"""
ReconX Pro - Amass-style CLI Tool with Go Integration
Hybrid Python + Go for maximum performance
"""

import os
import sys
import argparse
import subprocess
import tempfile
import json
from pathlib import Path

# -----------------------------
# CUSTOM BRANDING - APNA BANNER
# -----------------------------
BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝
              R E C O N   M A S T E R   [GO]
"""

VERSION = "v2.1.0"
AUTHOR = "ReconX Project - @reconxpro (Python + Go Hybrid)"

# -----------------------------
# GO INTEGRATION MODULE
# -----------------------------
class GoIntegration:
    def __init__(self):
        self.go_available = self._check_go_installation()
        self.go_tools = {
            'amass': self._check_tool('amass'),
            'subfinder': self._check_tool('subfinder'),
            'assetfinder': self._check_tool('assetfinder'),
            'httpx': self._check_tool('httpx'),
            'nuclei': self._check_tool('nuclei'),
            'katana': self._check_tool('katana'),
            'gau': self._check_tool('gau'),
            'waybackurls': self._check_tool('waybackurls')
        }
    
    def _check_go_installation(self):
        """Check if Go is installed"""
        try:
            result = subprocess.run(['go', 'version'], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_tool(self, tool_name):
        """Check if specific Go tool is installed"""
        try:
            result = subprocess.run([tool_name, '-h'], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def install_go_tools(self):
        """Install required Go tools"""
        if not self.go_available:
            print("[❌] Go language not installed. Please install Go first.")
            return False
        
        tools_to_install = {
            'amass': 'go install -v github.com/owasp-amass/amass/v4/...@master',
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
            'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'katana': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
            'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest',
            'waybackurls': 'go install github.com/tomnomnom/waybackurls@latest'
        }
        
        print("[🔧] Installing Go tools...")
        for tool, cmd in tools_to_install.items():
            if not self.go_tools.get(tool):
                print(f"  [📦] Installing {tool}...")
                try:
                    subprocess.run(cmd.split(), check=True)
                    self.go_tools[tool] = True
                    print(f"  [✅] {tool} installed successfully")
                except subprocess.CalledProcessError as e:
                    print(f"  [❌] Failed to install {tool}: {e}")
        
        return True
    
    def run_amass(self, domain, active=False, output_file=None):
        """Run Amass Go tool"""
        if not self.go_tools.get('amass'):
            print("[❌] Amass not installed. Run 'reconx tools install' first.")
            return None
        
        cmd = ['amass', 'enum', '-d', domain, '-json', '/dev/stdout']
        
        if active:
            cmd.extend(['-active'])
        
        try:
            print(f"[🚀] Running Amass (Go) on {domain}...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse JSON output
                lines = result.stdout.strip().split('\n')
                data = [json.loads(line) for line in lines if line]
                
                if output_file:
                    with open(output_file, 'w') as f:
                        for item in data:
                            f.write(json.dumps(item) + '\n')
                
                return data
            else:
                print(f"[❌] Amass error: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"[❌] Amass execution failed: {e}")
            return None
    
    def run_subfinder(self, domain, output_file=None):
        """Run SubFinder Go tool"""
        if not self.go_tools.get('subfinder'):
            print("[❌] SubFinder not installed.")
            return None
        
        cmd = ['subfinder', '-d', domain, '-silent']
        
        try:
            print(f"[🚀] Running SubFinder (Go) on {domain}...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                subdomains = result.stdout.strip().split('\n')
                
                if output_file:
                    with open(output_file, 'w') as f:
                        for subdomain in subdomains:
                            if subdomain:
                                f.write(subdomain + '\n')
                
                return subdomains
            else:
                print(f"[❌] SubFinder error: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"[❌] SubFinder execution failed: {e}")
            return None
    
    def run_httpx(self, domains_file, output_file=None):
        """Run HTTPx Go tool for live host detection"""
        if not self.go_tools.get('httpx'):
            print("[❌] HTTPx not installed.")
            return None
        
        cmd = ['httpx', '-l', domains_file, '-silent', '-status-code', '-title', '-tech-detect']
        
        try:
            print("[🚀] Running HTTPx (Go) for live host detection...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                live_hosts = result.stdout.strip().split('\n')
                
                if output_file:
                    with open(output_file, 'w') as f:
                        for host in live_hosts:
                            if host:
                                f.write(host + '\n')
                
                return live_hosts
            else:
                print(f"[❌] HTTPx error: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"[❌] HTTPx execution failed: {e}")
            return None
    
    def run_nuclei(self, targets_file, templates=None):
        """Run Nuclei Go tool for vulnerability scanning"""
        if not self.go_tools.get('nuclei'):
            print("[❌] Nuclei not installed.")
            return None
        
        cmd = ['nuclei', '-l', targets_file, '-silent']
        
        if templates:
            cmd.extend(['-t', templates])
        
        try:
            print("[🚀] Running Nuclei (Go) for vulnerability scanning...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                vulnerabilities = result.stdout.strip().split('\n')
                return vulnerabilities
            else:
                print(f"[❌] Nuclei error: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"[❌] Nuclei execution failed: {e}")
            return None

# -----------------------------
# HYBRID RECON ENGINE
# -----------------------------
class HybridReconEngine:
    def __init__(self):
        self.go_integration = GoIntegration()
        self.results = {}
    
    def comprehensive_hybrid_scan(self, domain, active=False):
        """Run hybrid scan using both Python and Go tools"""
        print(f"[🎯] Starting Hybrid Scan for {domain}")
        print("[🔀] Using Python + Go tools for maximum coverage")
        
        self.results[domain] = {
            'subdomains': set(),
            'ips': set(),
            'live_hosts': set(),
            'vulnerabilities': [],
            'technologies': set()
        }
        
        # Phase 1: Subdomain Discovery (Go Tools)
        self._phase1_subdomain_discovery(domain, active)
        
        # Phase 2: Live Host Detection (Go Tools)
        self._phase2_live_host_detection(domain)
        
        # Phase 3: Vulnerability Scanning (Go Tools)
        self._phase3_vulnerability_scanning(domain)
        
        # Phase 4: Python-based Advanced Recon
        self._phase4_python_advanced_recon(domain)
        
        return self.results[domain]
    
    def _phase1_subdomain_discovery(self, domain, active):
        """Phase 1: Subdomain discovery using Go tools"""
        print("\n[1️⃣] PHASE 1: Subdomain Discovery (Go Tools)")
        
        # Run Amass
        amass_results = self.go_integration.run_amass(domain, active)
        if amass_results:
            for item in amass_results:
                if 'name' in item:
                    self.results[domain]['subdomains'].add(item['name'])
        
        # Run SubFinder
        subfinder_results = self.go_integration.run_subfinder(domain)
        if subfinder_results:
            self.results[domain]['subdomains'].update(subfinder_results)
        
        print(f"    [✅] Found {len(self.results[domain]['subdomains'])} subdomains")
    
    def _phase2_live_host_detection(self, domain):
        """Phase 2: Live host detection using HTTPx"""
        print("\n[2️⃣] PHASE 2: Live Host Detection (Go Tools)")
        
        # Save subdomains to temporary file for HTTPx
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for subdomain in self.results[domain]['subdomains']:
                f.write(subdomain + '\n')
            temp_file = f.name
        
        try:
            # Run HTTPx
            live_hosts = self.go_integration.run_httpx(temp_file)
            if live_hosts:
                self.results[domain]['live_hosts'].update(live_hosts)
                print(f"    [✅] Found {len(live_hosts)} live hosts")
        finally:
            # Cleanup temp file
            os.unlink(temp_file)
    
    def _phase3_vulnerability_scanning(self, domain):
        """Phase 3: Vulnerability scanning using Nuclei"""
        print("\n[3️⃣] PHASE 3: Vulnerability Scanning (Go Tools)")
        
        if not self.results[domain]['live_hosts']:
            print("    [ℹ️] No live hosts found for vulnerability scanning")
            return
        
        # Save live hosts to temporary file for Nuclei
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for host in self.results[domain]['live_hosts']:
                f.write(host.split()[0] + '\n')  # Get only URL part
            temp_file = f.name
        
        try:
            # Run Nuclei
            vulnerabilities = self.go_integration.run_nuclei(temp_file)
            if vulnerabilities:
                self.results[domain]['vulnerabilities'].extend(vulnerabilities)
                print(f"    [✅] Found {len(vulnerabilities)} potential vulnerabilities")
        finally:
            # Cleanup temp file
            os.unlink(temp_file)
    
    def _phase4_python_advanced_recon(self, domain):
        """Phase 4: Python-based advanced reconnaissance"""
        print("\n[4️⃣] PHASE 4: Advanced Reconnaissance (Python)")
        
        # Python-specific advanced recon
        from reconx_advanced import AdvancedRecon
        advanced = AdvancedRecon(domain)
        
        # Cloud reconnaissance
        cloud_assets = advanced.cloud_recon()
        self.results[domain]['cloud_assets'] = cloud_assets
        
        # GitHub reconnaissance
        github_info = advanced.github_recon()
        self.results[domain]['github_info'] = github_info
        
        print("    [✅] Advanced reconnaissance completed")

# -----------------------------
# TOOLS SUBCOMMAND
# -----------------------------
def tools_usage():
    """Tools subcommand usage"""
    tools_help = """
Usage: reconx tools [options]

Manage Go tools and dependencies

SUBCOMMANDS:
   install     Install all required Go tools
   status      Check installation status of Go tools
   update      Update all installed Go tools
   list        List all available Go tools

OPTIONS:
   -h, --help  Show this help message

EXAMPLE:
   reconx tools install
   reconx tools status
   reconx tools update
"""
    print(tools_help)

def handle_tools_command(args):
    """Handle tools subcommand"""
    go_integration = GoIntegration()
    
    if args.subcommand == "install":
        print("[🔧] Installing Go tools...")
        go_integration.install_go_tools()
        
    elif args.subcommand == "status":
        print("[📊] Go Tools Status:")
        print(f"    Go Language: {'✅ Installed' if go_integration.go_available else '❌ Not Installed'}")
        print("\n    Tools Status:")
        for tool, installed in go_integration.go_tools.items():
            status = "✅ Installed" if installed else "❌ Not Installed"
            print(f"    {tool:15} {status}")
            
        if not go_integration.go_available:
            print("\n[💡] Install Go from: https://golang.org/dl/")
    
    elif args.subcommand == "update":
        print("[🔄] Updating Go tools...")
        # Implementation for updating tools
    
    elif args.subcommand == "list":
        print("[📋] Available Go Tools:")
        tools_list = """
  🛠️  Amass        - OWASP Amass for attack surface mapping
  🛠️  SubFinder    - Subdomain discovery tool
  🛠️  AssetFinder  - Find domains and subdomains
  🛠️  HTTPx        - Fast and multi-purpose HTTP toolkit
  🛠️  Nuclei       - Fast and customizable vulnerability scanner
  🛠️  Katana       - Next-generation crawling and spidering
  🛠️  GAU          - Fetch known URLs from AlienVault's OTX
  🛠️  WaybackURLs  - Fetch known URLs from Wayback Machine
        """
        print(tools_list)

# -----------------------------
# UPDATED MAIN COMMAND HANDLER
# -----------------------------
def main():
    if len(sys.argv) == 1:
        print_banner()
        print_usage()
        return
    
    # Add tools subcommand handling
    if len(sys.argv) > 1 and sys.argv[1] == "tools":
        tools_parser = argparse.ArgumentParser(description="ReconX Tools Management", add_help=False)
        tools_parser.add_argument('subcommand', nargs='?', help='Subcommand (install|status|update|list)')
        tools_parser.add_argument('-h', '--help', action='store_true', help='Show help')
        
        args, unknown = tools_parser.parse_known_args(sys.argv[2:])
        
        if args.help or not args.subcommand:
            tools_usage()
        else:
            handle_tools_command(args)
        return
    
    # ... (rest of existing main function)

# -----------------------------
# UPDATED USAGE INFORMATION
# -----------------------------
def print_usage():
    """Updated usage with Go tools"""
    usage = f"""
Usage: reconx intel|enum|tools [options]

  -h, --help     Show the program usage message
  -version       Print the version number
  -config string Path to the INI configuration file
  -dir string    Path to the directory containing the graph database

Subcommands:

    reconx intel  - Discover targets for enumerations
    reconx enum   - Perform enumerations and network mapping
    reconx tools  - Manage Go tools and dependencies [NEW!]

Go Integration Features:

    🚀 Hybrid scanning (Python + Go)
    ⚡ High-performance subdomain enumeration
    🔍 Advanced vulnerability scanning
    🌐 Live host detection

The user's guide can be found here:
https://github.com/reconxpro/reconx/blob/master/docs/user_guide.md

Go Tools Installation:
  reconx tools install    # Install all Go tools
  reconx tools status     # Check installation status
"""
    print(usage)

# -----------------------------
# UPDATED ENUM COMMAND WITH GO
# -----------------------------
def handle_enum_command(args):
    """Updated enum command with Go integration"""
    if args.hybrid or args.go:
        # Use hybrid engine
        engine = HybridReconEngine()
        results = engine.comprehensive_hybrid_scan(args.d, active=args.active)
        
        # Save results
        if args.oA:
            save_hybrid_results(results, args.oA)
            
    else:
        # Use original Python-only engine
        from reconx_enum import ReconEnum
        enum = ReconEnum()
        # ... existing code

def save_hybrid_results(results, output_file):
    """Save hybrid scan results"""
    with open(output_file, 'w') as f:
        f.write("RECONX HYBRID SCAN RESULTS\n")
        f.write("=" * 50 + "\n\n")
        
        for domain, data in results.items():
            f.write(f"DOMAIN: {domain}\n")
            f.write(f"Subdomains Found: {len(data.get('subdomains', []))}\n")
            f.write(f"Live Hosts: {len(data.get('live_hosts', []))}\n")
            f.write(f"Vulnerabilities: {len(data.get('vulnerabilities', []))}\n\n")
            
            f.write("SUBDOMAINS:\n")
            for subdomain in sorted(data.get('subdomains', [])):
                f.write(f"  {subdomain}\n")
            
            f.write("\nLIVE HOSTS:\n")
            for host in data.get('live_hosts', []):
                f.write(f"  {host}\n")
            
            f.write("\nVULNERABILITIES:\n")
            for vuln in data.get('vulnerabilities', []):
                f.write(f"  {vuln}\n")

if __name__ == "__main__":
    main()
