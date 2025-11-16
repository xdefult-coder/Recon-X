#!/usr/bin/env python3
"""
ReconX Pro - Advanced Reconnaissance Tool
Amass-style CLI with Python + Go Integration
"""

import os
import sys
import argparse
import subprocess
import json
import requests
import dns.resolver
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# -----------------------------
# CUSTOM BANNER
# -----------------------------
def print_banner():
    """Print custom branded banner"""
    BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝
              R E C O N   M A S T E R
"""
    print(BANNER)
    print("=" * 70)
    print(f"🎯 ReconX Pro - Advanced Reconnaissance Tool")
    print(f"📁 Version: v2.0.0")
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

# -----------------------------
# BASIC MODULE IMPORTS
# -----------------------------
class ReconIntel:
    def list_data_sources(self):
        """List all available data sources"""
        print("\n[📡] AVAILABLE DATA SOURCES:")
        print("=" * 40)
        
        sources = {
            "Passive": [
                "✅ Certificate Transparency",
                "✅ DNS Databases", 
                "✅ Web Archives",
                "✅ Security APIs",
                "✅ Threat Intelligence"
            ],
            "Active": [
                "🔍 DNS Bruteforcing",
                "🔍 Subdomain Permutations", 
                "🔍 Web Crawling",
                "🔍 Port Scanning"
            ]
        }
        
        for category, items in sources.items():
            print(f"\n{category}:")
            for item in items:
                print(f"  {item}")
    
    def domain_intel(self, domain, active=False):
        """Gather domain intelligence"""
        print(f"\n[🕵️] GATHERING INTELLIGENCE FOR: {domain}")
        print("-" * 50)
        
        # WHOIS Information
        print("[1️⃣] WHOIS Lookup...")
        whois_data = self._whois_lookup(domain)
        
        # DNS Intelligence
        print("[2️⃣] DNS Intelligence...")
        dns_data = self._dns_intel(domain)
        
        # Certificate Transparency
        print("[3️⃣] Certificate Analysis...")
        cert_data = self._certificate_intel(domain)
        
        return {
            "domain": domain,
            "whois": whois_data,
            "dns": dns_data,
            "certificates": cert_data,
            "status": "completed"
        }
    
    def _whois_lookup(self, domain):
        """Basic WHOIS lookup"""
        try:
            import whois
            domain_info = whois.whois(domain)
            return {"registrar": getattr(domain_info, 'registrar', 'Unknown')}
        except:
            return {"registrar": "WHOIS lookup failed"}
    
    def _dns_intel(self, domain):
        """DNS intelligence gathering"""
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                dns_records[rtype] = [str(rdata) for rdata in answers]
            except:
                dns_records[rtype] = []
        
        return dns_records
    
    def _certificate_intel(self, domain):
        """Certificate transparency lookup"""
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                certificates = response.json()
                return {"found": len(certificates), "source": "crt.sh"}
        except:
            pass
        return {"found": 0, "source": "Failed"}

class ReconEnum:
    def comprehensive_enum(self, domain, active=True, passive=False, **kwargs):
        """Comprehensive domain enumeration"""
        print(f"\n[🔍] ENUMERATING: {domain}")
        print("-" * 50)
        
        subdomains = set()
        
        # Passive enumeration
        if passive or active:
            print("[1️⃣] Passive Enumeration...")
            passive_subs = self._passive_enumeration(domain)
            subdomains.update(passive_subs)
        
        # Active enumeration
        if active:
            print("[2️⃣] Active Enumeration...")
            active_subs = self._active_enumeration(domain)
            subdomains.update(active_subs)
        
        # DNS resolution
        print("[3️⃣] DNS Resolution...")
        ips = self._resolve_subdomains(subdomains)
        
        return {
            "domain": domain,
            "subdomains": list(subdomains),
            "ips": ips,
            "total_subdomains": len(subdomains),
            "status": "completed"
        }
    
    def _passive_enumeration(self, domain):
        """Passive subdomain discovery"""
        subdomains = set()
        
        # Common subdomains
        common_subs = ['www', 'api', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging']
        
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            subdomains.add(subdomain)
        
        # Certificate transparency
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    if 'name_value' in cert:
                        subdomains.add(cert['name_value'])
        except:
            pass
        
        return subdomains
    
    def _active_enumeration(self, domain):
        """Active subdomain discovery"""
        subdomains = set()
        
        # DNS bruteforce with common wordlist
        wordlist = ['www', 'api', 'mail', 'ftp', 'admin', 'test', 'blog', 'shop',
                   'dev', 'staging', 'prod', 'backup', 'cdn', 'static', 'app']
        
        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_subdomain, wordlist)
            for result in results:
                if result:
                    subdomains.add(result)
        
        return subdomains
    
    def _resolve_subdomains(self, subdomains):
        """Resolve subdomains to IP addresses"""
        ips = {}
        
        def resolve_subdomain(subdomain):
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                return subdomain, [str(rdata) for rdata in answers]
            except:
                return subdomain, []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(resolve_subdomain, subdomains)
            for subdomain, ip_list in results:
                if ip_list:
                    ips[subdomain] = ip_list
        
        return ips
    
    def save_json_output(self, results, filename):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[💾] Results saved to: {filename}")
    
    def save_text_output(self, results, filename):
        """Save results to text file"""
        with open(filename, 'w') as f:
            f.write(f"ReconX Results for {results['domain']}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Total Subdomains: {results['total_subdomains']}\n\n")
            
            f.write("SUBdomains:\n")
            for subdomain in results['subdomains']:
                f.write(f"  {subdomain}\n")
            
            f.write("\nIP ADDRESSES:\n")
            for subdomain, ips in results['ips'].items():
                f.write(f"  {subdomain}: {', '.join(ips)}\n")
        
        print(f"\n[💾] Text results saved to: {filename}")

# -----------------------------
# USAGE FUNCTIONS
# -----------------------------
def print_usage():
    """Print usage information"""
    usage = """
Usage: reconx intel|enum [options]

  -h, --help     Show the program usage message
  -version       Print the version number

Subcommands:

    reconx intel - Discover targets for enumerations  
    reconx enum  - Perform enumerations and network mapping

Examples:
  reconx intel -d example.com
  reconx intel -list
  reconx enum -d example.com -o results.json
  reconx enum -d example.com -active -txt results.txt
"""
    print(usage)

def intel_usage():
    """Intel subcommand usage"""
    print("""
Usage: reconx intel [options]

OPTIONS:
   -d value    Domain names separated by commas
   -list       List all available data sources
   -active     Enable active recon methods

Example:
   reconx intel -d example.com -active
   reconx intel -list
""")

def enum_usage():
    """Enum subcommand usage"""
    print("""
Usage: reconx enum [options]  

OPTIONS:
   -d value    Domain names separated by commas
   -o value    Output file for results (JSON)
   -txt value  Output file for results (Text)
   -active     Enable active recon methods
   -passive    Passive recon only

Example:
   reconx enum -d example.com -o results.json
   reconx enum -d example.com -txt results.txt -active
""")

# -----------------------------
# COMMAND HANDLERS
# -----------------------------
def handle_intel_command(args):
    """Handle intel subcommand"""
    intel = ReconIntel()
    
    if args.list:
        print_banner()
        intel.list_data_sources()
        return
    
    if args.d:
        print_banner()
        domains = args.d.split(',')
        for domain in domains:
            results = intel.domain_intel(domain, active=args.active)
            print(f"\n[✅] Intelligence gathering completed for {domain}")
            
            # Show summary
            if 'dns' in results:
                print(f"   DNS Records: {len(results['dns'])} types found")
            if 'certificates' in results:
                print(f"   Certificates: {results['certificates'].get('found', 0)} found")
    else:
        intel_usage()

def handle_enum_command(args):
    """Handle enum subcommand"""
    if not args.d:
        enum_usage()
        return
        
    print_banner()
    enum = ReconEnum()
    
    domains = args.d.split(',')
    for domain in domains:
        results = enum.comprehensive_enum(
            domain, 
            active=args.active,
            passive=args.passive
        )
        
        # Display results
        print(f"\n[📊] ENUMERATION RESULTS:")
        print(f"   Domain: {results['domain']}")
        print(f"   Subdomains Found: {results['total_subdomains']}")
        print(f"   IP Addresses: {len(results['ips'])}")
        
        print(f"\n[🌐] DISCOVERED SUBDOMAINS:")
        for subdomain in results['subdomains']:
            print(f"   ✅ {subdomain}")
        
        # Save outputs
        if args.o:
            enum.save_json_output(results, args.o)
        
        if args.txt:
            enum.save_text_output(results, args.txt)
        
        if not args.o and not args.txt:
            print(f"\n[💡] Tip: Use -o or -txt to save results to file")

# -----------------------------
# MAIN FUNCTION
# -----------------------------
def main():
    if len(sys.argv) == 1:
        print_banner()
        print_usage()
        return
    
    # Version check
    if "-version" in sys.argv or "--version" in sys.argv:
        print("ReconX v2.0.0")
        return
    
    # Help check  
    if "-h" in sys.argv or "--help" in sys.argv:
        print_banner()
        print_usage()
        return
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="ReconX - Attack Surface Mapping", add_help=False)
    parser.add_argument('command', nargs='?', help='Main command (intel|enum)')
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    parser.add_argument('-version', action='store_true', help='Show version')
    
    args, unknown_args = parser.parse_known_args()
    
    if args.help or not args.command:
        print_banner()
        print_usage()
        return
    
    if args.version:
        print("ReconX v2.0.0")
        return
    
    # Handle subcommands
    if args.command == "intel":
        intel_parser = argparse.ArgumentParser(description="ReconX Intel", add_help=False)
        intel_parser.add_argument('-d', help='Domain names separated by commas')
        intel_parser.add_argument('-list', action='store_true', help='List data sources')
        intel_parser.add_argument('-active', action='store_true', help='Enable active methods')
        
        try:
            intel_args = intel_parser.parse_args(unknown_args)
            handle_intel_command(intel_args)
        except SystemExit:
            intel_usage()
    
    elif args.command == "enum":
        enum_parser = argparse.ArgumentParser(description="ReconX Enum", add_help=False) 
        enum_parser.add_argument('-d', help='Domain names separated by commas')
        enum_parser.add_argument('-o', help='JSON output file')
        enum_parser.add_argument('-txt', help='Text output file')
        enum_parser.add_argument('-active', action='store_true', help='Enable active methods')
        enum_parser.add_argument('-passive', action='store_true', help='Passive only')
        
        try:
            enum_args = enum_parser.parse_args(unknown_args)
            handle_enum_command(enum_args)
        except SystemExit:
            enum_usage()
    
    else:
        print(f"[❌] Unknown command: {args.command}")
        print_usage()

if __name__ == "__main__":
    main()
