#!/usr/bin/env python3
"""
ReconX Pro - Advanced Reconnaissance Tool
Complete CLI with Intel & Enum Commands
"""

import os
import sys
import argparse
import json
import requests
import dns.resolver
import socket
import threading
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
    print(f"📁 Version: v2.2.0")
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

# -----------------------------
# INTEL MODULE
# -----------------------------
class ReconIntel:
    def __init__(self):
        self.results = {}
    
    def domain_intel(self, domain, active=False):
        """Gather domain intelligence"""
        print(f"\n[🕵️] GATHERING INTELLIGENCE FOR: {domain}")
        print("-" * 50)
        
        intel_data = {
            "domain": domain,
            "whois": self._whois_lookup(domain),
            "dns": self._dns_intel(domain),
            "certificates": self._certificate_intel(domain),
            "subdomains": self._find_subdomains(domain),
            "status": "completed"
        }
        
        self._display_intel_results(intel_data)
        return intel_data
    
    def _whois_lookup(self, domain):
        """WHOIS information"""
        print("[1️⃣] WHOIS Lookup...")
        try:
            import whois
            domain_info = whois.whois(domain)
            return {
                "registrar": getattr(domain_info, 'registrar', 'Unknown'),
                "creation_date": str(getattr(domain_info, 'creation_date', 'Unknown')),
                "expiration_date": str(getattr(domain_info, 'expiration_date', 'Unknown'))
            }
        except:
            return {"error": "WHOIS lookup failed"}
    
    def _dns_intel(self, domain):
        """DNS intelligence"""
        print("[2️⃣] DNS Intelligence...")
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                dns_records[rtype] = [str(rdata) for rdata in answers]
            except:
                dns_records[rtype] = []
        
        return dns_records
    
    def _certificate_intel(self, domain):
        """Certificate transparency"""
        print("[3️⃣] Certificate Analysis...")
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                certificates = response.json()
                return {
                    "found": len(certificates),
                    "source": "crt.sh",
                    "sample": [cert.get('name_value', '') for cert in certificates[:3]]
                }
        except Exception as e:
            return {"error": str(e)}
        return {"found": 0}
    
    def _find_subdomains(self, domain):
        """Find subdomains"""
        print("[4️⃣] Subdomain Discovery...")
        subdomains = set()
        common_subs = ['www', 'api', 'mail', 'ftp', 'admin', 'test', 'blog', 'shop']
        
        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_subdomain, common_subs)
            for result in results:
                if result:
                    subdomains.add(result)
        
        return list(subdomains)
    
    def _display_intel_results(self, results):
        """Display intelligence results"""
        print(f"\n[📊] INTELLIGENCE RESULTS:")
        print(f"   Domain: {results['domain']}")
        
        if 'whois' in results:
            print(f"   Registrar: {results['whois'].get('registrar', 'Unknown')}")
        
        if 'dns' in results:
            dns_count = sum(len(records) for records in results['dns'].values())
            print(f"   DNS Records: {dns_count}")
        
        if 'certificates' in results:
            print(f"   Certificates: {results['certificates'].get('found', 0)} found")
        
        if 'subdomains' in results:
            print(f"   Subdomains: {len(results['subdomains'])} found")
            for subdomain in results['subdomains']:
                print(f"      ✅ {subdomain}")

# -----------------------------
# ENUM MODULE
# -----------------------------
class ReconEnum:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        self.common_subdomains = [
            'www', 'api', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'prod',
            'blog', 'shop', 'forum', 'support', 'help', 'docs', 'news', 'media',
            'cdn', 'static', 'app', 'apps', 'mobile', 'web', 'secure', 'portal'
        ]
    
    def comprehensive_enum(self, domain, active=True, passive=False, ports=False, **kwargs):
        """Comprehensive domain enumeration"""
        print(f"\n[🔍] ENUMERATING: {domain}")
        print("-" * 50)
        
        subdomains = set()
        live_subdomains = set()
        
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
        
        # Live host detection
        print("[3️⃣] Live Host Detection...")
        ips, live_hosts = self._resolve_and_check_subdomains(subdomains)
        live_subdomains.update(live_hosts)
        
        # Port scanning
        open_ports = {}
        if ports and live_subdomains:
            print("[4️⃣] Port Scanning...")
            open_ports = self._port_scanning(live_subdomains)
        
        results = {
            "domain": domain,
            "subdomains": list(subdomains),
            "live_subdomains": list(live_subdomains),
            "ips": ips,
            "open_ports": open_ports,
            "total_subdomains": len(subdomains),
            "total_live": len(live_subdomains),
            "status": "completed"
        }
        
        self._display_enum_results(results, ports)
        return results
    
    def _passive_enumeration(self, domain):
        """Passive subdomain discovery"""
        subdomains = set()
        
        # Certificate transparency
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            if domain in name and '*' not in name:
                                subdomains.add(name.strip())
        except:
            pass
        
        return subdomains
    
    def _active_enumeration(self, domain):
        """Active subdomain discovery"""
        subdomains = set()
        
        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_subdomain, self.common_subdomains)
            for result in results:
                if result:
                    subdomains.add(result)
        
        return subdomains
    
    def _resolve_and_check_subdomains(self, subdomains):
        """Resolve subdomains and check live hosts"""
        ips = {}
        live_hosts = set()
        
        def check_subdomain(subdomain):
            try:
                # DNS resolution
                answers = dns.resolver.resolve(subdomain, 'A')
                ip_list = [str(rdata) for rdata in answers]
                
                # HTTP check
                try:
                    response = requests.get(f"http://{subdomain}", timeout=3, verify=False)
                    if response.status_code < 400:
                        live_hosts.add(subdomain)
                except:
                    try:
                        response = requests.get(f"https://{subdomain}", timeout=3, verify=False)
                        if response.status_code < 400:
                            live_hosts.add(subdomain)
                    except:
                        pass
                
                return subdomain, ip_list
            except:
                return subdomain, []
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            results = executor.map(check_subdomain, subdomains)
            for subdomain, ip_list in results:
                if ip_list:
                    ips[subdomain] = ip_list
        
        return ips, live_hosts
    
    def _port_scanning(self, subdomains):
        """Port scanning for live hosts"""
        open_ports = {}
        
        def scan_ports(host):
            host_ports = []
            for port in self.common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        host_ports.append(port)
                    sock.close()
                except:
                    pass
            return host, host_ports
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(scan_ports, subdomains)
            for host, ports in results:
                if ports:
                    open_ports[host] = ports
        
        return open_ports
    
    def _display_enum_results(self, results, ports_enabled):
        """Display enumeration results"""
        print(f"\n[📊] ENUMERATION RESULTS:")
        print(f"   Domain: {results['domain']}")
        print(f"   Total Subdomains: {results['total_subdomains']}")
        print(f"   Live Subdomains: {results['total_live']}")
        
        if ports_enabled:
            total_ports = sum(len(ports) for ports in results['open_ports'].values())
            print(f"   Open Ports: {total_ports}")
        
        print(f"\n[🌐] LIVE SUBDOMAINS:")
        for subdomain in sorted(results['live_subdomains'])[:15]:
            ips = results['ips'].get(subdomain, [])
            print(f"   ✅ {subdomain} -> {', '.join(ips)}")
        
        if ports_enabled and results['open_ports']:
            print(f"\n[🔓] OPEN PORTS:")
            for host, ports in list(results['open_ports'].items())[:10]:
                print(f"   🔓 {host}: {', '.join(map(str, ports))}")
    
    def save_json_output(self, results, filename):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[💾] JSON results saved to: {filename}")
    
    def save_text_output(self, results, filename):
        """Save results to text file"""
        with open(filename, 'w') as f:
            f.write(f"ReconX Results for {results['domain']}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Total Subdomains: {results['total_subdomains']}\n")
            f.write(f"Live Subdomains: {results['total_live']}\n\n")
            
            f.write("SUBdomains:\n")
            for subdomain in sorted(results['subdomains']):
                f.write(f"  {subdomain}\n")
            
            f.write("\nLIVE HOSTS:\n")
            for subdomain in sorted(results['live_subdomains']):
                ips = results['ips'].get(subdomain, [])
                f.write(f"  {subdomain} -> {', '.join(ips)}\n")
            
            if results['open_ports']:
                f.write("\nOPEN PORTS:\n")
                for host, ports in results['open_ports'].items():
                    f.write(f"  {host}: {', '.join(map(str, ports))}\n")
        
        print(f"\n[💾] Text results saved to: {filename}")

# -----------------------------
# COMMAND LINE INTERFACE
# -----------------------------
def main():
    if len(sys.argv) == 1:
        print_banner()
        print_usage()
        return
    
    # Handle global options
    if "-version" in sys.argv or "--version" in sys.argv:
        print("ReconX v2.2.0")
        return
    
    if "-h" in sys.argv or "--help" in sys.argv:
        print_banner()
        print_usage()
        return
    
    # Parse main command
    parser = argparse.ArgumentParser(description="ReconX - Attack Surface Mapping", add_help=False)
    parser.add_argument('command', nargs='?', help='Main command (intel|enum)')
    
    args, unknown_args = parser.parse_known_args()
    
    if not args.command:
        print_banner()
        print_usage()
        return
    
    # Handle subcommands
    if args.command == "intel":
        handle_intel_command(unknown_args)
    elif args.command == "enum":
        handle_enum_command(unknown_args)
    else:
        print(f"[❌] Unknown command: {args.command}")
        print_usage()

def handle_intel_command(unknown_args):
    """Handle intel subcommand"""
    parser = argparse.ArgumentParser(description="ReconX Intel", add_help=False)
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-active', action='store_true', help='Enable active methods')
    
    try:
        args = parser.parse_args(unknown_args)
        print_banner()
        
        intel = ReconIntel()
        results = intel.domain_intel(args.domain, active=args.active)
        
        print(f"\n[✅] Intelligence gathering completed for {args.domain}")
        
    except SystemExit:
        print_intel_usage()

def handle_enum_command(unknown_args):
    """Handle enum subcommand"""
    parser = argparse.ArgumentParser(description="ReconX Enum", add_help=False)
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-active', action='store_true', help='Enable active methods')
    parser.add_argument('-passive', action='store_true', help='Passive only')
    parser.add_argument('-ports', action='store_true', help='Enable port scanning')
    parser.add_argument('-o', help='JSON output file')
    parser.add_argument('-txt', help='Text output file')
    
    try:
        args = parser.parse_args(unknown_args)
        print_banner()
        
        enum = ReconEnum()
        results = enum.comprehensive_enum(
            domain=args.domain,
            active=args.active,
            passive=args.passive,
            ports=args.ports
        )
        
        # Save outputs if specified
        if args.o:
            enum.save_json_output(results, args.o)
        
        if args.txt:
            enum.save_text_output(results, args.txt)
        
        if not args.o and not args.txt:
            print(f"\n[💡] Tip: Use -o or -txt to save results to file")
        
    except SystemExit:
        print_enum_usage()

def print_usage():
    """Print main usage"""
    usage = """
Usage: reconx intel|enum [options]

  -h, --help     Show the program usage message
  -version       Print the version number

Subcommands:

    reconx intel - Discover targets for enumerations  
    reconx enum  - Perform enumerations and network mapping

Examples:
  reconx intel -d example.com
  reconx enum -d example.com
  reconx enum -d example.com -ports -txt results.txt
  reconx enum -d example.com -active -ports -o results.json
"""
    print(usage)

def print_intel_usage():
    """Print intel usage"""
    usage = """
Usage: reconx intel [options]

OPTIONS:
  -d, --domain  Target domain (required)
  -active       Enable active reconnaissance

Examples:
  reconx intel -d example.com
  reconx intel -d example.com -active
"""
    print(usage)

def print_enum_usage():
    """Print enum usage"""
    usage = """
Usage: reconx enum [options]

OPTIONS:
  -d, --domain  Target domain (required)
  -active       Enable active methods
  -passive      Passive reconnaissance only  
  -ports        Enable port scanning
  -o            JSON output file
  -txt          Text output file

Examples:
  reconx enum -d example.com
  reconx enum -d example.com -ports -txt results.txt
  reconx enum -d example.com -active -ports -o results.json
"""
    print(usage)

if __name__ == "__main__":
    main()
