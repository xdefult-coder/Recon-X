#!/usr/bin/env python3
"""
ReconX Pro - Advanced Reconnaissance Tool
With Port Scanning & Better Results
"""

import os
import sys
import argparse
import subprocess
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
    print(f"📁 Version: v2.1.0 (With Port Scanning)")
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

# -----------------------------
# ADVANCED ENUMERATION WITH PORT SCANNING
# -----------------------------
class ReconEnum:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 
                           1433, 3306, 3389, 5432, 5900, 8080, 8443, 9000]
        self.common_subdomains = [
            'www', 'api', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'prod', 'backup', 'cdn', 'static', 'app', 'apps', 'blog', 'shop',
            'forum', 'support', 'help', 'docs', 'news', 'media', 'email',
            'webmail', 'smtp', 'pop', 'imap', 'portal', 'login', 'signin',
            'dashboard', 'adminpanel', 'cpanel', 'whm', 'webdisk', 'ns1',
            'ns2', 'dns', 'vpn', 'remote', 'ssh', 'ftp', 'file', 'files',
            'download', 'upload', 'image', 'images', 'img', 'video', 'videos',
            'music', 'audio', 'storage', 'db', 'database', 'sql', 'mysql',
            'oracle', 'postgres', 'mongodb', 'redis', 'elasticsearch', 'kibana',
            'grafana', 'prometheus', 'jenkins', 'git', 'svn', 'svn', 'bitbucket',
            'jira', 'confluence', 'wiki', 'sharepoint', 'exchange', 'owa',
            'lync', 'teams', 'skype', 'zoom', 'meet', 'webex', 'gotomeeting',
            'calendar', 'contacts', 'address', 'directory', 'search', 'find',
            'query', 'api', 'api1', 'api2', 'api3', 'rest', 'soap', 'graphql',
            'mobile', 'm', 'wap', 'android', 'ios', 'iphone', 'ipad', 'tablet',
            'desktop', 'pc', 'mac', 'linux', 'windows', 'live', 'stream',
            'broadcast', 'tv', 'radio', 'chat', 'message', 'messaging',
            'im', 'xmpp', 'webrtc', 'stun', 'turn', 'signal', 'telegram',
            'whatsapp', 'viber', 'line', 'kakao', 'wechat', 'qq', 'bbs',
            'forum', 'board', 'community', 'social', 'facebook', 'twitter',
            'instagram', 'linkedin', 'youtube', 'vimeo', 'dailymotion',
            'twitch', 'mixer', 'dlive', 'periscope', 'snapchat', 'tiktok',
            'pinterest', 'tumblr', 'reddit', 'quora', 'medium', 'blogger',
            'wordpress', 'joomla', 'drupal', 'magento', 'prestashop',
            'opencart', 'woocommerce', 'shopify', 'bigcommerce', 'squarespace',
            'wix', 'weebly', 'godaddy', 'namecheap', 'hostgator', 'bluehost',
            'siteground', 'cloudflare', 'akamai', 'fastly', 'incapsula',
            'imperva', 'sucuri', 'wordfence', 'cloudfront', 'azureedge',
            'googleusercontent', 'aws', 'azure', 'gcp', 'ibm', 'oraclecloud',
            'alibaba', 'digitalocean', 'linode', 'vultr', 'heroku', 'netlify',
            'vercel', 'firebase', 'amplify', 's3', 'storage', 'bucket',
            'container', 'registry', 'repository', 'docker', 'kubernetes',
            'openshift', 'rancher', 'mesos', 'nomad', 'consul', 'etcd',
            'zookeeper', 'kafka', 'rabbitmq', 'activemq', 'zeromq', 'nats',
            'redis', 'memcached', 'cassandra', 'couchbase', 'couchdb',
            'riak', 'neo4j', 'arangodb', 'orientdb', 'janusgraph', 'titan',
            'dynamodb', 'cosmosdb', 'firestore', 'bigtable', 'spanner',
            'aurora', 'rds', 'documentdb', 'elasticache', 'memorydb',
            'keyspaces', 'qldb', 'timestream', 'ledger', 'blockchain',
            'ethereum', 'bitcoin', 'litecoin', 'monero', 'ripple', 'cardano',
            'polkadot', 'cosmos', 'binance', 'coinbase', 'kraken', 'gemini',
            'bitfinex', 'bittrex', 'poloniex', 'huobi', 'okex', 'kucoin',
            'ftx', 'bybit', 'deribit', 'bitmex', 'phemex', 'gateio', 'mexc',
            'whitebit', 'probit', 'latoken', 'hotbit', 'bibox', 'coinEx'
        ]
    
    def comprehensive_enum(self, domain, active=True, passive=False, port_scan=False, **kwargs):
        """Comprehensive domain enumeration with port scanning"""
        print(f"\n[🔍] ENUMERATING: {domain}")
        print("-" * 50)
        
        subdomains = set()
        live_subdomains = set()
        
        # Passive enumeration
        if passive or active:
            print("[1️⃣] Passive Enumeration...")
            passive_subs = self._passive_enumeration(domain)
            subdomains.update(passive_subs)
        
        # Active enumeration with larger wordlist
        if active:
            print("[2️⃣] Active Enumeration...")
            active_subs = self._active_enumeration(domain)
            subdomains.update(active_subs)
        
        # DNS resolution and live host detection
        print("[3️⃣] DNS Resolution & Live Host Detection...")
        ips, live_hosts = self._resolve_and_check_subdomains(subdomains)
        live_subdomains.update(live_hosts)
        
        # Port scanning if requested
        open_ports = {}
        if port_scan and live_subdomains:
            print("[4️⃣] Port Scanning...")
            open_ports = self._port_scanning(live_subdomains)
        
        return {
            "domain": domain,
            "subdomains": list(subdomains),
            "live_subdomains": list(live_subdomains),
            "ips": ips,
            "open_ports": open_ports,
            "total_subdomains": len(subdomains),
            "total_live": len(live_subdomains),
            "status": "completed"
        }
    
    def _passive_enumeration(self, domain):
        """Passive subdomain discovery from multiple sources"""
        subdomains = set()
        
        # Certificate transparency
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            if domain in name and '*' not in name:
                                subdomains.add(name.strip())
                print(f"    ✅ CRT.sh: {len(data)} certificates found")
        except Exception as e:
            print(f"    ❌ CRT.sh failed: {e}")
        
        # Additional passive sources can be added here
        # Hackertarget, SecurityTrails, etc.
        
        return subdomains
    
    def _active_enumeration(self, domain):
        """Active subdomain discovery with large wordlist"""
        subdomains = set()
        
        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                return None
        
        print(f"    🔄 Checking {len(self.common_subdomains)} common subdomains...")
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(check_subdomain, self.common_subdomains)
            for result in results:
                if result:
                    subdomains.add(result)
        
        return subdomains
    
    def _resolve_and_check_subdomains(self, subdomains):
        """Resolve subdomains and check if they're live"""
        ips = {}
        live_hosts = set()
        
        def check_subdomain(subdomain):
            try:
                # DNS resolution
                answers = dns.resolver.resolve(subdomain, 'A')
                ip_list = [str(rdata) for rdata in answers]
                
                # HTTP check for live hosts
                for ip in ip_list:
                    try:
                        response = requests.get(f"http://{subdomain}", timeout=5, verify=False)
                        if response.status_code < 400:
                            live_hosts.add(subdomain)
                            break
                    except:
                        try:
                            response = requests.get(f"https://{subdomain}", timeout=5, verify=False)
                            if response.status_code < 400:
                                live_hosts.add(subdomain)
                                break
                        except:
                            pass
                
                return subdomain, ip_list
            except:
                return subdomain, []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_subdomain, subdomains)
            for subdomain, ip_list in results:
                if ip_list:
                    ips[subdomain] = ip_list
        
        return ips, live_hosts
    
    def _port_scanning(self, subdomains):
        """Port scanning for discovered subdomains"""
        open_ports = {}
        
        def scan_ports(host):
            host_ports = []
            for port in self.common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        host_ports.append(port)
                    sock.close()
                except:
                    pass
            return host, host_ports
        
        print(f"    🔄 Scanning {len(subdomains)} live hosts...")
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(scan_ports, subdomains)
            for host, ports in results:
                if ports:
                    open_ports[host] = ports
        
        return open_ports
    
    def save_json_output(self, results, filename):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[💾] JSON results saved to: {filename}")
    
    def save_text_output(self, results, filename):
        """Save results to text file"""
        with open(filename, 'w') as f:
            f.write(f"ReconX Advanced Results for {results['domain']}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Total Subdomains Found: {results['total_subdomains']}\n")
            f.write(f"Live Subdomains: {results['total_live']}\n")
            f.write(f"Port Scanning: {'Yes' if results['open_ports'] else 'No'}\n\n")
            
            f.write("ALL SUBDOMAINS:\n")
            f.write("-" * 40 + "\n")
            for subdomain in sorted(results['subdomains']):
                f.write(f"  ✅ {subdomain}\n")
            
            f.write("\nLIVE SUBDOMAINS:\n")
            f.write("-" * 40 + "\n")
            for subdomain in sorted(results['live_subdomains']):
                ips = results['ips'].get(subdomain, [])
                f.write(f"  🌐 {subdomain} -> {', '.join(ips)}\n")
            
            if results['open_ports']:
                f.write("\nOPEN PORTS:\n")
                f.write("-" * 40 + "\n")
                for host, ports in results['open_ports'].items():
                    f.write(f"  🔓 {host}: {', '.join(map(str, ports))}\n")
        
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
  reconx enum -d example.com
  reconx enum -d example.com -ports -txt results.txt
  reconx enum -d example.com -active -ports -o results.json
"""
    print(usage)

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
   -ports      Enable port scanning (NEW!)

Example:
   reconx enum -d facebook.com -txt results.txt
   reconx enum -d facebook.com -ports -active
   reconx enum -d facebook.com -o results.json -ports -active
""")

# -----------------------------
# COMMAND HANDLERS
# -----------------------------
def handle_enum_command(args):
    """Handle enum subcommand with port scanning"""
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
            passive=args.passive,
            port_scan=args.ports  # New port scan option
        )
        
        # Display results
        print(f"\n[📊] ENUMERATION RESULTS:")
        print(f"   Domain: {results['domain']}")
        print(f"   Total Subdomains: {results['total_subdomains']}")
        print(f"   Live Subdomains: {results['total_live']}")
        
        if args.ports:
            print(f"   Open Ports Found: {sum(len(ports) for ports in results['open_ports'].values())}")
        
        print(f"\n[🌐] LIVE SUBDOMAINS ({results['total_live']}):")
        for subdomain in sorted(results['live_subdomains'])[:20]:  # Show first 20
            ips = results['ips'].get(subdomain, [])
            print(f"   🌐 {subdomain} -> {', '.join(ips)}")
        
        if len(results['live_subdomains']) > 20:
            print(f"   ... and {len(results['live_subdomains']) - 20} more")
        
        # Show open ports if port scanning was done
        if args.ports and results['open_ports']:
            print(f"\n[🔓] OPEN PORTS:")
            for host, ports in list(results['open_ports'].items())[:10]:  # Show first 10
                print(f"   🔓 {host}: {', '.join(map(str, ports))}")
        
        # Save outputs
        if args.o:
            enum.save_json_output(results, args.o)
        
        if args.txt:
            enum.save_text_output(results, args.txt)
        
        if not args.o and not args.txt:
            print(f"\n[💡] Tip: Use -o or -txt to save complete results to file")

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
        print("ReconX v2.1.0 (With Port Scanning)")
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
        print("ReconX v2.1.0 (With Port Scanning)")
        return
    
    # Handle enum subcommand (simplified for now)
    if args.command == "enum":
        enum_parser = argparse.ArgumentParser(description="ReconX Enum", add_help=False) 
        enum_parser.add_argument('-d', help='Domain names separated by commas')
        enum_parser.add_argument('-o', help='JSON output file')
        enum_parser.add_argument('-txt', help='Text output file')
        enum_parser.add_argument('-active', action='store_true', help='Enable active methods')
        enum_parser.add_argument('-passive', action='store_true', help='Passive only')
        enum_parser.add_argument('-ports', action='store_true', help='Enable port scanning')  # NEW OPTION
        
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
