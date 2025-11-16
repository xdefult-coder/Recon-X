#!/usr/bin/env python3
"""
ReconX Pro - 1000+ Subdomains Finder
Kisi bhi domain ke liye complete subdomain discovery
"""

import os
import sys
import argparse
import json
import requests
import dns.resolver
import socket
import threading
import random
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# -----------------------------
# MASSIVE SUBDOMAINS WORDLIST (1000+)
# -----------------------------
MASSIVE_SUBDOMAINS = [
    # Common & Basic (50)
    'www', 'api', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'prod',
    'blog', 'shop', 'forum', 'support', 'help', 'docs', 'news', 'media',
    'cdn', 'static', 'app', 'apps', 'mobile', 'web', 'secure', 'portal',
    'login', 'signin', 'dashboard', 'account', 'user', 'users', 'profile',
    'search', 'find', 'query', 'results', 'data', 'database', 'db', 'sql',
    'backup', 'archive', 'old', 'new', 'temp', 'tmp', 'demo', 'sample', 'example',

    # Services & Protocols (50)
    'smtp', 'pop', 'pop3', 'imap', 'imap4', 'webmail', 'email', 'mail2',
    'ssh', 'vpn', 'remote', 'ftp2', 'ftps', 'sftp', 'rsync', 'ldap', 'ldaps',
    'proxy', 'firewall', 'router', 'switch', 'gateway', 'portal', 'console',
    'terminal', 'shell', 'cmd', 'command', 'exec', 'run', 'service', 'services',
    'svc', 'daemon', 'server', 'client', 'host', 'node', 'cluster', 'loadbalancer',
    'lb', 'balancer', 'cache', 'caching', 'cdn2', 'cdn3', 'edge', 'edges', 'origin',

    # Development & Staging (50)
    'dev1', 'dev2', 'dev3', 'dev4', 'dev5', 'dev6', 'dev7', 'dev8', 'dev9', 'dev10',
    'staging1', 'staging2', 'staging3', 'staging4', 'staging5', 'staging6', 'staging7',
    'stage', 'stage1', 'stage2', 'stage3', 'preprod', 'pre-prod', 'preproduction',
    'qa', 'qa1', 'qa2', 'qa3', 'test1', 'test2', 'test3', 'test4', 'test5',
    'testing', 'testing1', 'testing2', 'uat', 'uat1', 'uat2', 'demo1', 'demo2',
    'sandbox', 'playground', 'experiment', 'experimental', 'lab', 'labs', 'research',

    # Infrastructure & Cloud (100)
    'aws', 'azure', 'gcp', 'cloud', 'cloudfront', 's3', 'ec2', 'lambda', 'azureedge',
    'googleusercontent', 'digitalocean', 'linode', 'vultr', 'heroku', 'netlify',
    'vercel', 'firebase', 'amplify', 'storage', 'bucket', 'container', 'registry',
    'docker', 'kubernetes', 'k8s', 'openshift', 'rancher', 'mesos', 'nomad',
    'consul', 'etcd', 'zookeeper', 'kafka', 'rabbitmq', 'activemq', 'zeromq',
    'nats', 'redis', 'memcached', 'cassandra', 'couchbase', 'couchdb', 'riak',
    'neo4j', 'arangodb', 'orientdb', 'mongodb', 'mysql', 'postgres', 'mariadb',
    'oracle', 'sqlserver', 'db2', 'sybase', 'informix', 'teradata', 'vertica',
    'hadoop', 'hbase', 'hive', 'pig', 'spark', 'storm', 'flink', 'beam',
    'elasticsearch', 'logstash', 'kibana', 'grafana', 'prometheus', 'alertmanager',
    'thanos', 'cortex', 'loki', 'jaeger', 'zipkin', 'pinpoint', 'skywalking',
    'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'bamboo',
    'teamcity', 'circleci', 'travis', 'codeship', 'buddy', 'drone', 'argo',

    # Applications & Products (100)
    'wordpress', 'joomla', 'drupal', 'magento', 'prestashop', 'opencart',
    'woocommerce', 'shopify', 'bigcommerce', 'squarespace', 'wix', 'weebly',
    'sharepoint', 'exchange', 'owa', 'lync', 'teams', 'skype', 'zoom', 'meet',
    'webex', 'gotomeeting', 'slack', 'discord', 'telegram', 'whatsapp', 'viber',
    'signal', 'line', 'kakao', 'wechat', 'qq', 'vimeo', 'dailymotion', 'twitch',
    'mixer', 'dlive', 'periscope', 'snapchat', 'tiktok', 'pinterest', 'tumblr',
    'reddit', 'quora', 'medium', 'blogger', 'ghost', 'substack', 'medium',
    'linkedin', 'twitter', 'instagram', 'youtube', 'facebook', 'messenger',
    'whatsapp', 'telegram', 'discord', 'slack', 'teams', 'zoom', 'webex',
    'gotomeeting', 'skype', 'hangouts', 'duo', 'meet', 'jitsi', 'bigbluebutton',
    'moodle', 'blackboard', 'canvas', 'schoology', 'edmodo', 'googleclassroom',
    'office365', 'gsuite', 'gsuite2', 'workspace', 'dropbox', 'box', 'onedrive',
    'icloud', 'mega', 'mediafire', 'sendspace', 'wetransfer', 'fileserver',

    # Security & Monitoring (50)
    'security', 'secure', 'auth', 'authentication', 'authorization', 'oauth',
    'sso', 'cas', 'saml', 'openid', 'ldap', 'kerberos', 'radius', 'tacacs',
    'firewall', 'waf', 'ips', 'ids', 'siem', 'soc', 'noc', 'monitoring',
    'monitor', 'nagios', 'zabbix', 'icinga', 'observium', 'librenms', 'cacti',
    'prtg', 'solarwinds', 'datadog', 'newrelic', 'appdynamics', 'dynatrace',
    'splunk', 'elastic', 'loggly', 'papertrail', 'sumologic', 'graylog',
    'sentry', 'rollbar', 'bugsnag', 'airbrake', 'honeybadger', 'raygun',

    # Network & Infrastructure (100)
    'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'dns1', 'dns2', 'dns3', 'dns4', 'dns5',
    'router1', 'router2', 'switch1', 'switch2', 'firewall1', 'firewall2',
    'loadbalancer1', 'loadbalancer2', 'proxy1', 'proxy2', 'cache1', 'cache2',
    'cdn1', 'cdn2', 'cdn3', 'edge1', 'edge2', 'edge3', 'origin1', 'origin2',
    'server1', 'server2', 'server3', 'server4', 'server5', 'server6', 'server7',
    'server8', 'server9', 'server10', 'host1', 'host2', 'host3', 'host4', 'host5',
    'node1', 'node2', 'node3', 'node4', 'node5', 'cluster1', 'cluster2', 'cluster3',
    'dc1', 'dc2', 'dc3', 'idc1', 'idc2', 'idc3', 'rack1', 'rack2', 'rack3',
    'vm1', 'vm2', 'vm3', 'vm4', 'vm5', 'container1', 'container2', 'container3',
    'pod1', 'pod2', 'pod3', 'service1', 'service2', 'service3', 'deployment1',
    'deployment2', 'deployment3', 'statefulset1', 'statefulset2', 'daemonset1',

    # Geographic & Regional (100)
    'us', 'usa', 'uk', 'gb', 'eu', 'europe', 'asia', 'apac', 'emea', 'na', 'sa',
    'africa', 'australia', 'canada', 'germany', 'france', 'italy', 'spain',
    'japan', 'china', 'india', 'brazil', 'mexico', 'russia', 'korea', 'singapore',
    'hongkong', 'taiwan', 'dubai', 'uae', 'saudi', 'qatar', 'kuwait', 'bahrain',
    'oman', 'egypt', 'southafrica', 'nigeria', 'kenya', 'ghana', 'morocco',
    'turkey', 'israel', 'iran', 'pakistan', 'bangladesh', 'srilanka', 'vietnam',
    'thailand', 'malaysia', 'indonesia', 'philippines', 'newzealand', 'australia',
    'sydney', 'melbourne', 'brisbane', 'perth', 'adelaide', 'auckland', 'wellington',
    'london', 'paris', 'berlin', 'frankfurt', 'amsterdam', 'brussels', 'zurich',
    'milan', 'rome', 'madrid', 'barcelona', 'stockholm', 'oslo', 'copenhagen',
    'helsinki', 'warsaw', 'prague', 'vienna', 'budapest', 'bucharest', 'sofia',
    'athens', 'istanbul', 'moscow', 'stpetersburg', 'beijing', 'shanghai',
    'guangzhou', 'shenzhen', 'tokyo', 'osaka', 'nagoya', 'seoul', 'busan',
    'delhi', 'mumbai', 'bangalore', 'chennai', 'kolkata', 'hyderabad', 'pune',

    # Numbers & Combinations (200)
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
    '01', '02', '03', '04', '05', '06', '07', '08', '09', '010',
    '11', '12', '13', '14', '15', '16', '17', '18', '19', '20',
    '21', '22', '23', '24', '25', '26', '27', '28', '29', '30',
    '31', '32', '33', '34', '35', '36', '37', '38', '39', '40',
    '41', '42', '43', '44', '45', '46', '47', '48', '49', '50',
    '100', '200', '300', '400', '500', '600', '700', '800', '900', '1000',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta',
    'iota', 'kappa', 'lambda', 'mu', 'nu', 'xi', 'omicron', 'pi', 'rho',
    'sigma', 'tau', 'upsilon', 'phi', 'chi', 'psi', 'omega',
    'primary', 'secondary', 'tertiary', 'quaternary', 'quinary',
    'senary', 'septenary', 'octonary', 'nonary', 'denary',

    # Technology Specific (100)
    'java', 'python', 'ruby', 'php', 'node', 'nodejs', 'go', 'golang',
    'rust', 'scala', 'kotlin', 'swift', 'objectivec', 'csharp', 'fsharp',
    'dotnet', 'aspnet', 'laravel', 'django', 'flask', 'rails', 'spring',
    'express', 'koa', 'hapi', 'fastapi', 'graphql', 'rest', 'soap',
    'grpc', 'thrift', 'avro', 'protobuf', 'json', 'xml', 'yaml', 'toml',
    'html', 'css', 'javascript', 'typescript', 'coffeescript', 'clojure',
    'elixir', 'erlang', 'haskell', 'ocaml', 'perl', 'r', 'matlab',
    'tensorflow', 'pytorch', 'keras', 'scikit', 'numpy', 'pandas',
    'matplotlib', 'seaborn', 'plotly', 'd3', 'threejs', 'react', 'vue',
    'angular', 'svelte', 'ember', 'backbone', 'jquery', 'bootstrap',
    'tailwind', 'bulma', 'foundation', 'semanticui', 'materialize',

    # Business & Departments (100)
    'hr', 'humanresources', 'payroll', 'benefits', 'recruiting', 'talent',
    'careers', 'jobs', 'resume', 'application', 'interview', 'onboarding',
    'finance', 'accounting', 'billing', 'invoice', 'payment', 'payments',
    'revenue', 'expense', 'budget', 'forecast', 'tax', 'audit', 'compliance',
    'legal', 'law', 'contract', 'agreement', 'policy', 'policies', 'regulation',
    'sales', 'marketing', 'advertising', 'promotion', 'campaign', 'lead',
    'customer', 'client', 'partner', 'vendor', 'supplier', 'distributor',
    'reseller', 'dealer', 'agent', 'broker', 'merchant', 'retail', 'wholesale',
    'operations', 'production', 'manufacturing', 'factory', 'plant', 'warehouse',
    'logistics', 'supplychain', 'inventory', 'stock', 'order', 'shipping',
    'delivery', 'transport', 'fleet', 'maintenance', 'repair', 'service',
    'quality', 'qc', 'qa', 'testing', 'inspection', 'certification',
    'research', 'development', 'rnd', 'innovation', 'labs', 'studio',
    'design', 'creative', 'art', 'photo', 'video', 'audio', 'media',
    'content', 'publishing', 'editorial', 'newsroom', 'press', 'pr',

    # Additional Common (150)
    'access', 'activity', 'analytics', 'assets', 'attachment', 'back',
    'backup01', 'backup02', 'backup03', 'backup04', 'backup05', 'backup06',
    'backup07', 'backup08', 'backup09', 'backup10', 'backup11', 'backup12',
    'backup13', 'backup14', 'backup15', 'backup16', 'backup17', 'backup18',
    'backup19', 'backup20', 'backup21', 'backup22', 'backup23', 'backup24',
    'backup25', 'backup26', 'backup27', 'backup28', 'backup29', 'backup30',
    'backup31', 'backup32', 'backup33', 'backup34', 'backup35', 'backup36',
    'backup37', 'backup38', 'backup39', 'backup40', 'backup41', 'backup42',
    'backup43', 'backup44', 'backup45', 'backup46', 'backup47', 'backup48',
    'backup49', 'backup50', 'backup51', 'backup52', 'backup53', 'backup54',
    'backup55', 'backup56', 'backup57', 'backup58', 'backup59', 'backup60',
    'backup61', 'backup62', 'backup63', 'backup64', 'backup65', 'backup66',
    'backup67', 'backup68', 'backup69', 'backup70', 'backup71', 'backup72',
    'backup73', 'backup74', 'backup75', 'backup76', 'backup77', 'backup78',
    'backup79', 'backup80', 'backup81', 'backup82', 'backup83', 'backup84',
    'backup85', 'backup86', 'backup87', 'backup88', 'backup89', 'backup90',
    'backup91', 'backup92', 'backup93', 'backup94', 'backup95', 'backup96',
    'backup97', 'backup98', 'backup99', 'backup100', 'backup-01', 'backup-02',
    'backup-03', 'backup-04', 'backup-05', 'backup-06', 'backup-07', 'backup-08',
    'backup-09', 'backup-10', 'backup-11', 'backup-12', 'backup-13', 'backup-14',
    'backup-15', 'backup-16', 'backup-17', 'backup-18', 'backup-19', 'backup-20'
]

# -----------------------------
# ADVANCED RECON ENGINE
# -----------------------------
class AdvancedRecon:
    def __init__(self):
        self.results = {}
        self.found_subdomains = set()
        self.all_checked_subdomains = set()  # Error wale bhi include
    
    def massive_enumeration(self, domain, active=True, ports=False, output_file=None):
        """Massive enumeration with 1000+ subdomains"""
        print(f"\n[🎯] STARTING MASSIVE ENUMERATION FOR: {domain}")
        print(f"[📊] Testing {len(MASSIVE_SUBDOMAINS)}+ subdomains...")
        print("-" * 60)
        
        # Phase 1: DNS Resolution (All subdomains)
        print("[1️⃣] PHASE 1: DNS Resolution (1000+ Subdomains)...")
        dns_results = self._massive_dns_scan(domain)
        
        # Phase 2: Live Host Detection
        print("[2️⃣] PHASE 2: Live Host Detection...")
        live_results = self._live_host_detection(dns_results)
        
        # Phase 3: Port Scanning
        open_ports = {}
        if ports and live_results['live_subdomains']:
            print("[3️⃣] PHASE 3: Port Scanning...")
            open_ports = self._port_scanning(live_results['live_subdomains'])
        
        # Compile final results
        final_results = {
            "domain": domain,
            "all_checked_subdomains": list(self.all_checked_subdomains),
            "dns_resolved_subdomains": dns_results['resolved'],
            "live_subdomains": live_results['live_subdomains'],
            "ips": live_results['ips'],
            "open_ports": open_ports,
            "stats": {
                "total_checked": len(self.all_checked_subdomains),
                "dns_resolved": len(dns_results['resolved']),
                "live_hosts": len(live_results['live_subdomains']),
                "open_ports": sum(len(ports) for ports in open_ports.values())
            }
        }
        
        self._display_massive_results(final_results)
        
        # Save results
        if output_file:
            self._save_massive_results(final_results, output_file)
        
        return final_results
    
    def _massive_dns_scan(self, domain):
        """Massive DNS scanning with 1000+ subdomains"""
        resolved_subdomains = set()
        all_checked = set()
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            all_checked.add(full_domain)
            
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                ips = [str(rdata) for rdata in answers]
                return full_domain, ips, "RESOLVED"
            except dns.resolver.NXDOMAIN:
                return full_domain, [], "NXDOMAIN"
            except dns.resolver.NoAnswer:
                return full_domain, [], "NO_ANSWER"
            except dns.resolver.Timeout:
                return full_domain, [], "TIMEOUT"
            except Exception as e:
                return full_domain, [], f"ERROR: {str(e)}"
        
        # Process in batches to avoid overwhelming
        batch_size = 100
        total_batches = (len(MASSIVE_SUBDOMAINS) + batch_size - 1) // batch_size
        
        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min((batch_num + 1) * batch_size, len(MASSIVE_SUBDOMAINS))
            batch = MASSIVE_SUBDOMAINS[start_idx:end_idx]
            
            print(f"    🔄 Batch {batch_num + 1}/{total_batches} ({len(batch)} subdomains)...")
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                results = list(executor.map(check_subdomain, batch))
            
            for subdomain, ips, status in results:
                if ips:  # Only add if DNS resolved
                    resolved_subdomains.add(subdomain)
                    self.found_subdomains.add(subdomain)
                
                # Track all checked subdomains (including errors)
                self.all_checked_subdomains.add(subdomain)
        
        return {
            "resolved": list(resolved_subdomains),
            "total_checked": len(all_checked)
        }
    
    def _live_host_detection(self, dns_results):
        """Detect live hosts from resolved subdomains"""
        live_subdomains = set()
        ips_mapping = {}
        
        def check_live_host(subdomain):
            try:
                # Try HTTP
                response = requests.get(f"http://{subdomain}", timeout=3, verify=False)
                if response.status_code < 400:
                    return subdomain, "HTTP", response.status_code
            except:
                try:
                    # Try HTTPS
                    response = requests.get(f"https://{subdomain}", timeout=3, verify=False)
                    if response.status_code < 400:
                        return subdomain, "HTTPS", response.status_code
                except:
                    pass
            return subdomain, "DEAD", 0
        
        print(f"    🔄 Checking {len(dns_results['resolved'])} resolved subdomains...")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(check_live_host, dns_results['resolved']))
        
        for subdomain, protocol, status_code in results:
            if protocol != "DEAD":
                live_subdomains.add(subdomain)
                
                # Get IPs for live hosts
                try:
                    answers = dns.resolver.resolve(subdomain, 'A')
                    ips_mapping[subdomain] = [str(rdata) for rdata in answers]
                except:
                    ips_mapping[subdomain] = []
        
        return {
            "live_subdomains": list(live_subdomains),
            "ips": ips_mapping
        }
    
    def _port_scanning(self, subdomains):
        """Port scanning for live hosts"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        open_ports = {}
        
        def scan_host_ports(host):
            host_ports = []
            for port in common_ports:
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
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            results = list(executor.map(scan_host_ports, subdomains))
        
        for host, ports in results:
            if ports:
                open_ports[host] = ports
        
        return open_ports
    
    def _display_massive_results(self, results):
        """Display massive enumeration results"""
        print(f"\n{'='*60}")
        print(f"[📊] MASSIVE ENUMERATION COMPLETED!")
        print(f"{'='*60}")
        print(f"🎯 Target: {results['domain']}")
        print(f"🔍 Total Checked: {results['stats']['total_checked']}")
        print(f"🌐 DNS Resolved: {results['stats']['dns_resolved']}")
        print(f"✅ Live Hosts: {results['stats']['live_hosts']}")
        print(f"🔓 Open Ports: {results['stats']['open_ports']}")
        
        # Show sample of results
        if results['live_subdomains']:
            print(f"\n[🌐] SAMPLE LIVE SUBDOMAINS (First 20):")
            for subdomain in sorted(results['live_subdomains'])[:20]:
                ips = results['ips'].get(subdomain, [])
                print(f"   ✅ {subdomain} -> {', '.join(ips)}")
        
        if results['open_ports']:
            print(f"\n[🔓] SAMPLE OPEN PORTS (First 10):")
            for host, ports in list(results['open_ports'].items())[:10]:
                print(f"   🔓 {host}: {', '.join(map(str, ports))}")
    
    def _save_massive_results(self, results, filename):
        """Save massive results to file"""
        with open(filename, 'w') as f:
            f.write(f"MASSIVE RECON RESULTS - {results['domain']}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("STATISTICS:\n")
            f.write(f"  Total Subdomains Checked: {results['stats']['total_checked']}\n")
            f.write(f"  DNS Resolved: {results['stats']['dns_resolved']}\n")
            f.write(f"  Live Hosts: {results['stats']['live_hosts']}\n")
            f.write(f"  Open Ports: {results['stats']['open_ports']}\n\n")
            
            f.write("ALL CHECKED SUBDOMAINS:\n")
            f.write("-" * 40 + "\n")
            for subdomain in sorted(results['all_checked_subdomains']):
                f.write(f"  {subdomain}\n")
            
            f.write("\nDNS RESOLVED SUBDOMAINS:\n")
            f.write("-" * 40 + "\n")
            for subdomain in sorted(results['dns_resolved_subdomains']):
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
        
        print(f"\n[💾] Complete results saved to: {filename}")

# -----------------------------
# COMMAND LINE INTERFACE
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="ReconX Pro - Massive Subdomain Finder")
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-ports', action='store_true', help='Enable port scanning')
    parser.add_argument('-active', action='store_true', help='Enable active scanning', default=True)
    
    args = parser.parse_args()
    
    print_banner()
    
    recon = AdvancedRecon()
    results = recon.massive_enumeration(
        domain=args.domain,
        active=args.active,
        ports=args.ports,
        output_file=args.output
    )

def print_banner():
    """Print banner"""
    BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝
              M A S S I V E   R E C O N
"""
    print(BANNER)
    print("=" * 70)
    print(f"🎯 1000+ Subdomains Finder - Kisi bhi domain ke liye")
    print(f"📁 Version: v3.0.0 (Massive Edition)")
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_banner()
        print("Usage: python3 reconx.py -d example.com [-o results.txt] [-ports]")
        print("\nExamples:")
        print("  python3 reconx.py -d facebook.com")
        print("  python3 reconx.py -d google.com -o results.txt -ports")
        print("  python3 reconx.py -d microsoft.com -ports")
        sys.exit(1)
    
    main()
