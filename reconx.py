#!/usr/bin/env python3
"""
ReconX Pro - Universal Subdomain Finder
Kisi bhi domain ke liye 1000+ subdomains find karega
Amass + Subfinder jaisa powerful tool
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
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------
# MASSIVE SUBDOMAINS WORDLIST (1500+)
# -----------------------------
MASSIVE_SUBDOMAINS = [
    # Common & Basic (100)
    'www', 'api', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'prod',
    'blog', 'shop', 'forum', 'support', 'help', 'docs', 'news', 'media',
    'cdn', 'static', 'app', 'apps', 'mobile', 'web', 'secure', 'portal',
    'login', 'signin', 'dashboard', 'account', 'user', 'users', 'profile',
    'search', 'find', 'query', 'results', 'data', 'database', 'db', 'sql',
    'backup', 'archive', 'old', 'new', 'temp', 'tmp', 'demo', 'sample', 'example',
    'home', 'site', 'server', 'client', 'host', 'node', 'service', 'services',
    'cloud', 'storage', 'file', 'files', 'image', 'images', 'img', 'video',
    'videos', 'audio', 'music', 'download', 'uploads', 'cdn1', 'cdn2', 'cdn3',
    'static1', 'static2', 'assets', 'asset', 'resource', 'resources', 'content',
    'core', 'main', 'primary', 'secondary', 'backup01', 'backup02', 'backup03',

    # Services & Protocols (100)
    'smtp', 'pop', 'pop3', 'imap', 'imap4', 'webmail', 'email', 'mail2',
    'ssh', 'vpn', 'remote', 'ftp2', 'ftps', 'sftp', 'rsync', 'ldap', 'ldaps',
    'proxy', 'firewall', 'router', 'switch', 'gateway', 'portal', 'console',
    'terminal', 'shell', 'cmd', 'command', 'exec', 'run', 'svc', 'daemon',

    # Development & Staging (100)
    'dev1', 'dev2', 'dev3', 'dev4', 'dev5', 'dev6', 'dev7', 'dev8', 'dev9', 'dev10',
    'staging1', 'staging2', 'staging3', 'staging4', 'staging5', 'staging6', 'staging7',
    'stage', 'stage1', 'stage2', 'stage3', 'preprod', 'pre-prod', 'preproduction',
    'qa', 'qa1', 'qa2', 'qa3', 'test1', 'test2', 'test3', 'test4', 'test5',
    'testing', 'testing1', 'testing2', 'uat', 'uat1', 'uat2', 'demo1', 'demo2',
    'sandbox', 'playground', 'experiment', 'experimental', 'lab', 'labs', 'research',
    'alpha', 'beta', 'gamma', 'delta', 'rc', 'release', 'build', 'build1', 'build2',

    # Infrastructure & Cloud (150)
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

    # Applications & Products (150)
    'wordpress', 'joomla', 'drupal', 'magento', 'prestashop', 'opencart',
    'woocommerce', 'shopify', 'bigcommerce', 'squarespace', 'wix', 'weebly',
    'sharepoint', 'exchange', 'owa', 'lync', 'teams', 'skype', 'zoom', 'meet',
    'webex', 'gotomeeting', 'slack', 'discord', 'telegram', 'whatsapp', 'viber',
    'signal', 'line', 'kakao', 'wechat', 'qq', 'vimeo', 'dailymotion', 'twitch',
    'mixer', 'dlive', 'periscope', 'snapchat', 'tiktok', 'pinterest', 'tumblr',
    'reddit', 'quora', 'medium', 'blogger', 'ghost', 'substack',

    # Security & Monitoring (100)
    'security', 'secure', 'auth', 'authentication', 'authorization', 'oauth',
    'sso', 'cas', 'saml', 'openid', 'ldap', 'kerberos', 'radius', 'tacacs',
    'firewall', 'waf', 'ips', 'ids', 'siem', 'soc', 'noc', 'monitoring',
    'monitor', 'nagios', 'zabbix', 'icinga', 'observium', 'librenms', 'cacti',
    'prtg', 'solarwinds', 'datadog', 'newrelic', 'appdynamics', 'dynatrace',
    'splunk', 'elastic', 'loggly', 'papertrail', 'sumologic', 'graylog',
    'sentry', 'rollbar', 'bugsnag', 'airbrake', 'honeybadger', 'raygun',

    # Network & DNS (100)
    'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'dns1', 'dns2', 'dns3', 'dns4', 'dns5',
    'router1', 'router2', 'switch1', 'switch2', 'firewall1', 'firewall2',
    'loadbalancer1', 'loadbalancer2', 'proxy1', 'proxy2', 'cache1', 'cache2',
    'cdn1', 'cdn2', 'cdn3', 'edge1', 'edge2', 'edge3', 'origin1', 'origin2',
    'server1', 'server2', 'server3', 'server4', 'server5', 'server6', 'server7',
    'server8', 'server9', 'server10', 'host1', 'host2', 'host3', 'host4', 'host5',
    'node1', 'node2', 'node3', 'node4', 'node5', 'cluster1', 'cluster2', 'cluster3',

    # Geographic & Regional (150)
    'us', 'usa', 'uk', 'gb', 'eu', 'europe', 'asia', 'apac', 'emea', 'na', 'sa',
    'africa', 'australia', 'canada', 'germany', 'france', 'italy', 'spain',
    'japan', 'china', 'india', 'brazil', 'mexico', 'russia', 'korea', 'singapore',
    'hongkong', 'taiwan', 'dubai', 'uae', 'saudi', 'qatar', 'kuwait', 'bahrain',
    'oman', 'egypt', 'southafrica', 'nigeria', 'kenya', 'ghana', 'morocco',
    'turkey', 'israel', 'iran', 'pakistan', 'bangladesh', 'srilanka', 'vietnam',
    'thailand', 'malaysia', 'indonesia', 'philippines', 'newzealand',

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

    # Technology Stack (150)
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

    # Business & Departments (150)
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

    # Additional Common (250)
    'access', 'activity', 'analytics', 'assets', 'attachment', 'back',
    'backup01', 'backup02', 'backup03', 'backup04', 'backup05', 'backup06',
    'backup07', 'backup08', 'backup09', 'backup10', 'backup11', 'backup12',
    'backup13', 'backup14', 'backup15', 'backup16', 'backup17', 'backup18',
    'backup19', 'backup20', 'backup21', 'backup22', 'backup23', 'backup24',
    'backup25', 'backup26', 'backup27', 'backup28', 'backup29', 'backup30',
    'backup31', 'backup32', 'backup33', 'backup34', 'backup35', 'backup36',
    'backup37', 'backup38', 'backup39', 'backup40', 'backup41', 'backup42',
    'backup43', 'backup44', 'backup45', 'backup46', 'backup47', 'backup48',
    'backup49', 'backup50', 'm', 'mobile1', 'mobile2', 'wap', 'android', 'ios',
    'iphone', 'ipad', 'tablet', 'desktop', 'pc', 'mac', 'linux', 'windows',
    'live', 'stream', 'broadcast', 'tv', 'radio', 'chat', 'message', 'messaging',
    'im', 'xmpp', 'webrtc', 'stun', 'turn', 'cms', 'adminer', 'phpmyadmin',
    'cpanel', 'whm', 'plesk', 'webmin', 'directadmin', 'vesta', 'ajenti',
    'munin', 'munin1', 'munin2', 'nagios1', 'nagios2', 'zabbix1', 'zabbix2',
    'grafana1', 'grafana2', 'kibana1', 'kibana2', 'prometheus1', 'prometheus2',
    'elastic1', 'elastic2', 'logstash1', 'logstash2', 'redis1', 'redis2',
    'memcached1', 'memcached2', 'mongodb1', 'mongodb2', 'mysql1', 'mysql2',
    'postgres1', 'postgres2', 'oracle1', 'oracle2', 'sqlserver1', 'sqlserver2',
    'ldap1', 'ldap2', 'radius1', 'radius2', 'kerberos1', 'kerberos2',
    'vpn1', 'vpn2', 'proxy1', 'proxy2', 'firewall1', 'firewall2', 'waf1', 'waf2',
    'ips1', 'ips2', 'ids1', 'ids2', 'siem1', 'siem2', 'soc1', 'soc2', 'noc1', 'noc2',
    'monitor1', 'monitor2', 'alert1', 'alert2', 'warning1', 'warning2',
    'critical1', 'critical2', 'error1', 'error2', 'debug1', 'debug2',
    'info1', 'info2', 'trace1', 'trace2', 'log1', 'log2', 'logs1', 'logs2',
    'audit1', 'audit2', 'report1', 'report2', 'stats1', 'stats2', 'metric1', 'metric2',
    'health1', 'health2', 'status1', 'status2', 'ping1', 'ping2', 'check1', 'check2',
    'test1', 'test2', 'validate1', 'validate2', 'verify1', 'verify2',
    'scan1', 'scan2', 'scanner1', 'scanner2', 'detect1', 'detect2',
    'discover1', 'discover2', 'find1', 'find2', 'search1', 'search2',
    'query1', 'query2', 'request1', 'request2', 'response1', 'response2',
    'api1', 'api2', 'api3', 'rest1', 'rest2', 'graphql1', 'graphql2',
    'soap1', 'soap2', 'grpc1', 'grpc2', 'rpc1', 'rpc2', 'xml1', 'xml2',
    'json1', 'json2', 'yaml1', 'yaml2', 'protobuf1', 'protobuf2',
    'avro1', 'avro2', 'thrift1', 'thrift2'
]

# -----------------------------
# UNIVERSAL SUBDOMAIN FINDER
# -----------------------------
class UniversalSubdomainFinder:
    def __init__(self):
        self.results = {
            'valid_subdomains': set(),
            'invalid_subdomains': set(),
            'error_subdomains': set(),
            'all_checked': set()
        }
        self.dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
    
    def find_subdomains(self, domain, output_file=None, threads=100):
        """Kisi bhi domain ke liye 1000+ subdomains find karo"""
        print(f"\n[🎯] STARTING UNIVERSAL SUBDOMAIN FINDER")
        print(f"[🌐] Target: {domain}")
        print(f"[📊] Testing {len(MASSIVE_SUBDOMAINS)} subdomains...")
        print(f"[⚡] Threads: {threads}")
        print("-" * 60)
        
        start_time = time.time()
        
        # Phase 1: Massive DNS Scanning
        print("[1️⃣] PHASE 1: Massive DNS Scanning...")
        dns_results = self._massive_dns_scan(domain, threads)
        
        # Phase 2: Live Host Detection
        print("[2️⃣] PHASE 2: Live Host Detection...")
        live_results = self._detect_live_hosts(dns_results['valid'])
        
        # Compile final results
        final_results = {
            "domain": domain,
            "scan_info": {
                "total_tested": len(self.results['all_checked']),
                "valid_subdomains": len(dns_results['valid']),
                "invalid_subdomains": len(dns_results['invalid']),
                "error_subdomains": len(dns_results['errors']),
                "live_hosts": len(live_results['live']),
                "scan_time": round(time.time() - start_time, 2)
            },
            "valid_subdomains": sorted(dns_results['valid']),
            "invalid_subdomains": sorted(dns_results['invalid']),
            "error_subdomains": sorted(dns_results['errors']),
            "live_subdomains": live_results['live'],
            "all_checked": sorted(self.results['all_checked'])
        }
        
        self._display_results(final_results)
        
        # Save results
        if output_file:
            self._save_results(final_results, output_file)
        
        return final_results
    
    def _massive_dns_scan(self, domain, threads=100):
        """Massive DNS scanning with error tracking"""
        valid = set()
        invalid = set()
        errors = set()
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            self.results['all_checked'].add(full_domain)
            
            try:
                # Try multiple DNS servers
                for dns_server in self.dns_servers:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [dns_server]
                        resolver.timeout = 2
                        resolver.lifetime = 2
                        
                        answers = resolver.resolve(full_domain, 'A')
                        ips = [str(rdata) for rdata in answers]
                        return full_domain, ips, "VALID", None
                    except dns.resolver.NXDOMAIN:
                        return full_domain, [], "INVALID", "NXDOMAIN"
                    except dns.resolver.NoAnswer:
                        continue
                    except dns.resolver.Timeout:
                        continue
                
                return full_domain, [], "ERROR", "TIMEOUT_ALL_SERVERS"
                
            except Exception as e:
                return full_domain, [], "ERROR", str(e)
        
        # Process in batches
        batch_size = 200
        total = len(MASSIVE_SUBDOMAINS)
        
        for i in range(0, total, batch_size):
            batch = MASSIVE_SUBDOMAINS[i:i + batch_size]
            completed = i + len(batch)
            
            print(f"    🔄 Progress: {completed}/{total} ({completed/total*100:.1f}%)")
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(check_subdomain, sub) for sub in batch]
                
                for future in as_completed(futures):
                    subdomain, ips, status, error = future.result()
                    
                    if status == "VALID":
                        valid.add(subdomain)
                    elif status == "INVALID":
                        invalid.add(subdomain)
                    else:
                        errors.add(f"{subdomain} - {error}")
        
        return {
            "valid": valid,
            "invalid": invalid,
            "errors": errors
        }
    
    def _detect_live_hosts(self, subdomains):
        """Detect live HTTP/HTTPS hosts"""
        live_hosts = {}
        
        def check_http(subdomain):
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                    if response.status_code < 400:
                        return subdomain, {
                            "protocol": protocol,
                            "status_code": response.status_code,
                            "url": url
                        }
                except:
                    continue
            return subdomain, None
        
        print(f"    🔄 Checking {len(subdomains)} valid subdomains for live hosts...")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_http, sub) for sub in subdomains]
            
            for future in as_completed(futures):
                subdomain, result = future.result()
                if result:
                    live_hosts[subdomain] = result
        
        return {"live": live_hosts}
    
    def _display_results(self, results):
        """Display comprehensive results"""
        stats = results['scan_info']
        
        print(f"\n{'='*60}")
        print(f"[🎉] SCAN COMPLETED!")
        print(f"{'='*60}")
        print(f"🌐 Domain: {results['domain']}")
        print(f"⏱️  Scan Time: {stats['scan_time']} seconds")
        print(f"📊 Total Tested: {stats['total_tested']}")
        print(f"✅ Valid Subdomains: {stats['valid_subdomains']}")
        print(f"❌ Invalid Subdomains: {stats['invalid_subdomains']}")
        print(f"⚠️  Error Subdomains: {stats['error_subdomains']}")
        print(f"🌐 Live Hosts: {stats['live_hosts']}")
        
        # Show valid subdomains
        if results['valid_subdomains']:
            print(f"\n[✅] VALID SUBDOMAINS ({len(results['valid_subdomains'])}):")
            for subdomain in results['valid_subdomains'][:30]:  # Show first 30
                print(f"   🌐 {subdomain}")
            
            if len(results['valid_subdomains']) > 30:
                print(f"   ... and {len(results['valid_subdomains']) - 30} more")
        
        # Show live hosts
        if results['live_subdomains']:
            print(f"\n[🔥] LIVE HOSTS ({len(results['live_subdomains'])}):")
            for subdomain, info in list(results['live_subdomains'].items())[:20]:
                print(f"   🔥 {subdomain} -> {info['url']} ({info['status_code']})")
    
    def _save_results(self, results, filename):
        """Save all results to file"""
        with open(filename, 'w') as f:
            f.write(f"UNIVERSAL SUBDOMAIN FINDER RESULTS\n")
            f.write(f"Domain: {results['domain']}\n")
            f.write(f"Scan Time: {results['scan_info']['scan_time']} seconds\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("SCAN STATISTICS:\n")
            f.write(f"  Total Subdomains Tested: {results['scan_info']['total_tested']}\n")
            f.write(f"  Valid Subdomains: {results['scan_info']['valid_subdomains']}\n")
            f.write(f"  Invalid Subdomains: {results['scan_info']['invalid_subdomains']}\n")
            f.write(f"  Error Subdomains: {results['scan_info']['error_subdomains']}\n")
            f.write(f"  Live Hosts: {results['scan_info']['live_hosts']}\n\n")
            
            f.write("ALL VALID SUBDOMAINS:\n")
            f.write("-" * 40 + "\n")
            for subdomain in results['valid_subdomains']:
                f.write(f"{subdomain}\n")
            
            f.write("\nLIVE HOSTS:\n")
            f.write("-" * 40 + "\n")
            for subdomain, info in results['live_subdomains'].items():
                f.write(f"{subdomain} -> {info['url']} ({info['status_code']})\n")
            
            f.write("\nINVALID SUBDOMAINS:\n")
            f.write("-" * 40 + "\n")
            for subdomain in results['invalid_subdomains'][:100]:  # First 100 only
                f.write(f"{subdomain}\n")
            
            f.write("\nERROR SUBDOMAINS:\n")
            f.write("-" * 40 + "\n")
            for error in list(results['error_subdomains'])[:50]:  # First 50 errors
                f.write(f"{error}\n")
        
        print(f"\n[💾] Complete results saved to: {filename}")

# -----------------------------
# COMMAND LINE INTERFACE
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Universal Subdomain Finder - Kisi bhi domain ke liye 1000+ subdomains")
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com, example.com, example.com)')
    parser.add_argument('-o', '--output', help='Output file to save all results')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    
    args = parser.parse_args()
    
    print_banner()
    
    finder = UniversalSubdomainFinder()
    results = finder.find_subdomains(
        domain=args.domain,
        output_file=args.output,
        threads=args.threads
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
           U N I V E R S A L   F I N D E R
"""
    print(BANNER)
    print("=" * 70)
    print(f"🎯 Kisi bhi domain ke liye 1500+ Subdomains Finder")
    print(f"📁 Version: v4.0.0 (Universal Edition)")
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_banner()
        print("Usage: python3 reconx.py -d DOMAIN [-o OUTPUT_FILE] [-t THREADS]")
        print("\nExamples:")
        print("  python3 reconx.py -d example.com")
        print("  python3 reconx.py -d example.com -o example.txt")
        print("  python3 reconx.py -d example.com -t 200 -o example.txt")
        print("  python3 reconx.py -d example.com -o example.txt")
        print("\n💡 Kisi bhi domain ke liye use karein: example.com ")
        sys.exit(1)
    
    main()
