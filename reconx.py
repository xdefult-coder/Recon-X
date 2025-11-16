#!/usr/bin/env python3
"""
ReconX Pro - All Subdomains with HTTP Status Codes
Har subdomain aur uska status code dikhata hai
"""

import os
import sys
import argparse
import json
import requests
import dns.resolver
import socket
import threading
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
# ALL SUBDOMAINS WITH STATUS CODES
# -----------------------------
class AllSubdomainsWithStatus:
    def __init__(self):
        self.results = {
            'all_subdomains': [],
            'status_codes': {},
            'statistics': {
                'total_tested': 0,
                'dns_resolved': 0,
                'http_checked': 0,
                'by_status_code': {}
            }
        }
        self.dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    
    def find_all_with_status(self, domain, output_file=None, threads=100):
        """Sare subdomains aur unke status codes find karo"""
        print(f"\n[🎯] ALL SUBDOMAINS WITH HTTP STATUS CODES")
        print(f"[🌐] Target: {domain}")
        print(f"[📊] Testing {len(MASSIVE_SUBDOMAINS)} subdomains...")
        print(f"[⚡] Threads: {threads}")
        print("-" * 60)
        
        start_time = time.time()
        
        # Phase 1: DNS Resolution for ALL subdomains
        print("[1️⃣] PHASE 1: DNS Resolution (All Subdomains)...")
        all_subdomains = self._get_all_subdomains(domain)
        
        # Phase 2: HTTP Status Codes for ALL subdomains
        print("[2️⃣] PHASE 2: HTTP Status Code Analysis (All Subdomains)...")
        status_results = self._check_all_http_status(all_subdomains, threads)  # FIXED: threads parameter add kiya
        
        # Compile final results
        final_results = {
            "domain": domain,
            "scan_info": {
                "total_subdomains_tested": len(all_subdomains),
                "dns_resolved": len([s for s in all_subdomains if s['dns_status'] == 'VALID']),
                "http_status_checked": len(status_results),
                "scan_time": round(time.time() - start_time, 2),
                "status_code_breakdown": self._get_status_breakdown(status_results)
            },
            "all_subdomains": all_subdomains,
            "status_codes": status_results
        }
        
        self._display_all_results(final_results)
        
        if output_file:
            self._save_all_results(final_results, output_file)
        
        return final_results
    
    def _get_all_subdomains(self, domain):
        """Saare possible subdomains generate karo"""
        all_subs = []
        
        for sub in MASSIVE_SUBDOMAINS:
            full_domain = f"{sub}.{domain}"
            all_subs.append({
                'subdomain': full_domain,
                'base_sub': sub,
                'dns_status': 'PENDING'
            })
        
        return all_subs
    
    def _check_all_http_status(self, subdomains, threads=50):  # FIXED: threads parameter add kiya
        """Har subdomain ka HTTP status code check karo"""
        results = {}
        
        def check_single_subdomain(sub_info):
            subdomain = sub_info['subdomain']
            
            # First check DNS
            dns_status, ips = self._check_dns(subdomain)
            sub_info['dns_status'] = dns_status
            sub_info['ips'] = ips
            
            # Then check HTTP status
            http_results = {}
            
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = requests.get(
                        url, 
                        timeout=3, 
                        verify=False, 
                        allow_redirects=False,  # No redirects to get actual status
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    )
                    http_results[protocol] = {
                        'status_code': response.status_code,
                        'url': url,
                        'content_length': len(response.content) if response.content else 0,
                        'headers': dict(response.headers)
                    }
                except requests.exceptions.SSLError:
                    http_results[protocol] = {
                        'status_code': 'SSL_ERROR',
                        'error': 'SSL Certificate Error'
                    }
                except requests.exceptions.ConnectTimeout:
                    http_results[protocol] = {
                        'status_code': 'TIMEOUT',
                        'error': 'Connection Timeout'
                    }
                except requests.exceptions.ConnectionError:
                    http_results[protocol] = {
                        'status_code': 'CONNECTION_ERROR',
                        'error': 'Connection Failed'
                    }
                except requests.exceptions.RequestException as e:
                    http_results[protocol] = {
                        'status_code': 'REQUEST_ERROR',
                        'error': str(e)
                    }
                except Exception as e:
                    http_results[protocol] = {
                        'status_code': 'UNKNOWN_ERROR',
                        'error': str(e)
                    }
            
            return subdomain, http_results, dns_status, ips
        
        print(f"    🔄 Checking {len(subdomains)} subdomains...")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:  # FIXED: threads variable use kiya
            futures = [executor.submit(check_single_subdomain, sub) for sub in subdomains]
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 100 == 0:
                    print(f"        📊 Completed: {completed}/{len(subdomains)}")
                
                subdomain, http_results, dns_status, ips = future.result()
                results[subdomain] = {
                    'http': http_results,
                    'dns': dns_status,
                    'ips': ips
                }
        
        return results
    
    def _check_dns(self, subdomain):
        """DNS resolution check"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.dns_servers
            resolver.timeout = 2
            resolver.lifetime = 2
            
            answers = resolver.resolve(subdomain, 'A')
            return 'VALID', [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            return 'NXDOMAIN', []
        except dns.resolver.NoAnswer:
            return 'NO_ANSWER', []
        except dns.resolver.Timeout:
            return 'TIMEOUT', []
        except Exception:
            return 'ERROR', []
    
    def _get_status_breakdown(self, status_results):
        """Status codes ka breakdown generate karo"""
        breakdown = {
            '200-299': 0, '300-399': 0, '400-499': 0, '500-599': 0,
            'SSL_ERROR': 0, 'TIMEOUT': 0, 'CONNECTION_ERROR': 0,
            'REQUEST_ERROR': 0, 'UNKNOWN_ERROR': 0
        }
        
        for subdomain, data in status_results.items():
            for protocol, info in data['http'].items():
                status = info.get('status_code')
                if isinstance(status, int):
                    if 200 <= status < 300:
                        breakdown['200-299'] += 1
                    elif 300 <= status < 400:
                        breakdown['300-399'] += 1
                    elif 400 <= status < 500:
                        breakdown['400-499'] += 1
                    elif 500 <= status < 600:
                        breakdown['500-599'] += 1
                else:
                    if status in breakdown:
                        breakdown[status] += 1
                    else:
                        breakdown['UNKNOWN_ERROR'] += 1
        
        return breakdown
    
    def _display_all_results(self, results):
        """Sare results display karo"""
        stats = results['scan_info']
        status_results = results['status_codes']
        
        print(f"\n{'='*80}")
        print(f"[🎉] SCAN COMPLETED - ALL SUBDOMAINS WITH STATUS CODES")
        print(f"{'='*80}")
        print(f"🌐 Domain: {results['domain']}")
        print(f"⏱️  Scan Time: {stats['scan_time']} seconds")
        print(f"📊 Total Subdomains Tested: {stats['total_subdomains_tested']}")
        print(f"🔍 DNS Resolved: {stats['dns_resolved']}")
        print(f"🌐 HTTP Status Checked: {stats['http_status_checked']}")
        
        # Status code breakdown
        breakdown = stats['status_code_breakdown']
        print(f"\n[📊] HTTP STATUS CODE BREAKDOWN:")
        print(f"    🟢 200-299 (Success): {breakdown['200-299']}")
        print(f"    🔵 300-399 (Redirect): {breakdown['300-399']}")
        print(f"    🟡 400-499 (Client Error): {breakdown['400-499']}")
        print(f"    🔴 500-599 (Server Error): {breakdown['500-599']}")
        print(f"    🔐 SSL Errors: {breakdown['SSL_ERROR']}")
        print(f"    ⏰ Timeouts: {breakdown['TIMEOUT']}")
        print(f"    🔌 Connection Errors: {breakdown['CONNECTION_ERROR']}")
        
        # Display ALL subdomains with their status codes
        print(f"\n[🌐] ALL SUBDOMAINS WITH HTTP STATUS CODES:")
        print("-" * 80)
        
        # Sort by subdomain name
        sorted_subdomains = sorted(status_results.items())
        
        for subdomain, data in sorted_subdomains:
            dns_status = data['dns']
            http_data = data['http']
            
            # DNS status indicator
            if dns_status == 'VALID':
                dns_indicator = '🔵'
            elif dns_status == 'NXDOMAIN':
                dns_indicator = '⚫'
            else:
                dns_indicator = '⚪'
            
            # Get best HTTP status (prefer HTTPS over HTTP)
            best_status = None
            best_protocol = None
            
            for protocol in ['https', 'http']:
                if protocol in http_data:
                    status_info = http_data[protocol]
                    status = status_info.get('status_code')
                    if status:
                        best_status = status
                        best_protocol = protocol
                        break
            
            # Status code color and display
            if best_status:
                if isinstance(best_status, int):
                    if 200 <= best_status < 300:
                        status_str = f"🟢 {best_status}"
                    elif 300 <= best_status < 400:
                        status_str = f"🔵 {best_status}"
                    elif 400 <= best_status < 500:
                        status_str = f"🟡 {best_status}"
                    elif 500 <= best_status < 600:
                        status_str = f"🔴 {best_status}"
                    else:
                        status_str = f"⚪ {best_status}"
                else:
                    status_str = f"⚫ {best_status}"
                
                print(f"{dns_indicator} {status_str} - {subdomain}")
            else:
                print(f"{dns_indicator} ⚫ NO_HTTP - {subdomain}")
    
    def _save_all_results(self, results, filename):
        """Sare results save karo"""
        with open(filename, 'w') as f:
            f.write(f"ALL SUBDOMAINS WITH HTTP STATUS CODES\n")
            f.write(f"Domain: {results['domain']}\n")
            f.write(f"Scan Time: {results['scan_info']['scan_time']} seconds\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("SCAN STATISTICS:\n")
            f.write(f"  Total Subdomains Tested: {results['scan_info']['total_subdomains_tested']}\n")
            f.write(f"  DNS Resolved: {results['scan_info']['dns_resolved']}\n")
            f.write(f"  HTTP Status Checked: {results['scan_info']['http_status_checked']}\n\n")
            
            f.write("STATUS CODE BREAKDOWN:\n")
            breakdown = results['scan_info']['status_code_breakdown']
            for category, count in breakdown.items():
                if count > 0:
                    f.write(f"  {category}: {count}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("ALL SUBDOMAINS WITH STATUS CODES:\n")
            f.write("="*80 + "\n\n")
            
            # Sort by subdomain name
            sorted_subdomains = sorted(results['status_codes'].items())
            
            for subdomain, data in sorted_subdomains:
                f.write(f"{subdomain}:\n")
                f.write(f"  DNS Status: {data['dns']}\n")
                if data['ips']:
                    f.write(f"  IP Addresses: {', '.join(data['ips'])}\n")
                
                for protocol in ['http', 'https']:
                    if protocol in data['http']:
                        info = data['http'][protocol]
                        status = info.get('status_code', 'UNKNOWN')
                        f.write(f"  {protocol.upper()}: {status}\n")
                        
                        if 'url' in info:
                            f.write(f"    URL: {info['url']}\n")
                        if 'content_length' in info:
                            f.write(f"    Content Length: {info['content_length']} bytes\n")
                        if 'error' in info:
                            f.write(f"    Error: {info['error']}\n")
                
                f.write("\n")
        
        print(f"\n[💾] Complete results with ALL subdomains saved to: {filename}")

# -----------------------------
# COMMAND LINE INTERFACE
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="All Subdomains with HTTP Status Codes")
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com, example.com)')
    parser.add_argument('-o', '--output', help='Output file to save all results')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    
    args = parser.parse_args()
    
    print_banner()
    
    finder = AllSubdomainsWithStatus()
    results = finder.find_all_with_status(
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
        ALL SUBDOMAINS + STATUS CODES
"""
    print(BANNER)
    print("=" * 70)
    print(f"🎯 All Subdomains with HTTP Status Codes")
    print(f"📁 Version: v6.0.0 (Complete Edition)")
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_banner()
        print("Usage: python3 reconx.py -d DOMAIN [-o OUTPUT_FILE] [-t THREADS]")
        print("\nExamples:")
        print("  python3 reconx.py -d example.com")
        print("  python3 reconx.py -d example.com -o result.txt")
        print("  python3 reconx.py -d example.com -t 100 -o example_all_status.txt")
        print("\n💡 SARE SUBDOMAINS AUR UNKE STATUS CODES DIKHAYEGA!")
        sys.exit(1)
    
    main()
