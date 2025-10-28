#!/usr/bin/env python3
"""
Advanced Subdomain Enumerator - Inspired by Sublist3r
Combines dig with multiple OSINT sources for deep subdomain discovery

Author: Sir Jimbet
Version: 3.1.0
Features: dig + OSINT + Brute Force + Color Output
"""

import subprocess
import re
import concurrent.futures
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
import json
import shutil
import sys
import requests
import time
import warnings
from urllib.parse import quote

# Suppress SSL warnings for problematic sources
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class Colors:
    """Color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # Custom colors for better visibility on black background
    DOMAIN = '\033[96m'      # Cyan for domains
    IP = '\033[93m'          # Yellow for IPs
    SUCCESS = '\033[92m'     # Green for success
    ERROR = '\033[91m'       # Red for errors
    INFO = '\033[94m'        # Blue for info
    HIGHLIGHT = '\033[95m'   # Magenta for highlights


class CloudflareEnumerator:
    """
    Specialized enumerator for Cloudflare-protected domains.
    """

    def __init__(self, domain: str, timeout: int = 10):
        self.domain = domain
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def search_cloudflare_dns(self) -> Set[str]:
        """Query Cloudflare's DNS-over-HTTPS for subdomains"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Querying Cloudflare DNS-over-HTTPS...")
        subdomains = set()
        
        try:
            # Try multiple record types
            for record_type in ['A', 'AAAA', 'CNAME']:
                url = f"https://cloudflare-dns.com/dns-query?name={self.domain}&type={record_type}"
                headers = {'accept': 'application/dns-json'}
                
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json()
                    answers = data.get('Answer', [])
                    for answer in answers:
                        name = answer.get('name', '').rstrip('.')
                        if name.endswith(self.domain):
                            subdomains.add(name)
            
            print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from Cloudflare DoH")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} Cloudflare DoH unavailable (skipped)")
        
        return subdomains
    
    def search_securitytrails(self) -> Set[str]:
        """Search SecurityTrails (free tier, no API key needed for basic search)"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching SecurityTrails...")
        subdomains = set()
        
        try:
            url = f"https://securitytrails.com/list/apex_domain/{self.domain}"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                # Parse subdomains from HTML
                matches = re.findall(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*' + re.escape(self.domain), response.text)
                for match in matches:
                    subdomain = ''.join(match).strip()
                    if subdomain and subdomain.endswith(self.domain):
                        subdomains.add(subdomain)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from SecurityTrails")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} SecurityTrails unavailable (skipped)")
        
        return subdomains
    
    def check_common_cloudflare_patterns(self) -> Set[str]:
        """Generate common Cloudflare subdomain patterns"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Checking common Cloudflare patterns...")
        
        patterns = [
            # Common Cloudflare patterns
            "direct", "origin", "direct-connect", "origin-server",
            # Geographic patterns
            "us", "eu", "asia", "uk", "de", "fr", "au", "ca", "jp",
            # Service patterns    
            "assets", "static", "media", "images", "img", "cdn", "cdn1", "cdn2",
            "files", "uploads", "downloads", "storage",
            # API patterns
            "api", "api1", "api2", "rest", "graphql", "ws", "websocket",
            # Application patterns
            "app", "webapp", "web", "portal", "dashboard", "admin", "panel",
            # Environment patterns
            "prod", "production", "staging", "stage", "dev", "development", "test",
            # Load balancer patterns
            "lb", "lb1", "lb2", "loadbalancer",
            # Worker patterns (Cloudflare Workers)
            "workers", "worker", "edge",
            # Pages patterns (Cloudflare Pages)
            "pages", "preview",
            # Stream patterns
            "stream", "video", "live",
        ]
        
        subdomains = set()
        for pattern in patterns:
            subdomains.add(f"{pattern}.{self.domain}")
        
        print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Generated {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} pattern-based subdomains")
        return subdomains
    
    def enumerate_all(self) -> Set[str]:
        """Run all Cloudflare-specific enumeration"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Cloudflare-Specific Subdomain Discovery{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        all_subdomains = set()
        
        sources = [
            self.search_cloudflare_dns,
            self.search_securitytrails,
            self.check_common_cloudflare_patterns
        ]
        
        for source in sources:
            try:
                results = source()
                all_subdomains.update(results)
                time.sleep(1)
            except Exception as e:
                # Silent failure - already handled in individual methods
                pass
        
        print(f"\n  {Colors.SUCCESS}✓{Colors.ENDC} Total unique subdomains from Cloudflare methods: {Colors.HIGHLIGHT}{len(all_subdomains)}{Colors.ENDC}\n")
        return all_subdomains


class OSINTEnumerator:
    """
    OSINT-based subdomain discovery using multiple public sources.
    """
    
    def __init__(self, domain: str, timeout: int = 10):
        self.domain = domain
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def search_crtsh(self) -> Set[str]:
        """Search Certificate Transparency logs via crt.sh"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching crt.sh (SSL Certificates)...")
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().replace('*.', '')
                        if subdomain.endswith(self.domain) and subdomain:
                            subdomains.add(subdomain)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from crt.sh")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} crt.sh unavailable (skipped)")
        
        return subdomains
    
    def search_hackertarget(self) -> Set[str]:
        """Search HackerTarget API"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching HackerTarget API...")
        subdomains = set()

        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and subdomain.endswith(self.domain):
                            subdomains.add(subdomain)

                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from HackerTarget")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} HackerTarget unavailable (skipped)")

        return subdomains
    
    def search_threatcrowd(self) -> Set[str]:
        """Search ThreatCrowd API"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching ThreatCrowd...")
        subdomains = set()
        
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                subs = data.get('subdomains', [])
                for subdomain in subs:
                    if subdomain and subdomain.endswith(self.domain):
                        subdomains.add(subdomain)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from ThreatCrowd")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} ThreatCrowd unavailable (skipped)")
        
        return subdomains
    
    def search_alienvault(self) -> Set[str]:
        """Search AlienVault OTX"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching AlienVault OTX...")
        subdomains = set()
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if hostname and hostname.endswith(self.domain):
                        subdomains.add(hostname)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from AlienVault")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} AlienVault unavailable (skipped)")
        
        return subdomains
    
    def search_urlscan(self) -> Set[str]:
        """Search URLScan.io"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching URLScan.io...")
        subdomains = set()
        
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    page_domain = result.get('page', {}).get('domain', '')
                    if page_domain and page_domain.endswith(self.domain):
                        subdomains.add(page_domain)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from URLScan")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} URLScan unavailable (skipped)")
        
        return subdomains
    
    def search_rapiddns(self) -> Set[str]:
        """Search RapidDNS"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching RapidDNS...")
        subdomains = set()
        
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                matches = re.findall(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(self.domain), response.text)
                for match in matches:
                    subdomain = match[0] + self.domain if match[0] else match
                    if subdomain.endswith(self.domain):
                        subdomains.add(subdomain.rstrip('.'))
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from RapidDNS")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} RapidDNS unavailable (skipped)")
        
        return subdomains
    
    def search_anubis(self) -> Set[str]:
        """Search Anubis DB"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching Anubis-DB...")
        subdomains = set()
        
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for subdomain in data:
                    if subdomain and subdomain.endswith(self.domain):
                        subdomains.add(subdomain)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from Anubis")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} Anubis unavailable (skipped)")
        
        return subdomains
    
    def search_certspotter(self) -> Set[str]:
        """Search CertSpotter"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching CertSpotter...")
        subdomains = set()
        
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    dns_names = cert.get('dns_names', [])
                    for name in dns_names:
                        if name.endswith(self.domain):
                            name = name.replace('*.', '')
                            subdomains.add(name)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from CertSpotter")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} CertSpotter unavailable (skipped)")
        
        return subdomains
    
    def search_wayback(self) -> Set[str]:
        """Search Wayback Machine"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching Wayback Machine...")
        subdomains = set()
        
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for item in data[1:]:
                    if item:
                        full_url = item[0]
                        match = re.search(r'https?://([^/]+)', full_url)
                        if match:
                            extracted_domain = match.group(1).lower()
                            if extracted_domain.endswith(self.domain):
                                subdomains.add(extracted_domain)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from Wayback Machine")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} Wayback Machine unavailable (skipped)")
        
        return subdomains
    
    def search_commoncrawl(self) -> Set[str]:
        """Search CommonCrawl"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching CommonCrawl...")
        subdomains = set()
        
        try:
            url = f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{self.domain}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            full_url = data.get('url', '')
                            match = re.search(r'https?://([^/]+)', full_url)
                            if match:
                                extracted_domain = match.group(1).lower()
                                if extracted_domain.endswith(self.domain):
                                    subdomains.add(extracted_domain)
                        except:
                            pass
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from CommonCrawl")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} CommonCrawl unavailable (skipped)")
        
        return subdomains
    
    def search_webarchive(self) -> Set[str]:
        """Search Web Archive"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching Archive.org...")
        subdomains = set()
        
        try:
            url = f"https://web.archive.org/__wb/search/metadata?url=*.{self.domain}&limit=1000"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            original_url = data.get('original', '')
                            match = re.search(r'https?://([^/]+)', original_url)
                            if match:
                                extracted_domain = match.group(1).lower()
                                if extracted_domain.endswith(self.domain):
                                    subdomains.add(extracted_domain)
                        except:
                            pass
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from Archive.org")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} Archive.org unavailable (skipped)")
        
        return subdomains
    
    def search_dnsdumpster(self) -> Set[str]:
        """Search DNSDumpster"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching DNSDumpster...")
        subdomains = set()
        
        try:
            url = "https://dnsdumpster.com/"
            response = self.session.get(url, timeout=self.timeout)
            
            csrf_match = re.search(r"name='csrfmiddlewaretoken' value='([^']+)'", response.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
                
                data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'targetip': self.domain
                }
                headers = {
                    'Referer': url,
                    'Origin': 'https://dnsdumpster.com'
                }
                
                response = self.session.post(url, data=data, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    matches = re.findall(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(self.domain), response.text)
                    for match in matches:
                        subdomain = match[0] + self.domain if match[0] else match
                        if subdomain.endswith(self.domain):
                            subdomains.add(subdomain.rstrip('.'))
                    
                    print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from DNSDumpster")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} DNSDumpster unavailable (skipped)")
        
        return subdomains
    
    def enumerate_all(self) -> Set[str]:
        """Run all OSINT sources"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}OSINT Subdomain Discovery{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        all_subdomains = set()
        
        sources = [
            self.search_crtsh,
            self.search_hackertarget,
            self.search_threatcrowd,
            self.search_alienvault,
            self.search_urlscan,
            self.search_rapiddns,
            self.search_anubis,
            self.search_certspotter,
            self.search_wayback,
            self.search_commoncrawl,
            self.search_webarchive,
            self.search_dnsdumpster
        ]
        
        for source in sources:
            try:
                results = source()
                all_subdomains.update(results)
                time.sleep(1)
            except Exception as e:
                pass
        
        print(f"\n  {Colors.SUCCESS}✓{Colors.ENDC} Total unique subdomains from OSINT: {Colors.HIGHLIGHT}{len(all_subdomains)}{Colors.ENDC}\n")
        return all_subdomains


class DigResolver:
    """
    DNS resolver using the dig command-line tool with Cloudflare optimization.
    """
    
    def __init__(self, timeout: int = 5, dns_server: Optional[str] = None, use_cloudflare: bool = False):
        self.timeout = timeout
        self.dns_server = dns_server
        self.use_cloudflare = use_cloudflare
        self.dig_available = self._check_dig_available()
        
        # If Cloudflare mode, use their DNS servers
        if self.use_cloudflare and not self.dns_server:
            self.dns_server = "1.1.1.1"  # Cloudflare DNS
    
    def _check_dig_available(self) -> bool:
        """Check if dig command is available on the system."""
        return shutil.which('dig') is not None
    
    def get_nameservers(self, domain: str) -> List[str]:
        """Get nameservers for a domain using dig"""
        if not self.dig_available:
            return []
        
        cmd = ['dig', '+short', 'NS', domain]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 2
            )
            
            if result.returncode == 0:
                nameservers = []
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    ns = line.strip().rstrip('.')
                    if ns:
                        nameservers.append(ns.lower())
                return nameservers
        except Exception:
            pass
        
        return []
    
    def is_cloudflare_ns(self, nameservers: List[str]) -> bool:
        """Check if nameservers belong to Cloudflare"""
        cloudflare_ns_patterns = [
            'cloudflare.com',
            'ns.cloudflare.com',
            '.ns.cloudflare.com'
        ]
        
        for ns in nameservers:
            for pattern in cloudflare_ns_patterns:
                if pattern in ns:
                    return True
        return False
    
    def resolve_with_dig(self, domain: str, record_type: str = 'A') -> List[str]:
        """Resolve domain using dig command."""
        if not self.dig_available:
            raise RuntimeError("dig command not found")
        
        cmd = ['dig', '+short', '+time=' + str(self.timeout)]
        
        # Cloudflare-specific optimizations
        if self.use_cloudflare:
            cmd.extend(['+noedns', '+nocookie'])  # Disable EDNS for better compatibility
        
        if self.dns_server:
            cmd.append('@' + self.dns_server)
        
        cmd.extend([domain, record_type])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 2
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                addresses = []
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith(';'):
                        if record_type == 'A':
                            if self._is_valid_ipv4(line):
                                addresses.append(line)
                        else:
                            addresses.append(line)
                
                return addresses
            
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        
        return []
    
    def check_cname_chain(self, domain: str) -> List[str]:
        """Follow CNAME chain to discover additional subdomains (useful for Cloudflare)"""
        cnames = []
        current = domain
        max_depth = 10
        depth = 0
        
        while depth < max_depth:
            result = self.resolve_with_dig(current, 'CNAME')
            if result:
                cname = result[0].rstrip('.')
                cnames.append(cname)
                current = cname
                depth += 1
            else:
                break
        
        return cnames
    
    def _is_valid_ipv4(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


class SubdomainEnumerator:
    """
    Advanced subdomain enumerator combining OSINT + DNS verification with dig.
    Includes automatic Cloudflare detection and optimization.
    """
    
    def __init__(self, domain: str, timeout: int = 5, max_workers: int = 30, 
                 dns_server: Optional[str] = None, use_cloudflare: bool = False,
                 detected_nameservers: Optional[List[str]] = None):
        self.domain = domain
        self.timeout = timeout
        self.max_workers = max_workers
        self.use_cloudflare = use_cloudflare
        self.detected_nameservers = detected_nameservers or []
        self.dig_resolver = DigResolver(timeout=timeout, dns_server=dns_server, use_cloudflare=use_cloudflare)
        self.osint_enum = OSINTEnumerator(domain, timeout=10)
        self.cloudflare_enum = CloudflareEnumerator(domain, timeout=10) if use_cloudflare else None
        self.dns_server = dns_server or (self.dig_resolver.dns_server if use_cloudflare else None)
        
        if not self.dig_resolver.dig_available:
            print(f"{Colors.ERROR}⚠ WARNING: dig command not found!{Colors.ENDC}")
            print("Please install: apt-get install dnsutils (Debian/Ubuntu)")
            print("          or: yum install bind-utils (RHEL/CentOS)")
            print("          or: brew install bind (macOS)")
            sys.exit(1)
    
    def resolve_subdomain(self, subdomain: str) -> Tuple[str, List[str], List[str]]:
        """Resolve a subdomain to its IPv4 addresses using dig."""
        ipv4_addresses = self.dig_resolver.resolve_with_dig(subdomain, 'A')
        
        # For Cloudflare sites, also check CNAME chains
        cnames = []
        if self.use_cloudflare:
            cnames = self.dig_resolver.check_cname_chain(subdomain)
        
        return subdomain, ipv4_addresses, cnames
    
    def verify_subdomains_with_dig(self, subdomains: Set[str], show_progress: bool = True) -> Dict[str, List[str]]:
        """Verify discovered subdomains using dig."""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Verifying {len(subdomains)} subdomains with dig{Colors.ENDC}")
        if self.dns_server:
            print(f"{Colors.INFO}DNS Server: {self.dns_server}{Colors.ENDC}")
        if self.use_cloudflare:
            print(f"{Colors.INFO}Mode: Cloudflare-optimized{Colors.ENDC}")
        print(f"{Colors.INFO}Timeout: {self.timeout}s | Workers: {self.max_workers}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        results = {}
        discovered_from_cnames = set()
        total = len(subdomains)
        completed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self.resolve_subdomain, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                completed += 1
                
                try:
                    full_domain, ipv4_list, cnames = future.result()
                    
                    if ipv4_list:
                        results[full_domain] = ipv4_list
                        if show_progress:
                            # Format IPs with color
                            colored_ips = [f"{Colors.IP}{ip}{Colors.ENDC}" for ip in ipv4_list]
                            cname_info = f" {Colors.INFO}[CNAME: {cnames[0]}]{Colors.ENDC}" if cnames else ""
                            print(f"[{completed}/{total}] {Colors.SUCCESS}✓{Colors.ENDC} {Colors.DOMAIN}{full_domain}{Colors.ENDC} -> {', '.join(colored_ips)}{cname_info}")
                        
                        # Add discovered CNAMEs to potential targets
                        for cname in cnames:
                            if cname.endswith(self.domain) and cname not in results:
                                discovered_from_cnames.add(cname)
                
                except Exception:
                    pass
                
                if show_progress and completed % 50 == 0:
                    print(f"\n{Colors.INFO}Progress: {completed}/{total} verified, {len(results)} alive{Colors.ENDC}\n")
        
        # If we found new subdomains via CNAME, resolve them too
        if discovered_from_cnames:
            print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(discovered_from_cnames)}{Colors.ENDC} additional subdomains via CNAME chains")
            additional_results = self.verify_subdomains_with_dig(discovered_from_cnames, show_progress=False)
            results.update(additional_results)
        
        return results
    
    def bruteforce_subdomains(self, wordlist: List[str], show_progress: bool = True) -> Dict[str, List[str]]:
        """Brute force subdomains using a wordlist."""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Brute Force Enumeration{Colors.ENDC}")
        print(f"{Colors.HEADER}Testing {len(wordlist)} subdomain names{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        # Generate full subdomains
        subdomains = [f"{word}.{self.domain}" for word in wordlist]
        
        return self.verify_subdomains_with_dig(set(subdomains), show_progress)
    
    def enumerate_deep(self, use_osint: bool = True, use_bruteforce: bool = True, 
                       wordlist: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Deep enumeration combining OSINT and brute force (like Sublist3r).
        """
        all_subdomains = set()
        
        # Step 1: Cloudflare-specific discovery (if enabled)
        if self.use_cloudflare and self.cloudflare_enum:
            cloudflare_subs = self.cloudflare_enum.enumerate_all()
            all_subdomains.update(cloudflare_subs)
        
        # Step 2: OSINT Discovery
        if use_osint:
            osint_subs = self.osint_enum.enumerate_all()
            all_subdomains.update(osint_subs)
        
        # Step 3: Brute Force (if enabled)
        if use_bruteforce and wordlist:
            print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
            print(f"{Colors.HEADER}Brute Force Discovery{Colors.ENDC}")
            print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
            bruteforce_subs = [f"{word}.{self.domain}" for word in wordlist]
            all_subdomains.update(bruteforce_subs)
        
        # Step 4: Verify all discovered subdomains with dig
        if all_subdomains:
            verified = self.verify_subdomains_with_dig(all_subdomains, show_progress=True)
            return verified
        
        return {}
    
    def group_by_ip(self, subdomain_results: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Group subdomains by shared IP addresses."""
        ip_to_subdomains = defaultdict(list)
        
        for subdomain, ip_list in subdomain_results.items():
            for ip in ip_list:
                ip_to_subdomains[ip].append(subdomain)
                
        return dict(ip_to_subdomains)
    
    def find_shared_ips(self, subdomain_results: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Find IPs shared by multiple subdomains."""
        ip_groups = self.group_by_ip(subdomain_results)
        shared_ips = {ip: domains for ip, domains in ip_groups.items() if len(domains) > 1}
        return shared_ips
    
    def generate_report(self, subdomain_results: Dict[str, List[str]], 
                       include_shared_only: bool = False) -> str:
        """Generate formatted report."""
        if include_shared_only:
            ip_groups = self.find_shared_ips(subdomain_results)
            title = "Shared IP Addresses Report"
        else:
            ip_groups = self.group_by_ip(subdomain_results)
            title = "Deep Subdomain Enumeration Report"
        
        report = f"\n{Colors.HEADER}{'='*60}\n{title}\n{'='*60}{Colors.ENDC}\n"
        report += f"Domain: {Colors.DOMAIN}{self.domain}{Colors.ENDC}\n"
        
        # Show detected nameservers
        if self.detected_nameservers:
            ns_colored = [f"{Colors.INFO}{ns}{Colors.ENDC}" for ns in self.detected_nameservers]
            report += f"Nameservers: {', '.join(ns_colored)}\n"
        
        if self.use_cloudflare:
            report += f"Protection: {Colors.HIGHLIGHT}Cloudflare (detected){Colors.ENDC}\n"
        
        if self.dns_server:
            report += f"DNS Server: {Colors.INFO}{self.dns_server}{Colors.ENDC}\n"
        
        report += f"Total subdomains found: {Colors.SUCCESS}{len(subdomain_results)}{Colors.ENDC}\n"
        report += f"Total unique IPs: {Colors.SUCCESS}{len(ip_groups)}{Colors.ENDC}\n"
        report += f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n\n"
        
        for ip, domains in sorted(ip_groups.items()):
            report += f"{Colors.IP}IP Address: {ip}{Colors.ENDC}\n"
            report += f"Subdomain count: {Colors.HIGHLIGHT}{len(domains)}{Colors.ENDC}\n"
            for domain in sorted(domains):
                report += f"  - {Colors.DOMAIN}{domain}{Colors.ENDC}\n"
            report += "\n"
            
        return report
    
    def export_json(self, subdomain_results: Dict[str, List[str]], 
                   filename: str = "subdomain_results.json"):
        """Export results to JSON file."""
        ip_groups = self.group_by_ip(subdomain_results)
        shared_ips = self.find_shared_ips(subdomain_results)
        
        output = {
            "domain": self.domain,
            "dns_server": self.dns_server,
            "resolver": "dig + OSINT",
            "total_subdomains": len(subdomain_results),
            "total_unique_ips": len(ip_groups),
            "subdomains": subdomain_results,
            "ip_groups": ip_groups,
            "shared_ips": shared_ips
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
            
        print(f"{Colors.SUCCESS}✓{Colors.ENDC} Results exported to {Colors.HIGHLIGHT}{filename}{Colors.ENDC}")


# Example usage
if __name__ == "__main__":
    # Ask user for target domain
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}Advanced Subdomain Enumerator (Sublist3r-style){Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    domain = input(f"\n{Colors.OKCYAN}Enter the target domain (e.g., example.com): {Colors.ENDC}").strip()
    
    if not domain:
        print(f"{Colors.FAIL}❌ Error: Domain cannot be empty!{Colors.ENDC}")
        sys.exit(1)
    
    # Clean domain input
    domain = domain.replace('https://', '').replace('http://', '').replace('www.', '')
    if '/' in domain:
        domain = domain.split('/')[0]
    
    print(f"\n{Colors.SUCCESS}✓ Target domain: {Colors.DOMAIN}{domain}{Colors.ENDC}")
    
    # Detect nameservers first
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}Detecting Nameservers...{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
    
    temp_resolver = DigResolver(timeout=5)
    nameservers = temp_resolver.get_nameservers(domain)
    
    if nameservers:
        print(f"{Colors.SUCCESS}✓ Detected nameservers:{Colors.ENDC}")
        for ns in nameservers:
            print(f"  - {Colors.INFO}{ns}{Colors.ENDC}")
        
        # Check if Cloudflare
        is_cloudflare = temp_resolver.is_cloudflare_ns(nameservers)
        
        if is_cloudflare:
            print(f"\n{Colors.SUCCESS}✓ Cloudflare detected! Enabling Cloudflare-optimized enumeration{Colors.ENDC}")
            cloudflare_mode = True
            dns_server = "1.1.1.1"
            print(f"{Colors.SUCCESS}✓ Using Cloudflare DNS ({Colors.IP}1.1.1.1{Colors.ENDC})")
            
            # Also try to use detected Cloudflare NS directly
            cloudflare_ns = [ns for ns in nameservers if 'cloudflare' in ns]
            if cloudflare_ns:
                # Extract IP from NS if possible or use the first CF nameserver
                print(f"{Colors.SUCCESS}✓ Will also query Cloudflare nameserver: {Colors.INFO}{cloudflare_ns[0]}{Colors.ENDC}")
        else:
            print(f"\n{Colors.SUCCESS}✓ No Cloudflare detected (standard enumeration mode){Colors.ENDC}")
            cloudflare_mode = False
            dns_server = None
            
            # Use detected nameserver for queries
            if nameservers:
                # Try to resolve the nameserver to IP
                ns_ip = temp_resolver.resolve_with_dig(nameservers[0], 'A')
                if ns_ip:
                    dns_server = ns_ip[0]
                    print(f"{Colors.SUCCESS}✓ Using detected nameserver: {Colors.INFO}{nameservers[0]}{Colors.ENDC} ({Colors.IP}{dns_server}{Colors.ENDC})")
    else:
        print(f"{Colors.WARNING}⚠ Could not detect nameservers, using system default{Colors.ENDC}")
        cloudflare_mode = False
        dns_server = None
        nameservers = []
    
    # Ask if user wants to override DNS server
    override_dns = input(f"\n{Colors.OKCYAN}Override DNS server? (y/n, default=n): {Colors.ENDC}").strip().lower()
    
    if override_dns in ['y', 'yes']:
        print(f"\n{Colors.INFO}Common DNS servers:{Colors.ENDC}")
        print("  1. Google DNS (8.8.8.8)")
        print("  2. Cloudflare DNS (1.1.1.1)")
        print("  3. Custom")
        dns_choice = input(f"\n{Colors.OKCYAN}Choose option (1-3, or press Enter for system default): {Colors.ENDC}").strip()
        
        if dns_choice == '1':
            dns_server = "8.8.8.8"
            print(f"{Colors.SUCCESS}✓ Using Google DNS: {dns_server}{Colors.ENDC}")
        elif dns_choice == '2':
            dns_server = "1.1.1.1"
            print(f"{Colors.SUCCESS}✓ Using Cloudflare DNS: {dns_server}{Colors.ENDC}")
        elif dns_choice == '3':
            dns_server = input(f"{Colors.OKCYAN}Enter custom DNS server IP: {Colors.ENDC}").strip()
            print(f"{Colors.SUCCESS}✓ Using custom DNS: {dns_server}{Colors.ENDC}")
        else:
            print(f"{Colors.SUCCESS}✓ Using system default DNS{Colors.ENDC}")
    else:
        print(f"{Colors.SUCCESS}✓ Using system default DNS{Colors.ENDC}")
    
    # Ask about enumeration method
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}Enumeration Options:{Colors.ENDC}")
    print("  1. OSINT only (fast, passive)")
    print("  2. OSINT + Brute force (comprehensive)")
    print("  3. Brute force only (wordlist)")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    method = input(f"\n{Colors.OKCYAN}Choose method (1-3, default=2): {Colors.ENDC}").strip() or "2"
    
    # Common subdomain wordlist for brute force (default/built-in)
    common_wordlist = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "admin", "api", "blog", "dev", "stage", "staging", "test", "portal", "cdn", 
        "shop", "store", "app", "mobile", "m", "vpn", "support", "help", "docs", 
        "status", "git", "secure", "my", "remote", "server", "host", "beta", "cloud",
        "ftp2", "ns3", "mx", "email", "direct", "cpanel", "forum", "search", "dns",
        "intranet", "web", "bbs", "demo", "news", "mysql", "backup", "old", "new",
        # Additional Cloudflare-common subdomains
        "assets", "static", "media", "images", "img", "files", "uploads", "downloads",
        "api-gateway", "gateway", "proxy", "lb", "balancer", "edge", "node", 
        "client", "customer", "partner", "vendor", "internal", "external",
        "dashboard", "console", "manage", "control", "monitor", "analytics",
        "ws", "websocket", "socket", "realtime", "live", "stream", "broadcast"
    ]
    
    # Ask if user wants to use custom wordlist
    if method in ["2", "3"]:
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Wordlist Options:{Colors.ENDC}")
        print(f"  1. Use built-in wordlist ({len(common_wordlist)} subdomains)")
        print("  2. Load from local file")
        print("  3. Load from URL")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        wordlist_choice = input(f"\n{Colors.OKCYAN}Choose wordlist source (1-3, default=1): {Colors.ENDC}").strip() or "1"
        
        if wordlist_choice == "2":
            # Load from local file
            wordlist_path = input(f"{Colors.OKCYAN}Enter path to wordlist file: {Colors.ENDC}").strip()
            try:
                with open(wordlist_path, 'r') as f:
                    common_wordlist = [line.strip() for line in f if line.strip()]
                print(f"{Colors.SUCCESS}✓ Loaded {len(common_wordlist)} words from {wordlist_path}{Colors.ENDC}")
            except FileNotFoundError:
                print(f"{Colors.ERROR}✗ File not found! Using built-in wordlist.{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.ERROR}✗ Error reading file: {e}. Using built-in wordlist.{Colors.ENDC}")
        
        elif wordlist_choice == "3":
            # Load from URL
            # example URL
            print(f"{Colors.INFO}**Popular subdomain wordlists:**{Colors.ENDC}")
            print(f"{Colors.INFO}https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt{Colors.ENDC}")
            print(f"{Colors.INFO}https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt{Colors.ENDC}")
            print(f"{Colors.INFO}https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/fierce-hostlist.txt{Colors.ENDC}")

            wordlist_url = input(f"{Colors.OKCYAN}Enter URL to wordlist: {Colors.ENDC}").strip()
            try:
                print(f"{Colors.INFO}[*] Downloading wordlist...{Colors.ENDC}")
                response = requests.get(wordlist_url, timeout=30)
                if response.status_code == 200:
                    common_wordlist = [line.strip() for line in response.text.split('\n') if line.strip()]
                    print(f"{Colors.SUCCESS}✓ Loaded {len(common_wordlist)} words from URL{Colors.ENDC}")
                else:
                    print(f"{Colors.ERROR}✗ Failed to download (HTTP {response.status_code}). Using built-in wordlist.{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.ERROR}✗ Error downloading: {e}. Using built-in wordlist.{Colors.ENDC}")
        else:
            print(f"{Colors.SUCCESS}✓ Using built-in wordlist ({len(common_wordlist)} subdomains){Colors.ENDC}")
    
    # Initialize enumerator
    enumerator = SubdomainEnumerator(
        domain, 
        timeout=5, 
        max_workers=50,
        dns_server=dns_server,
        use_cloudflare=cloudflare_mode,
        detected_nameservers=nameservers
    )
    
    print(f"\n{Colors.INFO}Starting deep enumeration for {Colors.DOMAIN}{domain}{Colors.ENDC}...")
    
    # Run enumeration based on chosen method
    if method == "1":
        # OSINT only
        results = enumerator.enumerate_deep(use_osint=True, use_bruteforce=False)
    elif method == "3":
        # Brute force only
        results = enumerator.bruteforce_subdomains(common_wordlist)
    else:
        # OSINT + Brute force (default)
        results = enumerator.enumerate_deep(
            use_osint=True, 
            use_bruteforce=True, 
            wordlist=common_wordlist
        )
    
    # Display results
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}Enumeration Complete!{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.SUCCESS}Found {Colors.HIGHLIGHT}{len(results)}{Colors.ENDC}{Colors.SUCCESS} active subdomains{Colors.ENDC}\n")
    
    # Show all results
    print(enumerator.generate_report(results, include_shared_only=False))
    
    # Show shared IPs
    shared_ips = enumerator.find_shared_ips(results)
    if shared_ips:
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}SUBDOMAINS SHARING IP ADDRESSES{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        for ip, domains in shared_ips.items():
            print(f"\n{Colors.IP}{ip}{Colors.ENDC} is shared by {Colors.HIGHLIGHT}{len(domains)}{Colors.ENDC} subdomains:")
            for domain_name in domains:
                print(f"  - {Colors.DOMAIN}{domain_name}{Colors.ENDC}")
    
    # Export to JSON
    enumerator.export_json(results, f"{domain}_deep_results.json")
    
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.SUCCESS}✓ Enumeration finished successfully!{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
