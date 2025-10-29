#!/usr/bin/env python3
"""
Advanced Subdomain Enumerator - Inspired by Sublist3r
Combines DNS resolution with multiple OSINT sources for deep subdomain discovery

Author: Sir Jimbet
Version: 3.3.5
Features: dnspython + OSINT + Brute Force + Color Output + Free SSL + TOR/Proxy Support
"""

import concurrent.futures
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
import json
import sys
import requests
import time
import warnings
import dns.resolver
import dns.exception
import random

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

    def __init__(self, domain: str, timeout: int = 20):
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
            import re
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
            "us", "eu", "asia", "uk", "de", "fr", "au", "ca", "jp", "my", "sg", "id", "th", "ph", "ng", "in",
            # Service patterns    
            "assets", "static", "media", "images", "img", "cdn", "cdn1", "cdn2",
            "files", "uploads", "downloads", "storage",
            # API patterns
            "api", "api1", "api2", "rest", "graphql", "ws", "websocket", "vless", "vmess", "trojan",
            # Application patterns
            "app", "webapp", "web", "portal", "dashboard", "admin", "panel",
            # Environment patterns
            "prod", "production", "staging", "stage", "dev", "development", "test", "st",
            # Load balancer patterns
            "lb", "lb1", "lb2", "loadbalancer",
            # Worker patterns (Cloudflare Workers)
            "workers", "worker", "edge",
            # Pages patterns (Cloudflare Pages)
            "pages", "preview",
            # Stream patterns
            "stream", "video", "live",
            # Other pattern
            "xyz", "at", "ly", "ee", "iptv", "info", "biz", "pro", "nat", "proxy",
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


class ProxyManager:
    """
    Proxy and TOR management for anonymous OSINT operations.
    """
    
    def __init__(self, use_tor: bool = False, proxy_list: Optional[List[str]] = None, 
                 rotate_proxy: bool = False):
        self.use_tor = use_tor
        self.proxy_list = proxy_list or []
        self.rotate_proxy = rotate_proxy
        self.current_proxy_index = 0
        self.tor_available = False
        
        if use_tor:
            self.tor_available = self._check_tor_connection()
    
    def _check_tor_connection(self) -> bool:
        """Check if TOR is running on default SOCKS port"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9050))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_proxy_config(self) -> Optional[Dict[str, str]]:
        """Get current proxy configuration"""
        if self.use_tor and self.tor_available:
            return {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
        elif self.proxy_list and len(self.proxy_list) > 0:
            if self.rotate_proxy:
                # Rotate through proxy list
                proxy = self.proxy_list[self.current_proxy_index]
                self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
            else:
                proxy = self.proxy_list[0]
            
            return {
                'http': proxy,
                'https': proxy
            }
        return None
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent for better anonymity"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]
        import random
        return random.choice(user_agents)
    
    def test_tor_connection(self) -> bool:
        """Test if TOR is working by checking IP"""
        try:
            import requests
            session = requests.Session()
            session.proxies = self.get_proxy_config()
            response = session.get('https://check.torproject.org/api/ip', timeout=20)
            data = response.json()
            return data.get('IsTor', False)
        except:
            return False


class OSINTEnumerator:
    """
    OSINT-based subdomain discovery using multiple public sources.
    """
    
    def __init__(self, domain: str, timeout: int = 10, verbose: bool = False, 
                 proxy_manager: Optional[ProxyManager] = None, max_retries: int = 2):
        self.domain = domain
        self.timeout = timeout
        self.verbose = verbose
        self.proxy_manager = proxy_manager
        self.max_retries = max_retries
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session with proxy support"""
        session = requests.Session()
        
        # Set user agent
        if self.proxy_manager:
            user_agent = self.proxy_manager.get_random_user_agent()
        else:
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        
        session.headers.update({'User-Agent': user_agent})
        
        # Configure proxy if available
        if self.proxy_manager:
            proxies = self.proxy_manager.get_proxy_config()
            if proxies:
                session.proxies.update(proxies)
                if self.verbose:
                    if self.proxy_manager.use_tor:
                        print(f"      {Colors.INFO}[i]{Colors.ENDC} Using TOR network")
                    else:
                        print(f"      {Colors.INFO}[i]{Colors.ENDC} Using proxy: {list(proxies.values())[0]}")
        
        # Add retries for failed requests
        from requests.adapters import HTTPAdapter
        try:
            from urllib3.util.retry import Retry
            
            retry_strategy = Retry(
                total=self.max_retries,
                backoff_factor=2,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
        except ImportError:
            # urllib3 might not have Retry in older versions
            pass
        
        return session
    
    def _get_with_retry(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make request with proxy rotation on failure"""
        # Set a longer timeout for slow services
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
        
        if not self.proxy_manager or not self.proxy_manager.rotate_proxy:
            # Single attempt with current proxy/direct connection
            for attempt in range(self.max_retries):
                try:
                    response = self.session.get(url, **kwargs)
                    if response.status_code == 200:
                        return response
                    elif response.status_code == 429:  # Rate limited
                        if self.verbose:
                            print(f"      {Colors.WARNING}[!]{Colors.ENDC} Rate limited, waiting...")
                        time.sleep(3 * (attempt + 1))
                        continue
                except requests.exceptions.Timeout:
                    if attempt < self.max_retries - 1 and self.verbose:
                        print(f"      {Colors.WARNING}[!]{Colors.ENDC} Timeout, retrying... ({attempt + 1}/{self.max_retries})")
                    time.sleep(2)
                    continue
                except Exception:
                    if attempt < self.max_retries - 1:
                        time.sleep(1)
                        continue
            return None
        
        # Try with different proxies if rotation is enabled
        max_attempts = min(self.max_retries, len(self.proxy_manager.proxy_list)) if self.proxy_manager.proxy_list else self.max_retries
        
        for attempt in range(max_attempts):
            try:
                # Rotate proxy for each attempt
                proxies = self.proxy_manager.get_proxy_config()
                if proxies:
                    self.session.proxies.update(proxies)
                
                response = self.session.get(url, **kwargs)
                if response.status_code == 200:
                    return response
            except Exception as e:
                if self.verbose and attempt < max_attempts - 1:
                    print(f"      {Colors.WARNING}[!]{Colors.ENDC} Proxy failed, rotating...")
                continue
        
        return None
    
    def search_crtsh(self) -> Set[str]:
        """Search Certificate Transparency logs via crt.sh"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching crt.sh (SSL Certificates)...")
        subdomains = set()
        
        try:
            # crt.sh is often slow, use longer timeout
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self._get_with_retry(url, timeout=60)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip().replace('*.', '')
                            if subdomain.endswith(self.domain) and subdomain:
                                subdomains.add(subdomain)
                    
                    print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from crt.sh")
                except json.JSONDecodeError:
                    if self.verbose:
                        print(f"      {Colors.ERROR}✗{Colors.ENDC} crt.sh returned invalid JSON")
            else:
                if self.verbose:
                    status = response.status_code if response else 'No response'
                    print(f"      {Colors.ERROR}✗{Colors.ENDC} crt.sh returned status {status}")
                else:
                    print(f"      {Colors.ERROR}✗{Colors.ENDC} crt.sh unavailable (skipped)")
        except requests.exceptions.Timeout:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} crt.sh timed out (very slow/overloaded)")
        except Exception as e:
            if self.verbose:
                print(f"      {Colors.ERROR}✗{Colors.ENDC} crt.sh error: {str(e)}")
            else:
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
            response = self._get_with_retry(url, timeout=60, verify=False)
            
            if response and response.status_code == 200:
                data = response.json()
                subs = data.get('subdomains', [])
                for subdomain in subs:
                    if subdomain and subdomain.endswith(self.domain):
                        subdomains.add(subdomain)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from ThreatCrowd")
            else:
                if self.verbose:
                    status = response.status_code if response else 'No response'
                    print(f"      {Colors.ERROR}✗{Colors.ENDC} ThreatCrowd returned status {status}")
                else:
                    print(f"      {Colors.ERROR}✗{Colors.ENDC} ThreatCrowd unavailable (skipped)")
        except requests.exceptions.Timeout:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} ThreatCrowd timed out (very slow)")
        except Exception as e:
            if self.verbose:
                print(f"      {Colors.ERROR}✗{Colors.ENDC} ThreatCrowd error: {str(e)}")
            else:
                print(f"      {Colors.ERROR}✗{Colors.ENDC} ThreatCrowd unavailable (skipped)")
        
        return subdomains
    
    def search_alienvault(self) -> Set[str]:
        """Search AlienVault OTX"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching AlienVault OTX...")
        subdomains = set()
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = self._get_with_retry(url, timeout=60)
            
            if response and response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if hostname and hostname.endswith(self.domain):
                        subdomains.add(hostname)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from AlienVault")
            else:
                if self.verbose:
                    status = response.status_code if response else 'No response'
                    print(f"      {Colors.ERROR}✗{Colors.ENDC} AlienVault returned status {status}")
                else:
                    print(f"      {Colors.ERROR}✗{Colors.ENDC} AlienVault unavailable (skipped)")
        except requests.exceptions.Timeout:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} AlienVault timed out (very slow)")
        except Exception as e:
            if self.verbose:
                print(f"      {Colors.ERROR}✗{Colors.ENDC} AlienVault error: {str(e)}")
            else:
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
            import re
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
    
    def search_letsencrypt_crt(self) -> Set[str]:
        """Search Let's Encrypt certificates via crt.sh (filtered by CA)"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching Let's Encrypt certificates...")
        subdomains = set()
        
        try:
            # Search for Let's Encrypt issued certificates
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    # Check if issued by Let's Encrypt
                    issuer = entry.get('issuer_name', '').lower()
                    if "let's encrypt" in issuer or 'letsencrypt' in issuer:
                        name = entry.get('name_value', '')
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip().replace('*.', '')
                            if subdomain.endswith(self.domain) and subdomain:
                                subdomains.add(subdomain)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from Let's Encrypt")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} Let's Encrypt search unavailable (skipped)")
        
        return subdomains
    
    def search_zerossl_crt(self) -> Set[str]:
        """Search ZeroSSL certificates via crt.sh (filtered by CA)"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching ZeroSSL certificates...")
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    # Check if issued by ZeroSSL
                    issuer = entry.get('issuer_name', '').lower()
                    if 'zerossl' in issuer or 'sectigo' in issuer:
                        name = entry.get('name_value', '')
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip().replace('*.', '')
                            if subdomain.endswith(self.domain) and subdomain:
                                subdomains.add(subdomain)
                
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from ZeroSSL")
        except Exception as e:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} ZeroSSL search unavailable (skipped)")
        
        return subdomains
    
    def search_free_ssl_providers(self) -> Set[str]:
        """Search certificates from all major free SSL providers"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching Free SSL Providers (Let's Encrypt, ZeroSSL, etc.)...")
        subdomains = set()
        
        try:
            # Use longer timeout for crt.sh
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self._get_with_retry(url, timeout=60)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    
                    # Track stats for each provider
                    providers_count = defaultdict(int)
                    
                    for entry in data:
                        issuer = entry.get('issuer_name', '').lower()
                        
                        # Check for various free SSL providers
                        is_free_ssl = False
                        provider_name = "Unknown"
                        
                        if "let's encrypt" in issuer or 'letsencrypt' in issuer or 'r3' in issuer or 'e1' in issuer:
                            is_free_ssl = True
                            provider_name = "Let's Encrypt"
                        elif 'zerossl' in issuer:
                            is_free_ssl = True
                            provider_name = "ZeroSSL"
                        elif 'sectigo' in issuer and 'sectigo limited' in issuer:
                            # Sectigo powers ZeroSSL
                            is_free_ssl = True
                            provider_name = "ZeroSSL/Sectigo"
                        elif 'buypass' in issuer:
                            is_free_ssl = True
                            provider_name = "Buypass"
                        elif 'ssl.com' in issuer:
                            is_free_ssl = True
                            provider_name = "SSL.com"
                        elif 'google trust services' in issuer or 'gts' in issuer:
                            is_free_ssl = True
                            provider_name = "Google Trust"
                        
                        if is_free_ssl:
                            name = entry.get('name_value', '')
                            for subdomain in name.split('\n'):
                                subdomain = subdomain.strip().replace('*.', '')
                                if subdomain.endswith(self.domain) and subdomain:
                                    subdomains.add(subdomain)
                                    providers_count[provider_name] += 1
                    
                    # Print breakdown by provider
                    if providers_count:
                        print(f"      {Colors.SUCCESS}✓{Colors.ENDC} Found {Colors.HIGHLIGHT}{len(subdomains)}{Colors.ENDC} subdomains from free SSL providers:")
                        for provider, count in sorted(providers_count.items(), key=lambda x: x[1], reverse=True):
                            print(f"        - {Colors.INFO}{provider}{Colors.ENDC}: {count} certificates")
                    else:
                        print(f"      {Colors.WARNING}⚠{Colors.ENDC} No free SSL certificates found for this domain")
                except json.JSONDecodeError:
                    if self.verbose:
                        print(f"      {Colors.ERROR}✗{Colors.ENDC} Free SSL providers returned invalid JSON")
                    else:
                        print(f"      {Colors.ERROR}✗{Colors.ENDC} Free SSL providers unavailable (skipped)")
            else:
                if self.verbose:
                    status = response.status_code if response else 'No response'
                    print(f"      {Colors.ERROR}✗{Colors.ENDC} Free SSL providers returned status {status}")
                else:
                    print(f"      {Colors.ERROR}✗{Colors.ENDC} Free SSL providers unavailable (skipped)")
        except requests.exceptions.Timeout:
            print(f"      {Colors.ERROR}✗{Colors.ENDC} Free SSL providers timed out (very slow/overloaded)")
        except Exception as e:
            if self.verbose:
                print(f"      {Colors.ERROR}✗{Colors.ENDC} Free SSL providers error: {str(e)}")
            else:
                print(f"      {Colors.ERROR}✗{Colors.ENDC} Free SSL providers unavailable (skipped)")
        
        return subdomains
    
    def search_wayback(self) -> Set[str]:
        """Search Wayback Machine"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching Wayback Machine...")
        subdomains = set()
        
        try:
            import re
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
    
    def search_dnsdumpster(self) -> Set[str]:
        """Search DNSDumpster"""
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Searching DNSDumpster...")
        subdomains = set()
        
        try:
            import re
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
        print(f"{Colors.INFO}Note: Some sources may be slow (crt.sh often takes 20-30s){Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        all_subdomains = set()
        
        sources = [
            self.search_crtsh,
            self.search_free_ssl_providers,  # Searches Let's Encrypt, ZeroSSL, etc.
            self.search_hackertarget,
            self.search_threatcrowd,
            self.search_alienvault,
            self.search_urlscan,
            self.search_rapiddns,
            self.search_anubis,
            self.search_certspotter,
            self.search_wayback,
            self.search_dnsdumpster
        ]
        
        for source in sources:
            try:
                results = source()
                all_subdomains.update(results)
                time.sleep(0.5)  # Reduced delay between sources
            except Exception as e:
                pass
        
        print(f"\n  {Colors.SUCCESS}✓{Colors.ENDC} Total unique subdomains from OSINT: {Colors.HIGHLIGHT}{len(all_subdomains)}{Colors.ENDC}\n")
        return all_subdomains


class DNSResolver:
    """
    DNS resolver using dnspython library with Cloudflare optimization.
    """
    
    def __init__(self, timeout: int = 5, dns_server: Optional[str] = None, use_cloudflare: bool = False):
        self.timeout = timeout
        self.dns_server = dns_server
        self.use_cloudflare = use_cloudflare
        
        # Create resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # If Cloudflare mode, use their DNS servers
        if self.use_cloudflare and not self.dns_server:
            self.dns_server = "1.1.1.1"  # Cloudflare DNS
        
        # Configure custom DNS server if provided
        if self.dns_server:
            self.resolver.nameservers = [self.dns_server]
    
    def get_nameservers(self, domain: str) -> List[str]:
        """Get nameservers for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'NS')
            nameservers = []
            for rdata in answers:
                ns = str(rdata.target).rstrip('.')
                if ns:
                    nameservers.append(ns.lower())
            return nameservers
        except Exception:
            return []
    
    def get_mx_records(self, domain: str) -> List[Dict[str, any]]:
        """Get MX (Mail Exchange) records for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_records = []
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'host': str(rdata.exchange).rstrip('.')
                })
            return sorted(mx_records, key=lambda x: x['priority'])
        except Exception:
            return []
    
    def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            txt_records = []
            for rdata in answers:
                # TXT records are returned as quoted strings, join them
                txt_data = ' '.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                txt_records.append(txt_data)
            return txt_records
        except Exception:
            return []
    
    def get_soa_record(self, domain: str) -> Optional[Dict[str, any]]:
        """Get SOA (Start of Authority) record for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'SOA')
            for rdata in answers:
                return {
                    'mname': str(rdata.mname).rstrip('.'),
                    'rname': str(rdata.rname).rstrip('.'),
                    'serial': rdata.serial,
                    'refresh': rdata.refresh,
                    'retry': rdata.retry,
                    'expire': rdata.expire,
                    'minimum': rdata.minimum
                }
        except Exception:
            return None
    
    def get_spf_record(self, domain: str) -> Optional[str]:
        """Get SPF (Sender Policy Framework) record from TXT records"""
        txt_records = self.get_txt_records(domain)
        for record in txt_records:
            if record.startswith('v=spf1'):
                return record
        return None
    
    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """Get DMARC (Domain-based Message Authentication) record"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = self.get_txt_records(dmarc_domain)
            for record in txt_records:
                if record.startswith('v=DMARC1'):
                    return record
        except Exception:
            pass
        return None
    
    def get_dkim_record(self, domain: str, selector: str = "default") -> Optional[str]:
        """Get DKIM (DomainKeys Identified Mail) record"""
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            txt_records = self.get_txt_records(dkim_domain)
            for record in txt_records:
                if 'v=DKIM1' in record or 'p=' in record:
                    return record
        except Exception:
            pass
        return None
    
    def get_caa_records(self, domain: str) -> List[Dict[str, any]]:
        """Get CAA (Certificate Authority Authorization) records"""
        try:
            answers = self.resolver.resolve(domain, 'CAA')
            caa_records = []
            for rdata in answers:
                caa_records.append({
                    'flags': rdata.flags,
                    'tag': rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag,
                    'value': rdata.value.decode() if isinstance(rdata.value, bytes) else rdata.value
                })
            return caa_records
        except Exception:
            return []
    
    def get_srv_records(self, domain: str, service: str = "_http._tcp") -> List[Dict[str, any]]:
        """Get SRV (Service) records"""
        try:
            srv_domain = f"{service}.{domain}"
            answers = self.resolver.resolve(srv_domain, 'SRV')
            srv_records = []
            for rdata in answers:
                srv_records.append({
                    'priority': rdata.priority,
                    'weight': rdata.weight,
                    'port': rdata.port,
                    'target': str(rdata.target).rstrip('.')
                })
            return srv_records
        except Exception:
            return []
    
    def get_ptr_record(self, ip: str) -> Optional[str]:
        """Get PTR (Pointer/Reverse DNS) record for an IP"""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            ptr = dns.reversename.from_address(str(addr))
            answers = self.resolver.resolve(ptr, 'PTR')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except Exception:
            return None
    
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
    
    def resolve(self, domain: str, record_type: str = 'A') -> List[str]:
        """Resolve domain using dnspython"""
        try:
            answers = self.resolver.resolve(domain, record_type)
            addresses = []
            
            for rdata in answers:
                if record_type == 'A':
                    addresses.append(str(rdata))
                elif record_type == 'AAAA':
                    addresses.append(str(rdata))
                elif record_type == 'CNAME':
                    addresses.append(str(rdata.target).rstrip('.'))
                else:
                    addresses.append(str(rdata))
            
            return addresses
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception:
            return []
    
    def check_cname_chain(self, domain: str) -> List[str]:
        """Follow CNAME chain to discover additional subdomains (useful for Cloudflare)"""
        cnames = []
        current = domain
        max_depth = 10
        depth = 0
        
        while depth < max_depth:
            result = self.resolve(current, 'CNAME')
            if result:
                cname = result[0]
                cnames.append(cname)
                current = cname
                depth += 1
            else:
                break
        
        return cnames
    
    def get_comprehensive_dns_info(self, domain: str) -> Dict[str, any]:
        """Get comprehensive DNS information for a domain"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Comprehensive DNS Information for {Colors.DOMAIN}{domain}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        dns_info = {
            'domain': domain,
            'nameservers': [],
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'txt_records': [],
            'soa_record': None,
            'spf_record': None,
            'dmarc_record': None,
            'caa_records': [],
            'srv_records': []
        }
        
        # Get A records
        print(f"  {Colors.INFO}[*]{Colors.ENDC} Querying A records...")
        a_records = self.resolve(domain, 'A')
        if a_records:
            dns_info['a_records'] = a_records
            for ip in a_records:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} A: {Colors.IP}{ip}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠{Colors.ENDC} No A records found")
        
        # Get AAAA records (IPv6)
        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying AAAA records (IPv6)...")
        aaaa_records = self.resolve(domain, 'AAAA')
        if aaaa_records:
            dns_info['aaaa_records'] = aaaa_records
            for ip in aaaa_records:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} AAAA: {Colors.IP}{ip}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠{Colors.ENDC} No AAAA records found")
        
        # Get Nameservers
        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying NS records...")
        nameservers = self.get_nameservers(domain)
        if nameservers:
            dns_info['nameservers'] = nameservers
            for ns in nameservers:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} NS: {Colors.INFO}{ns}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠{Colors.ENDC} No NS records found")
        
        # Get MX records
        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying MX records...")
        mx_records = self.get_mx_records(domain)
        if mx_records:
            dns_info['mx_records'] = mx_records
            for mx in mx_records:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} MX: {Colors.HIGHLIGHT}{mx['priority']}{Colors.ENDC} {Colors.DOMAIN}{mx['host']}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠{Colors.ENDC} No MX records found")
        
        # Get TXT records
        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying TXT records...")
        txt_records = self.get_txt_records(domain)
        if txt_records:
            dns_info['txt_records'] = txt_records
            for i, txt in enumerate(txt_records, 1):
                # Truncate long records for display
                display_txt = txt if len(txt) <= 80 else txt[:77] + "..."
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} TXT[{i}]: {Colors.INFO}{display_txt}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠{Colors.ENDC} No TXT records found")
        
        # Get SOA record
        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying SOA record...")
        soa_record = self.get_soa_record(domain)
        if soa_record:
            dns_info['soa_record'] = soa_record
            print(f"      {Colors.SUCCESS}✓{Colors.ENDC} SOA:")
            print(f"        Primary NS: {Colors.INFO}{soa_record['mname']}{Colors.ENDC}")
            print(f"        Admin Email: {Colors.INFO}{soa_record['rname']}{Colors.ENDC}")
            print(f"        Serial: {Colors.HIGHLIGHT}{soa_record['serial']}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠{Colors.ENDC} No SOA record found")
        
        # Get SPF record
        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Checking SPF record...")
        spf_record = self.get_spf_record(domain)
        if spf_record:
            dns_info['spf_record'] = spf_record
            display_spf = spf_record if len(spf_record) <= 80 else spf_record[:77] + "..."
            print(f"      {Colors.SUCCESS}✓{Colors.ENDC} SPF: {Colors.INFO}{display_spf}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠{Colors.ENDC} No SPF record found")
        
        # Get DMARC record
        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Checking DMARC record...")
        dmarc_record = self.get_dmarc_record(domain)
        if dmarc_record:
            dns_info['dmarc_record'] = dmarc_record
            display_dmarc = dmarc_record if len(dmarc_record) <= 80 else dmarc_record[:77] + "..."
            print(f"      {Colors.SUCCESS}✓{Colors.ENDC} DMARC: {Colors.INFO}{display_dmarc}{Colors.ENDC}")
        else:
            print(f"      {Colors.WARNING}⚠{Colors.ENDC} No DMARC record found")
        
        # Get CAA records
        print(f"\n  {Colors.INFO}[*]{Colors.ENDC} Querying CAA records...")
        caa_records = self.get_caa_records(domain)
        if caa_records:
            dns_info['caa_records'] = caa_records
            for caa in caa_records:
                print(f"      {Colors.SUCCESS}✓{Colors.ENDC} CAA: {Colors.HIGHLIGHT}{caa['tag']}{Colors.ENDC} \"{Colors.INFO}{caa['value']}{Colors.ENDC}\"")
        else:
            print(f"      {Colors.WARNING}⚠{Colors.ENDC} No CAA records found")
        
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        return dns_info


class SubdomainEnumerator:
    """
    Advanced subdomain enumerator combining OSINT + DNS verification with dnspython.
    Includes automatic Cloudflare detection and optimization.
    """
    
    def __init__(self, domain: str, timeout: int = 5, max_workers: int = 30, 
                 dns_server: Optional[str] = None, use_cloudflare: bool = False,
                 detected_nameservers: Optional[List[str]] = None, verbose: bool = False,
                 proxy_manager: Optional[ProxyManager] = None):
        self.domain = domain
        self.timeout = timeout
        self.max_workers = max_workers
        self.use_cloudflare = use_cloudflare
        self.detected_nameservers = detected_nameservers or []
        self.verbose = verbose
        self.proxy_manager = proxy_manager
        self.dns_resolver = DNSResolver(timeout=timeout, dns_server=dns_server, use_cloudflare=use_cloudflare)
        self.osint_enum = OSINTEnumerator(domain, timeout=30, verbose=verbose, proxy_manager=proxy_manager)
        self.cloudflare_enum = CloudflareEnumerator(domain, timeout=30) if use_cloudflare else None
        self.dns_server = dns_server or (self.dns_resolver.dns_server if use_cloudflare else None)
    
    def resolve_subdomain(self, subdomain: str) -> Tuple[str, List[str], List[str]]:
        """Resolve a subdomain to its IPv4 addresses using dnspython."""
        ipv4_addresses = self.dns_resolver.resolve(subdomain, 'A')
        
        # For Cloudflare sites, also check CNAME chains
        cnames = []
        if self.use_cloudflare:
            cnames = self.dns_resolver.check_cname_chain(subdomain)
        
        return subdomain, ipv4_addresses, cnames
    
    def verify_subdomains(self, subdomains: Set[str], show_progress: bool = True) -> Dict[str, List[str]]:
        """Verify discovered subdomains using dnspython."""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Verifying {len(subdomains)} subdomains with DNS{Colors.ENDC}")
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
            additional_results = self.verify_subdomains(discovered_from_cnames, show_progress=False)
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
        
        return self.verify_subdomains(set(subdomains), show_progress)
    
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
        
        # Step 4: Verify all discovered subdomains with DNS
        if all_subdomains:
            verified = self.verify_subdomains(all_subdomains, show_progress=True)
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
                   filename: str = "subdomain_results.json", 
                   dns_info: Optional[Dict[str, any]] = None):
        """Export results to JSON file."""
        ip_groups = self.group_by_ip(subdomain_results)
        shared_ips = self.find_shared_ips(subdomain_results)
        
        output = {
            "domain": self.domain,
            "dns_server": self.dns_server,
            "resolver": "dnspython + OSINT",
            "total_subdomains": len(subdomain_results),
            "total_unique_ips": len(ip_groups),
            "subdomains": subdomain_results,
            "ip_groups": ip_groups,
            "shared_ips": shared_ips
        }
        
        # Add DNS info if provided
        if dns_info:
            output["dns_info"] = dns_info
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
            
        print(f"{Colors.SUCCESS}✓{Colors.ENDC} Results exported to {Colors.HIGHLIGHT}{filename}{Colors.ENDC}")


# Example usage
if __name__ == "__main__":
    # Ask user for target domain
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Advanced Subdomain Enumerator (Sir Jimbet v3.3.5){Colors.ENDC}")
    print(f"{Colors.HEADER}Using dnspython for cross-platform DNS resolution, OSINT, TOR/Proxy{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    
    domain = input(f"\n{Colors.OKCYAN}Enter the target domain (e.g., example.com): {Colors.ENDC}").strip()
    
    if not domain:
        print(f"{Colors.FAIL}❌ Error: Domain cannot be empty!{Colors.ENDC}")
        sys.exit(1)
    
    # Clean domain input
    domain = domain.replace('https://', '').replace('http://', '').replace('www.', '')
    if '/' in domain:
        domain = domain.split('/')[0]
    
    print(f"\n{Colors.SUCCESS}✓ Target domain: {Colors.DOMAIN}{domain}{Colors.ENDC}")
    
    # Ask if user wants comprehensive DNS info first
    dns_info_choice = input(f"\n{Colors.OKCYAN}Show comprehensive DNS information? (y/n, default=y): {Colors.ENDC}").strip().lower()
    
    if dns_info_choice != 'n':
        temp_resolver = DNSResolver(timeout=5)
        dns_info = temp_resolver.get_comprehensive_dns_info(domain)
    
    # Detect nameservers first
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}Detecting Nameservers...{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
    
    temp_resolver = DNSResolver(timeout=20)
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
                print(f"{Colors.SUCCESS}✓ Will also query Cloudflare nameserver: {Colors.INFO}{cloudflare_ns[0]}{Colors.ENDC}")
        else:
            print(f"\n{Colors.SUCCESS}✓ No Cloudflare detected (standard enumeration mode){Colors.ENDC}")
            cloudflare_mode = False
            dns_server = None
            
            # Use detected nameserver for queries
            if nameservers:
                # Try to resolve the nameserver to IP
                ns_ip = temp_resolver.resolve(nameservers[0], 'A')
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
        "ws", "websocket", "vless", "vmess", "socket", "realtime", "live", "stream", "broadcast"
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
            print(f"{Colors.INFO}Popular subdomain wordlists (copy-paste):{Colors.ENDC}")
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
    
    # Ask if user wants verbose output
    verbose_choice = input(f"\n{Colors.OKCYAN}Enable verbose error messages? (y/n, default=n): {Colors.ENDC}").strip().lower()
    verbose_mode = verbose_choice in ['y', 'yes']
    
    # Ask about proxy/TOR usage
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}Anonymity & Proxy Options{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print("  1. No proxy (direct connection)")
    print("  2. Use TOR network (requires TOR service running)")
    print("  3. Use custom proxy/proxies")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    proxy_choice = input(f"\n{Colors.OKCYAN}Choose option (1-3, default=1): {Colors.ENDC}").strip() or "1"
    
    proxy_manager = None
    
    if proxy_choice == "2":
        # TOR setup
        print(f"\n{Colors.INFO}[*] Checking TOR connection...{Colors.ENDC}")
        proxy_manager = ProxyManager(use_tor=True)
        
        if proxy_manager.tor_available:
            print(f"{Colors.SUCCESS}✓ TOR is running on 127.0.0.1:9050{Colors.ENDC}")
            
            # Test TOR connection
            print(f"{Colors.INFO}[*] Testing TOR connection...{Colors.ENDC}")
            if proxy_manager.test_tor_connection():
                print(f"{Colors.SUCCESS}✓ Successfully connected through TOR network!{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}⚠ TOR is running but connection test failed{Colors.ENDC}")
        else:
            print(f"{Colors.ERROR}✗ TOR is not running!{Colors.ENDC}")
            print(f"\n{Colors.INFO}To use TOR:{Colors.ENDC}")
            print("  - Windows: Download TOR Browser from torproject.org")
            print("  - Linux: sudo apt install tor && sudo systemctl start tor")
            print("  - macOS: brew install tor && brew services start tor")
            print(f"\n{Colors.WARNING}Continuing without TOR...{Colors.ENDC}")
            proxy_manager = None
    
    elif proxy_choice == "3":
        # Custom proxy setup
        print(f"\n{Colors.INFO}Proxy format examples:{Colors.ENDC}")
        print("  - HTTP: http://proxy.example.com:8080")
        print("  - HTTPS: https://proxy.example.com:8080")
        print("  - SOCKS5: socks5://proxy.example.com:1080")
        print("  - With auth: http://user:pass@proxy.example.com:8080")
        
        proxy_input = input(f"\n{Colors.OKCYAN}Enter proxy URL(s) (comma-separated for multiple): {Colors.ENDC}").strip()
        
        if proxy_input:
            proxy_list = [p.strip() for p in proxy_input.split(',') if p.strip()]
            
            if len(proxy_list) > 1:
                rotate = input(f"{Colors.OKCYAN}Rotate through proxies? (y/n, default=y): {Colors.ENDC}").strip().lower()
                rotate_proxy = rotate != 'n'
            else:
                rotate_proxy = False
            
            proxy_manager = ProxyManager(proxy_list=proxy_list, rotate_proxy=rotate_proxy)
            print(f"{Colors.SUCCESS}✓ Configured {len(proxy_list)} proxy(s){Colors.ENDC}")
            if rotate_proxy:
                print(f"{Colors.INFO}[i] Proxy rotation enabled{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}⚠ No proxy provided, using direct connection{Colors.ENDC}")
    
    else:
        print(f"{Colors.SUCCESS}✓ Using direct connection (no proxy){Colors.ENDC}")
    
    # Initialize enumerator
    enumerator = SubdomainEnumerator(
        domain, 
        timeout=25, 
        max_workers=50,
        dns_server=dns_server,
        use_cloudflare=cloudflare_mode,
        detected_nameservers=nameservers,
        verbose=verbose_mode,
        proxy_manager=proxy_manager
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
    enumerator.export_json(results, f"{domain}_deep_results.json", dns_info if dns_info_choice != 'n' else None)
    
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.SUCCESS}✓ Enumeration finished successfully!{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
