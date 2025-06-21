#!/usr/bin/env python3
"""
Certificate Transparency Log Monitor
Monitors CT logs and extracts domain names and certificate information
"""

import argparse
import base64
import hashlib
import json
import re
import sys
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional, Set
import ipaddress

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import publicsuffix2
from colorama import init, Fore, Back, Style

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
MAX_DOWNLOAD_RETRIES = 10
CHROME_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
BATCH_SIZE = 1000

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# IPv4 and IPv6 regex patterns
IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})$'
)

IPV6_PATTERN = re.compile(
    r'^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$'
)

class CTResult:
    """Represents a Certificate Transparency result"""
    def __init__(self, name: str, timestamp: int, cn: str, sha1: str, 
                 emails: List[str] = None, ips: List[str] = None, dns: List[str] = None):
        self.name = name
        self.timestamp = timestamp
        self.cn = cn
        self.sha1 = sha1
        self.emails = emails or []
        self.ips = ips or []
        self.dns = dns or []
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'ts': self.timestamp,
            'cn': self.cn,
            'sha1': self.sha1,
            'email': self.emails if self.emails else None,
            'ip': self.ips if self.ips else None,
            'dns': self.dns if self.dns else None
        }

class CTLogMonitor:
    """Certificate Transparency Log Monitor"""
    
    def __init__(self, log_url: Optional[str] = None, tail_count: int = 100, 
                 poll_time: int = 10, follow: bool = False, pattern: Optional[str] = None,
                 verbose: bool = False, quiet: bool = False):
        self.log_url = log_url
        self.tail_count = tail_count
        self.poll_time = poll_time
        self.follow = follow
        self.pattern = re.compile(pattern) if pattern else None
        self.verbose = verbose
        self.quiet = quiet
        
        # Statistics
        self.stat_input = 0
        self.stat_output = 0
        self.stat_errors = 0
        self.stat_processed = 0
        
        # Threading
        self.input_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.shutdown_event = threading.Event()
        self.stats_lock = threading.Lock()
        
        # Rate limiting tracking
        self.rate_limited_logs = set()
        
        # Initialize requests session with retry configuration
        self.session = requests.Session()
        self.session.headers.update({'Accept': 'application/json'})
        
        # Initialize public suffix list
        self.psl = publicsuffix2.PublicSuffixList()
    
    def scrub_x509_value(self, s: str) -> str:
        """Clean X509 string values"""
        if not s:
            return ""
        # Replace null bytes and ensure valid UTF-8
        return s.replace('\x00', '').encode('utf-8', errors='ignore').decode('utf-8')
    
    def is_valid_hostname_or_ip(self, name: str) -> bool:
        """Check if name looks like a valid hostname or IP address"""
        if not name:
            return False
            
        # Check if it's an IP address
        if IPV4_PATTERN.match(name) or IPV6_PATTERN.match(name):
            return True
            
        # For hostnames, they shouldn't contain spaces or colons (unless IPv6)
        if ' ' in name or ':' in name:
            return False
            
        return True
    
    def download_json(self, url: str) -> Dict:
        """Download JSON data with retry logic"""
        retries = 0
        
        while retries <= MAX_DOWNLOAD_RETRIES and not self.shutdown_event.is_set():
            try:
                response = self.session.get(url, timeout=30, verify=False)
                
                if response.status_code in [429, 503, 504]:  # Rate limited or unavailable
                    if retries < MAX_DOWNLOAD_RETRIES and not self.shutdown_event.is_set():
                        retries += 1
                        # Track rate limited logs
                        log_domain = url.split('/')[2] if '/' in url else url
                        self.rate_limited_logs.add(log_domain)
                        
                        # Exponential backoff for rate limiting
                        sleep_time = min(self.poll_time * (2 ** (retries - 1)), 60)
                        if not self.quiet:
                            print(f"{Fore.YELLOW}⏳ Rate limited - sleeping for {sleep_time}s ({log_domain}) - status {response.status_code}{Style.RESET_ALL}", 
                                  file=sys.stderr)
                        
                        # Sleep in small chunks to be responsive to shutdown
                        for _ in range(sleep_time):
                            if self.shutdown_event.is_set():
                                raise KeyboardInterrupt("Shutdown during rate limit sleep")
                            time.sleep(1)
                        continue
                
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.RequestException as e:
                if retries < MAX_DOWNLOAD_RETRIES and not self.shutdown_event.is_set():
                    retries += 1
                    if not self.quiet:
                        print(f"{Fore.RED}❌ Request failed for {url}: {e}, retrying ({retries}/{MAX_DOWNLOAD_RETRIES}){Style.RESET_ALL}", 
                              file=sys.stderr)
                    
                    # Sleep in small chunks to be responsive to shutdown
                    for _ in range(self.poll_time):
                        if self.shutdown_event.is_set():
                            raise KeyboardInterrupt("Shutdown during retry sleep")
                        time.sleep(1)
                    continue
                else:
                    raise
        
        # If we get here due to shutdown, raise interrupt
        if self.shutdown_event.is_set():
            raise KeyboardInterrupt("Shutdown during download")
            
        raise Exception(f"Max retries exceeded for {url}")
    
    def get_sth(self, log_url: str) -> Dict:
        """Get Signed Tree Head from CT log"""
        url = f"{log_url.rstrip('/')}/ct/v1/get-sth"
        return self.download_json(url)
    
    def get_entries(self, log_url: str, start: int, end: int) -> List[Dict]:
        """Get entries from CT log"""
        url = f"{log_url.rstrip('/')}/ct/v1/get-entries?start={start}&end={end}"
        data = self.download_json(url)
        
        if 'error_message' in data:
            raise Exception(data['error_message'])
            
        return data.get('entries', [])
    
    def get_all_logs(self) -> List[str]:
        """Get all known CT logs from Chrome's log list"""
        if not self.quiet:
            print(f"{Fore.GREEN}🚀 Loading all known logs from {CHROME_LOG_LIST_URL}{Style.RESET_ALL}", file=sys.stderr)
        
        data = self.download_json(CHROME_LOG_LIST_URL)
        logs = []
        
        for operator in data.get('operators', []):
            for log in operator.get('logs', []):
                if 'url' in log:
                    logs.append(log['url'])
        
        if not self.quiet:
            print(f"{Fore.BLUE}📋 Loaded {len(logs)} log servers{Style.RESET_ALL}", file=sys.stderr)
        return logs
    
    def parse_certificate_entry(self, entry: Dict) -> Optional[x509.Certificate]:
        """Parse certificate from CT log entry"""
        try:
            # Decode the leaf input
            leaf_input = base64.b64decode(entry['leaf_input'])
            
            if self.verbose:
                print(f"{Fore.CYAN}🔬 Parsing certificate entry: {len(leaf_input)} bytes{Style.RESET_ALL}", file=sys.stderr)
            
            # Parse the merkle tree leaf structure more carefully
            if len(leaf_input) < 15:
                if self.verbose:
                    print(f"{Fore.YELLOW}⚠️ Leaf input too short: {len(leaf_input)} bytes{Style.RESET_ALL}", file=sys.stderr)
                return None
            
            # The structure is:
            # - version (1 byte)
            # - leaf_type (1 byte) 
            # - timestamp (8 bytes)
            # - entry_type (2 bytes)
            # - certificate data
            
            entry_type = int.from_bytes(leaf_input[10:12], 'big')
            
            if self.verbose:
                timestamp = int.from_bytes(leaf_input[2:10], 'big')
                timestamp_str = datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
                print(f"{Fore.CYAN}📅 Entry type: {entry_type}, Timestamp: {timestamp_str}{Style.RESET_ALL}", file=sys.stderr)
            
            if entry_type == 0:  # X509LogEntryType
                # Certificate length (3 bytes) + certificate data
                if len(leaf_input) < 15:
                    return None
                cert_length = int.from_bytes(leaf_input[12:15], 'big')
                if len(leaf_input) < 15 + cert_length:
                    if self.verbose:
                        print(f"{Fore.YELLOW}⚠️ Certificate data truncated: expected {cert_length}, available {len(leaf_input) - 15}{Style.RESET_ALL}", file=sys.stderr)
                    return None
                cert_data = leaf_input[15:15+cert_length]
                
                if self.verbose:
                    print(f"{Fore.GREEN}📜 X509 certificate: {cert_length} bytes{Style.RESET_ALL}", file=sys.stderr)
                
            elif entry_type == 1:  # PrecertLogEntryType
                # More complex structure for precerts
                # Skip issuer key hash (32 bytes) and get TBS cert
                if len(leaf_input) < 47:  # 12 + 32 + 3 minimum
                    return None
                    
                offset = 12 + 32  # Skip to TBS certificate length
                if len(leaf_input) < offset + 3:
                    return None
                    
                tbs_cert_length = int.from_bytes(leaf_input[offset:offset+3], 'big')
                offset += 3
                
                if len(leaf_input) < offset + tbs_cert_length:
                    return None
                    
                tbs_cert_data = leaf_input[offset:offset+tbs_cert_length]
                
                if self.verbose:
                    print(f"{Fore.BLUE}🔐 Precertificate: {tbs_cert_length} bytes{Style.RESET_ALL}", file=sys.stderr)
                
                # For precerts, try multiple parsing approaches
                cert = None
                
                # Method 1: Try parsing as complete certificate (sometimes works)
                try:
                    cert = x509.load_der_x509_certificate(tbs_cert_data)
                    if self.verbose:
                        print(f"{Fore.GREEN}✅ Parsed precert as X509 certificate{Style.RESET_ALL}", file=sys.stderr)
                except Exception:
                    pass
                
                # Method 2: Try parsing the TBS certificate portion
                if cert is None:
                    try:
                        # Parse as TBSCertificate structure
                        from cryptography.hazmat.primitives import serialization
                        from cryptography.x509.oid import ExtensionOID
                        
                        # This is a simplified approach - create a minimal certificate
                        # In reality, precerts have poison extensions that need handling
                        if self.verbose:
                            print(f"{Fore.YELLOW}⚠️ Failed to parse precert as complete X509, skipping{Style.RESET_ALL}", file=sys.stderr)
                        return None
                        
                    except Exception:
                        if self.verbose:
                            print(f"{Fore.YELLOW}⚠️ Failed to parse precertificate with all methods{Style.RESET_ALL}", file=sys.stderr)
                        return None
                
                if cert is None:
                    return None
                    
                cert_data = None  # Not used for precerts
                    
            else:
                if self.verbose:
                    print(f"{Fore.RED}❓ Unknown entry type: {entry_type}{Style.RESET_ALL}", file=sys.stderr)
                return None
            
            # Parse the certificate (for X509 entries, cert_data is set above)
            if entry_type == 0:  # X509LogEntryType
                cert = x509.load_der_x509_certificate(cert_data)
            # For precerts, cert is already set above or None
            
            if cert and self.verbose:
                print(f"{Fore.GREEN}✅ Successfully parsed certificate{Style.RESET_ALL}", file=sys.stderr)
            
            return cert
            
        except Exception as e:
            # Count parsing errors but don't spam logs for common issues
            self.stat_errors += 1
            
            # Only log detailed errors for debugging (less frequent)
            if self.stat_errors % 100 == 1 or self.verbose:  # Log every 100th error or if verbose
                if not self.quiet:  # Don't log errors in quiet mode unless verbose
                    error_msg = str(e)
                    if len(error_msg) > 100:
                        error_msg = error_msg[:100] + "..."
                    print(f"{Fore.RED}🚫 Certificate parsing error (#{self.stat_errors}): {error_msg}{Style.RESET_ALL}", 
                          file=sys.stderr)
            
            return None
    
    def extract_names_from_cert(self, cert: x509.Certificate) -> Set[str]:
        """Extract valid domain names from certificate"""
        names = set()
        
        # Extract Common Name
        try:
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    cn = attribute.value.lower()
                    if self.verbose:
                        print(f"{Fore.CYAN}🏷️ Common Name: {cn}{Style.RESET_ALL}", file=sys.stderr)
                    if self.is_valid_hostname_or_ip(cn):
                        try:
                            self.psl.get_tld(cn, strict=False)
                            names.add(cn)
                            if self.verbose:
                                print(f"{Fore.GREEN}✅ Added CN: {cn}{Style.RESET_ALL}", file=sys.stderr)
                        except Exception as e:
                            if self.verbose:
                                print(f"{Fore.YELLOW}⚠️ Invalid TLD for CN {cn}: {e}{Style.RESET_ALL}", file=sys.stderr)
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}❌ Error extracting CN: {e}{Style.RESET_ALL}", file=sys.stderr)
        
        # Extract Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_count = 0
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    name = san.value.lower()
                    san_count += 1
                    if self.verbose:
                        print(f"{Fore.CYAN}🌐 SAN #{san_count}: {name}{Style.RESET_ALL}", file=sys.stderr)
                    if self.is_valid_hostname_or_ip(name):
                        try:
                            self.psl.get_tld(name, strict=False)
                            names.add(name)
                            if self.verbose:
                                print(f"{Fore.GREEN}✅ Added SAN: {name}{Style.RESET_ALL}", file=sys.stderr)
                        except Exception as e:
                            if self.verbose:
                                print(f"{Fore.YELLOW}⚠️ Invalid TLD for SAN {name}: {e}{Style.RESET_ALL}", file=sys.stderr)
            
            if self.verbose and san_count > 0:
                print(f"{Fore.BLUE}📊 Total SANs processed: {san_count}, Valid names: {len(names)}{Style.RESET_ALL}", file=sys.stderr)
                
        except x509.ExtensionNotFound:
            if self.verbose:
                print(f"{Fore.YELLOW}⚠️ No SAN extension found{Style.RESET_ALL}", file=sys.stderr)
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}❌ Error extracting SANs: {e}{Style.RESET_ALL}", file=sys.stderr)
        
        return names
    
    def process_certificate(self, entry: Dict) -> List[CTResult]:
        """Process a certificate entry and extract information"""
        with self.stats_lock:
            self.stat_processed += 1
        
        if self.verbose:
            print(f"{Fore.MAGENTA}🔍 Processing certificate entry #{self.stat_processed}{Style.RESET_ALL}", file=sys.stderr)
        
        cert = self.parse_certificate_entry(entry)
        if not cert:
            if self.verbose:
                print(f"{Fore.RED}❌ Failed to parse certificate entry #{self.stat_processed}{Style.RESET_ALL}", file=sys.stderr)
            return []
        
        with self.stats_lock:
            self.stat_input += 1
        
        if self.verbose:
            print(f"{Fore.GREEN}✅ Valid certificate #{self.stat_input}{Style.RESET_ALL}", file=sys.stderr)
            
            # Show certificate details
            try:
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                
                print(f"{Fore.CYAN}📋 Certificate Details:{Style.RESET_ALL}", file=sys.stderr)
                print(f"{Fore.CYAN}   Subject: {subject}{Style.RESET_ALL}", file=sys.stderr)
                print(f"{Fore.CYAN}   Issuer: {issuer}{Style.RESET_ALL}", file=sys.stderr)
                print(f"{Fore.CYAN}   Valid: {not_before} to {not_after}{Style.RESET_ALL}", file=sys.stderr)
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️ Error displaying cert details: {e}{Style.RESET_ALL}", file=sys.stderr)
        
        # Extract names
        names = self.extract_names_from_cert(cert)
        if not names:
            if self.verbose:
                print(f"{Fore.YELLOW}⚠️ No valid names extracted from certificate{Style.RESET_ALL}", file=sys.stderr)
            return []
        
        if self.verbose:
            print(f"{Fore.GREEN}🎯 Extracted {len(names)} valid names: {', '.join(sorted(names))}{Style.RESET_ALL}", file=sys.stderr)
        
        # Calculate SHA1 hash
        sha1_hash = hashlib.sha1(cert.public_bytes(Encoding.DER)).hexdigest()
        
        if self.verbose:
            print(f"{Fore.BLUE}🔐 SHA1: {sha1_hash}{Style.RESET_ALL}", file=sys.stderr)
        
        # Extract additional information
        cn = ""
        try:
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    cn = self.scrub_x509_value(attribute.value.lower())
                    break
        except:
            pass
        
        # Extract email addresses
        emails = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for san in san_ext.value:
                if isinstance(san, x509.RFC822Name):
                    emails.append(self.scrub_x509_value(san.value.lower()))
        except:
            pass
        
        if self.verbose and emails:
            print(f"{Fore.CYAN}📧 Email addresses: {', '.join(emails)}{Style.RESET_ALL}", file=sys.stderr)
        
        # Extract IP addresses
        ips = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for san in san_ext.value:
                if isinstance(san, x509.IPAddress):
                    ips.append(str(san.value))
        except:
            pass
        
        if self.verbose and ips:
            print(f"{Fore.CYAN}🌐 IP addresses: {', '.join(ips)}{Style.RESET_ALL}", file=sys.stderr)
        
        # Get DNS names
        dns_names = list(names)
        
        # Extract actual timestamp from leaf input
        timestamp = self.extract_timestamp_from_entry(entry)
        
        results = []
        for name in names:
            # Apply pattern filter if specified
            if self.pattern:
                if self.pattern.search(name):
                    if self.verbose:
                        print(f"{Fore.GREEN}🎯 Pattern MATCH: {name} matches {self.pattern.pattern}{Style.RESET_ALL}", file=sys.stderr)
                else:
                    # Don't show SKIP messages in verbose mode - they're too noisy
                    continue
            
            result = CTResult(
                name=name,
                timestamp=timestamp,
                cn=cn,
                sha1=sha1_hash,
                emails=emails if emails else None,
                ips=ips if ips else None,
                dns=dns_names if dns_names else None
            )
            results.append(result)
        
        if self.verbose:
            print(f"{Fore.MAGENTA}📤 Generated {len(results)} results for output{Style.RESET_ALL}", file=sys.stderr)
            print(f"{Fore.BLUE}{'='*60}{Style.RESET_ALL}", file=sys.stderr)
        
        return results
    
    def extract_timestamp_from_entry(self, entry: Dict) -> int:
        """Extract timestamp from CT log entry"""
        try:
            # Decode the leaf input to get the actual timestamp
            leaf_input = base64.b64decode(entry['leaf_input'])
            
            # Timestamp is at bytes 2-9 (8 bytes, big endian)
            if len(leaf_input) >= 10:
                timestamp_bytes = leaf_input[2:10]
                timestamp = int.from_bytes(timestamp_bytes, 'big')
                return timestamp
        except:
            pass
            
        # Fallback to current time
        return int(time.time() * 1000)
    
    def worker_thread(self):
        """Worker thread to process certificate entries"""
        while not self.shutdown_event.is_set():
            try:
                entry = self.input_queue.get(timeout=1)
                if entry is None:  # Shutdown signal
                    break
                    
                results = self.process_certificate(entry)
                for result in results:
                    self.output_queue.put(result)
                    
                self.input_queue.task_done()
                    
            except queue.Empty:
                continue
            except Exception as e:
                if not self.quiet:
                    print(f"{Fore.RED}⚠️ Worker thread error: {e}{Style.RESET_ALL}", file=sys.stderr)
    
    def output_thread(self):
        """Output thread to write results as JSON"""
        last_output_time = time.time()
        last_stats_time = time.time()
        
        while not self.shutdown_event.is_set():
            try:
                result = self.output_queue.get(timeout=1)
                if result is None:  # Shutdown signal
                    break
                    
                # Filter out None values for cleaner JSON
                data = {k: v for k, v in result.to_dict().items() if v is not None}
                
                # Add colored emoji prefix for terminal visibility
                domain_type = "🌐"
                if any(char.isdigit() for char in result.name):
                    if ":" in result.name:
                        domain_type = "🔢"  # IPv6
                    elif result.name.count('.') == 3:
                        domain_type = "📍"  # IPv4
                
                # Print with color coding and better formatting
                current_time = time.time()
                
                # Show match notification for patterns
                if self.pattern:
                    if not self.quiet:
                        print(f"{Fore.GREEN}🎯 MATCH FOUND: {domain_type}{Style.RESET_ALL} {json.dumps(data)}", file=sys.stderr)
                    print(json.dumps(data))
                else:
                    if not self.quiet:
                        print(f"{Fore.CYAN}{domain_type}{Style.RESET_ALL} {json.dumps(data)}")
                    else:
                        print(json.dumps(data))
                
                sys.stdout.flush()
                with self.stats_lock:
                    self.stat_output += 1
                
                # Periodic status update when using patterns
                if self.pattern and current_time - last_stats_time > 30:  # Every 30 seconds
                    if not self.quiet:
                        with self.stats_lock:
                            print(f"{Fore.BLUE}📊 Pattern '{self.pattern.pattern}': {self.stat_output} matches found from {self.stat_input} valid certs{Style.RESET_ALL}", 
                                  file=sys.stderr)
                    last_stats_time = current_time
                
                self.output_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                if not self.quiet:
                    print(f"{Fore.RED}⚠️ Output thread error: {e}{Style.RESET_ALL}", file=sys.stderr)
    
    def monitor_log(self, log_url: str):
        """Monitor a single CT log"""
        iteration = 0
        cur_idx = 0
        
        if self.verbose:
            print(f"{Fore.MAGENTA}🎯 Starting monitor for {log_url}{Style.RESET_ALL}", file=sys.stderr)
        
        try:
            while True:
                if iteration > 0:
                    if self.verbose:
                        print(f"{Fore.YELLOW}💤 Iteration {iteration}: Sleeping for {self.poll_time} seconds ({Fore.MAGENTA}{log_url}{Fore.YELLOW}) at index {cur_idx}{Style.RESET_ALL}", 
                              file=sys.stderr)
                    elif not self.quiet:
                        print(f"{Fore.YELLOW}💤 Sleeping for {self.poll_time} seconds ({Fore.MAGENTA}{log_url}{Fore.YELLOW}) at index {cur_idx}{Style.RESET_ALL}", 
                              file=sys.stderr)
                    time.sleep(self.poll_time)
                
                # Get current tree head
                if self.verbose:
                    print(f"{Fore.CYAN}📡 Fetching STH from {log_url}{Style.RESET_ALL}", file=sys.stderr)
                
                sth = self.get_sth(log_url)
                tree_size = sth['tree_size']
                
                if self.verbose:
                    print(f"{Fore.BLUE}📊 Tree size: {tree_size}, Tree head timestamp: {sth.get('timestamp', 'N/A')}{Style.RESET_ALL}", file=sys.stderr)
                
                if iteration == 0:
                    # Start from tail
                    start_idx = max(0, tree_size - self.tail_count)
                    cur_idx = start_idx
                    if not self.quiet:
                        print(f"{Fore.GREEN}🎯 Starting from index {start_idx} (tree size: {tree_size}) for {log_url}{Style.RESET_ALL}", 
                              file=sys.stderr)
                
                # Download entries in batches
                entries_processed = 0
                for idx in range(start_idx, tree_size, BATCH_SIZE):
                    if self.shutdown_event.is_set():
                        if self.verbose:
                            print(f"{Fore.YELLOW}🛑 Shutdown event detected for {log_url}{Style.RESET_ALL}", file=sys.stderr)
                        return
                        
                    end_idx = min(idx + BATCH_SIZE - 1, tree_size - 1)
                    
                    if self.verbose:
                        print(f"{Fore.CYAN}📥 Downloading entries {idx}-{end_idx} from {log_url}{Style.RESET_ALL}", file=sys.stderr)
                    
                    try:
                        entries = self.get_entries(log_url, idx, end_idx)
                        
                        if self.verbose:
                            print(f"{Fore.GREEN}✅ Downloaded {len(entries)} entries from {log_url}{Style.RESET_ALL}", file=sys.stderr)
                        
                        for entry in entries:
                            if self.shutdown_event.is_set():
                                return
                            self.input_queue.put(entry)
                            entries_processed += 1
                        
                        # Progress indicator with better spacing
                        if entries_processed > 0 and entries_processed % 1000 == 0 and not self.quiet:
                            print(f"{Fore.BLUE}📊 Progress: {entries_processed} entries processed from {Fore.MAGENTA}{log_url}{Style.RESET_ALL}", 
                                  file=sys.stderr)
                            
                            # Show statistics periodically
                            if self.stat_errors > 0:
                                error_rate = (self.stat_errors / max(self.stat_processed, 1)) * 100
                                print(f"{Fore.YELLOW}📈 Stats: {self.stat_input} valid certs, {self.stat_errors} parse errors ({error_rate:.1f}%){Style.RESET_ALL}", 
                                      file=sys.stderr)
                            
                    except Exception as e:
                        if not self.quiet:
                            print(f"{Fore.RED}💥 Failed to download entries for {log_url}: index {idx} -> {e}{Style.RESET_ALL}", 
                                  file=sys.stderr)
                        if self.verbose:
                            import traceback
                            print(f"{Fore.RED}🔍 Full traceback: {traceback.format_exc()}{Style.RESET_ALL}", file=sys.stderr)
                        return
                
                if entries_processed > 0 and not self.quiet:
                    success_rate = (self.stat_input / max(self.stat_processed, 1)) * 100
                    print(f"{Fore.GREEN}✅ Batch complete: {entries_processed} entries, {self.stat_input} valid certs ({success_rate:.1f}%) from {Fore.MAGENTA}{log_url}{Style.RESET_ALL}", 
                          file=sys.stderr)
                
                cur_idx = tree_size
                iteration += 1
                
                if self.verbose:
                    print(f"{Fore.BLUE}🔄 Completed iteration {iteration} for {log_url}{Style.RESET_ALL}", file=sys.stderr)
                
                if not self.follow:
                    if self.verbose:
                        print(f"{Fore.GREEN}🏁 Finished monitoring {log_url} (follow mode disabled){Style.RESET_ALL}", file=sys.stderr)
                    break
                    
        except Exception as e:
            if not self.quiet:
                print(f"{Fore.RED}💀 Failed to monitor log {log_url}: {e}{Style.RESET_ALL}", file=sys.stderr)
            if self.verbose:
                import traceback
                print(f"{Fore.RED}🔍 Full traceback: {traceback.format_exc()}{Style.RESET_ALL}", file=sys.stderr)
    
    def run(self):
        """Main execution method"""
        try:
            if not self.quiet:
                print(f"{Fore.CYAN}{Style.BRIGHT}🔍 Certificate Transparency Log Monitor Starting...{Style.RESET_ALL}", file=sys.stderr)
            
            # Determine which logs to monitor
            if self.log_url:
                logs = [self.log_url]
                if not self.quiet:
                    print(f"{Fore.GREEN}🎯 Monitoring single log: {self.log_url}{Style.RESET_ALL}", file=sys.stderr)
            else:
                logs = self.get_all_logs()
            
            # Show pattern info
            if self.pattern and not self.quiet:
                print(f"{Fore.MAGENTA}🔍 Searching for pattern: {self.pattern.pattern}{Style.RESET_ALL}", file=sys.stderr)
                print(f"{Fore.YELLOW}💡 Tip: This will only show certificates matching your pattern!{Style.RESET_ALL}", file=sys.stderr)
            
            # Start worker threads
            num_workers = min(4, len(logs))
            workers = []
            if not self.quiet:
                print(f"{Fore.BLUE}🔧 Starting {num_workers} worker threads{Style.RESET_ALL}", file=sys.stderr)
            for _ in range(num_workers):
                worker = threading.Thread(target=self.worker_thread)
                worker.start()
                workers.append(worker)
            
            # Start output thread
            if not self.quiet:
                print(f"{Fore.BLUE}📝 Starting output thread{Style.RESET_ALL}", file=sys.stderr)
            output_worker = threading.Thread(target=self.output_thread)
            output_worker.start()
            
            # Monitor logs
            if not self.quiet:
                print(f"{Fore.GREEN}🚀 Beginning log monitoring with {len(logs)} log(s){Style.RESET_ALL}", file=sys.stderr)
            
            with ThreadPoolExecutor(max_workers=len(logs)) as executor:
                futures = [executor.submit(self.monitor_log, log_url) for log_url in logs]
                
                try:
                    # Wait for completion or interruption
                    for future in as_completed(futures):
                        if self.shutdown_event.is_set():
                            break
                        try:
                            future.result()  # This will raise any exceptions
                        except Exception as e:
                            if not self.quiet:
                                print(f"{Fore.RED}💥 Log monitoring error: {e}{Style.RESET_ALL}", file=sys.stderr)
                            
                except KeyboardInterrupt:
                    # Always show interrupt message, even in quiet mode
                    print(f"\n{Fore.YELLOW}🛑 Interrupt received, shutting down...{Style.RESET_ALL}", file=sys.stderr)
                    
                    # Set shutdown event immediately
                    self.shutdown_event.set()
                    
                    # Cancel all futures immediately
                    for future in futures:
                        future.cancel()
                    
                    # Force shutdown the executor without waiting
                    executor.shutdown(wait=False)
            
            # Immediate shutdown sequence
            self.shutdown_event.set()
            
            # Send shutdown signals with very short timeouts
            for _ in range(num_workers):
                try:
                    self.input_queue.put(None, block=False)
                except:
                    pass
            
            try:
                self.output_queue.put(None, block=False)
            except:
                pass
            
            # Don't wait for threads - let them be killed by process exit
            
        except KeyboardInterrupt:
            # Handle interrupt at outer level - don't show message again
            pass
        except Exception as e:
            if not self.quiet:
                print(f"{Fore.RED}💀 Fatal error: {e}{Style.RESET_ALL}", file=sys.stderr)
            return 1
        finally:
            # Always show final statistics
            with self.stats_lock:
                total_processed = max(self.stat_processed, 1)
                success_rate = (self.stat_input / total_processed) * 100
                error_rate = (self.stat_errors / total_processed) * 100
                domains_per_cert = (self.stat_output / max(self.stat_input, 1))
            
            # Always show final statistics
            print(f"\n{Fore.CYAN}📊 Final Statistics:{Style.RESET_ALL}", file=sys.stderr)
            print(f"{Fore.GREEN}  🎯 Total entries processed: {Style.BRIGHT}{total_processed}{Style.RESET_ALL}", file=sys.stderr)
            print(f"{Fore.GREEN}  ✅ Valid certificates: {Style.BRIGHT}{self.stat_input}{Style.RESET_ALL}{Fore.GREEN} ({success_rate:.1f}%){Style.RESET_ALL}", file=sys.stderr)
            print(f"{Fore.RED}    ❌ Parse errors: {Style.BRIGHT}{self.stat_errors}{Style.RESET_ALL}{Fore.RED} ({error_rate:.1f}%){Style.RESET_ALL}", file=sys.stderr)
            
            if self.pattern:
                match_rate = (self.stat_output / max(self.stat_input, 1)) * 100
                print(f"{Fore.MAGENTA}  🎯 Pattern matches: {Style.BRIGHT}{self.stat_output}{Style.RESET_ALL}{Fore.MAGENTA} ({match_rate:.1f}% of valid certs){Style.RESET_ALL}", file=sys.stderr)
                if self.stat_output == 0:
                    print(f"{Fore.YELLOW}  💡 No matches found - try a broader pattern or increase -n (tail count){Style.RESET_ALL}", file=sys.stderr)
            else:
                print(f"{Fore.BLUE}  📝 Domain names output: {Style.BRIGHT}{self.stat_output}{Style.RESET_ALL}{Fore.BLUE} (avg {domains_per_cert:.1f} domains per cert){Style.RESET_ALL}", file=sys.stderr)
            
            # Show rate limiting summary
            if self.rate_limited_logs:
                print(f"{Fore.YELLOW}  ⚠️ Rate limited logs: {len(self.rate_limited_logs)} (consider using -p with higher value){Style.RESET_ALL}", file=sys.stderr)
        
        return 0

def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}🔍 Certificate Transparency Log Monitor{Style.RESET_ALL} - Extracts domain names from CT logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.GREEN}Examples:{Style.RESET_ALL}
  {Fore.YELLOW}python ct_monitor.py -l https://ct.googleapis.com/logs/xenon2024/{Style.RESET_ALL}
  {Fore.YELLOW}python ct_monitor.py -f -n 1000{Style.RESET_ALL}
  {Fore.YELLOW}python ct_monitor.py -m ".*\\.example\\.com$" -p 30{Style.RESET_ALL}
  {Fore.YELLOW}python ct_monitor.py -v -m "microsoft" -n 500{Style.RESET_ALL}
  {Fore.YELLOW}python ct_monitor.py -q -m "github" -n 1000 > domains.json{Style.RESET_ALL}

{Fore.BLUE}Output Emojis:{Style.RESET_ALL}
  🌐 Domain name
  📍 IPv4 address  
  🔢 IPv6 address
        """
    )
    parser.add_argument('-l', '--log-url', help='Only read from the specified CT log URL')
    parser.add_argument('-n', '--tail-count', type=int, default=100, 
                       help='Number of entries from the end to start from (default: 100)')
    parser.add_argument('-p', '--poll-time', type=int, default=10,
                       help='Number of seconds to wait between polls (default: 10)')
    parser.add_argument('-f', '--follow', action='store_true',
                       help='Follow the tail of the CT log')
    parser.add_argument('-m', '--pattern', help='Only show entries matching this regex pattern')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output showing detailed certificate processing')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode - suppress all status messages, only output results')
    
    args = parser.parse_args()
    
    # Validate conflicting options
    if args.verbose and args.quiet:
        parser.error("Cannot use both --verbose and --quiet options together")
    
    # Print startup banner (only if not quiet)
    if not args.quiet:
        verbose_status = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if args.verbose else f"{Fore.YELLOW}No{Style.RESET_ALL}"
        quiet_status = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if args.quiet else f"{Fore.YELLOW}No{Style.RESET_ALL}"
        print(f"""
{Fore.CYAN}{Style.BRIGHT}🔍 Certificate Transparency Log Monitor{Style.RESET_ALL}
{Fore.BLUE}{'='*50}{Style.RESET_ALL}
{Fore.GREEN}🎯 Target:{Style.RESET_ALL} {'Single log' if args.log_url else 'All known logs'}
{Fore.GREEN}📊 Tail count:{Style.RESET_ALL} {args.tail_count}
{Fore.GREEN}⏱️  Poll interval:{Style.RESET_ALL} {args.poll_time}s
{Fore.GREEN}🔄 Follow mode:{Style.RESET_ALL} {'Yes' if args.follow else 'No'}
{Fore.GREEN}🔍 Pattern:{Style.RESET_ALL} {args.pattern if args.pattern else 'None'}
{Fore.GREEN}🗣️  Verbose mode:{Style.RESET_ALL} {verbose_status}
{Fore.GREEN}🤫 Quiet mode:{Style.RESET_ALL} {quiet_status}
{Fore.BLUE}{'='*50}{Style.RESET_ALL}
        """, file=sys.stderr)
        
        if args.verbose:
            print(f"{Fore.MAGENTA}🔍 Verbose mode enabled - detailed certificate processing information will be shown{Style.RESET_ALL}", file=sys.stderr)
        
        if args.quiet:
            print(f"{Fore.BLUE}🤫 Quiet mode enabled - only results will be output{Style.RESET_ALL}", file=sys.stderr)
    
    monitor = CTLogMonitor(
        log_url=args.log_url,
        tail_count=args.tail_count,
        poll_time=args.poll_time,
        follow=args.follow,
        pattern=args.pattern,
        verbose=args.verbose,
        quiet=args.quiet
    )
    
    return monitor.run()

if __name__ == '__main__':
    sys.exit(main())