#!/usr/bin/env python3
"""
Certificate Transparency Log Monitor
Monitors CT logs and extracts domain names and certificate information

A powerful Python tool for monitoring Certificate Transparency (CT) logs to extract 
domain names, IP addresses, and email addresses from SSL/TLS certificates in real-time.

Features:
- Multi-threaded processing of multiple CT logs
- Pattern matching with regex filtering  
- Quiet mode for automation and piping
- Verbose mode for debugging and analysis
- Real-time statistics and progress tracking
- Smart rate limit handling with exponential backoff
- Follow mode for continuous monitoring
- Support for all major CT log operators

Version: 1.1.1
Author: Jonas Lejon <jonas.github@triop.se>
License: MIT
Repository: https://github.com/jonaslejon/ct-monitor
"""

__version__ = "1.3.0"
__author__ = "Jonas Lejon <jonas.github@triop.se>"
__license__ = "MIT"

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import ipaddress

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
import publicsuffix2

# RFC 6962 precertificate poison extension: present on a precert, never on the final certificate.
CT_POISON_OID = "1.3.6.1.4.1.11129.2.4.3"
from fetcher import PositionStore, RangeFetcher, RateLimited
from colorama import init, Fore, Back, Style

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class Config:
    """Configuration constants"""
    MAX_DOWNLOAD_RETRIES = 10
    CHROME_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
    BATCH_SIZE = 1000
    DEFAULT_TAIL_COUNT = 100
    DEFAULT_POLL_TIME = 10
    DEFAULT_TIMEOUT = 30
    WORKER_THREAD_COUNT = 4
    ERROR_LOG_FREQUENCY = 100  # Log every N errors
    STATS_UPDATE_INTERVAL = 30  # seconds
    PROGRESS_UPDATE_INTERVAL = 1000  # entries


class EntryType(Enum):
    """CT log entry types"""
    X509_LOG_ENTRY = 0
    PRECERT_LOG_ENTRY = 1


class LeafInputStructure:
    """Constants for leaf input structure parsing"""
    VERSION_OFFSET = 0
    LEAF_TYPE_OFFSET = 1
    TIMESTAMP_OFFSET = 2
    TIMESTAMP_LENGTH = 8
    ENTRY_TYPE_OFFSET = 10
    ENTRY_TYPE_LENGTH = 2
    MIN_LEAF_LENGTH = 15
    CERT_LENGTH_OFFSET = 12
    CERT_LENGTH_SIZE = 3
    PRECERT_ISSUER_KEY_HASH_LENGTH = 32
    PRECERT_MIN_LENGTH = 47  # 12 + 32 + 3


@dataclass
class CTResult:
    """Represents a Certificate Transparency result"""
    name: str
    timestamp: int
    cn: str
    sha1: str
    emails: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    dns: List[str] = field(default_factory=list)
    # issuer + serial: shared by a precertificate and its final certificate, unlike sha1
    issuance_key: Optional[str] = None
    precert: bool = False

    def to_dict(self) -> Dict:
        """Convert to dictionary, excluding None values"""
        return {
            'name': self.name,
            'ts': self.timestamp,
            'cn': self.cn,
            'sha1': self.sha1,
            'email': self.emails if self.emails else None,
            'ip': self.ips if self.ips else None,
            'dns': self.dns if self.dns else None,
            'ik': self.issuance_key,
            'pc': self.precert,
        }


class Statistics:
    """Thread-safe statistics tracker"""
    def __init__(self):
        self.lock = threading.Lock()
        self.input = 0
        self.output = 0
        self.errors = 0
        self.processed = 0
        
    def increment_input(self):
        with self.lock:
            self.input += 1
            
    def increment_output(self):
        with self.lock:
            self.output += 1
            
    def increment_errors(self):
        with self.lock:
            self.errors += 1
            
    def increment_processed(self):
        with self.lock:
            self.processed += 1
            
    def get_stats(self) -> Dict[str, int]:
        with self.lock:
            return {
                'input': self.input,
                'output': self.output,
                'errors': self.errors,
                'processed': self.processed
            }


class IPValidator:
    """IP address validation utilities"""
    
    @classmethod
    def is_ip_address(cls, value: str) -> bool:
        """Check if value is an IP address (IPv4 or IPv6)"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    @classmethod
    def is_ipv4(cls, value: str) -> bool:
        """Check if value is an IPv4 address"""
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False
    
    @classmethod
    def is_ipv6(cls, value: str) -> bool:
        """Check if value is an IPv6 address"""
        try:
            ipaddress.IPv6Address(value)
            return True
        except ValueError:
            return False


class Logger:
    """Centralized logging with verbosity and quiet mode support"""
    
    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        
    def info(self, message: str, force: bool = False):
        """Log info message"""
        if not self.quiet or force:
            print(f"{Fore.CYAN}{message}{Style.RESET_ALL}", file=sys.stderr)
            
    def success(self, message: str, force: bool = False):
        """Log success message"""
        if not self.quiet or force:
            print(f"{Fore.GREEN}{message}{Style.RESET_ALL}", file=sys.stderr)
            
    def warning(self, message: str, force: bool = False):
        """Log warning message"""
        if not self.quiet or force:
            print(f"{Fore.YELLOW}{message}{Style.RESET_ALL}", file=sys.stderr)
            
    def error(self, message: str, force: bool = False):
        """Log error message"""
        if not self.quiet or force:
            print(f"{Fore.RED}{message}{Style.RESET_ALL}", file=sys.stderr)
            
    def debug(self, message: str):
        """Log debug message (verbose only)"""
        if self.verbose:
            print(f"{Fore.MAGENTA}{message}{Style.RESET_ALL}", file=sys.stderr)
            
    def output(self, data: str):
        """Output data to stdout"""
        print(data)
        sys.stdout.flush()


class CertificateParser:
    """Certificate parsing utilities"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        
    def parse_leaf_input(self, leaf_input: bytes) -> Tuple[Optional[EntryType], Optional[bytes], int]:
        """
        Parse leaf input structure
        Returns: (entry_type, certificate_data, timestamp)
        """
        if len(leaf_input) < LeafInputStructure.MIN_LEAF_LENGTH:
            self.logger.debug(f"⚠️ Leaf input too short: {len(leaf_input)} bytes")
            return None, None, 0
            
        # Extract entry type
        entry_type_value = int.from_bytes(
            leaf_input[LeafInputStructure.ENTRY_TYPE_OFFSET:
                      LeafInputStructure.ENTRY_TYPE_OFFSET + LeafInputStructure.ENTRY_TYPE_LENGTH], 
            'big'
        )
        
        try:
            entry_type = EntryType(entry_type_value)
        except ValueError:
            self.logger.debug(f"❓ Unknown entry type: {entry_type_value}")
            return None, None, 0
            
        # Extract timestamp
        timestamp = int.from_bytes(
            leaf_input[LeafInputStructure.TIMESTAMP_OFFSET:
                      LeafInputStructure.TIMESTAMP_OFFSET + LeafInputStructure.TIMESTAMP_LENGTH], 
            'big'
        )
        
        if self.logger.verbose:
            timestamp_str = datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
            self.logger.debug(f"📅 Entry type: {entry_type.name}, Timestamp: {timestamp_str}")
            
        # Extract certificate data based on entry type
        if entry_type == EntryType.X509_LOG_ENTRY:
            cert_data = self._extract_x509_cert(leaf_input)
        else:  # PRECERT_LOG_ENTRY
            cert_data = self._extract_precert(leaf_input)
            
        return entry_type, cert_data, timestamp
        
    def _extract_x509_cert(self, leaf_input: bytes) -> Optional[bytes]:
        """Extract X509 certificate from leaf input"""
        offset = LeafInputStructure.CERT_LENGTH_OFFSET
        
        if len(leaf_input) < offset + LeafInputStructure.CERT_LENGTH_SIZE:
            return None
            
        cert_length = int.from_bytes(
            leaf_input[offset:offset + LeafInputStructure.CERT_LENGTH_SIZE], 
            'big'
        )
        offset += LeafInputStructure.CERT_LENGTH_SIZE
        
        if len(leaf_input) < offset + cert_length:
            self.logger.debug(
                f"⚠️ Certificate data truncated: expected {cert_length}, "
                f"available {len(leaf_input) - offset}"
            )
            return None
            
        self.logger.debug(f"📜 X509 certificate: {cert_length} bytes")
        return leaf_input[offset:offset + cert_length]
        
    def _extract_precert(self, leaf_input: bytes) -> Optional[bytes]:
        """Extract precertificate from leaf input"""
        if len(leaf_input) < LeafInputStructure.PRECERT_MIN_LENGTH:
            return None
            
        # Skip issuer key hash
        offset = LeafInputStructure.CERT_LENGTH_OFFSET + LeafInputStructure.PRECERT_ISSUER_KEY_HASH_LENGTH
        
        if len(leaf_input) < offset + LeafInputStructure.CERT_LENGTH_SIZE:
            return None
            
        tbs_cert_length = int.from_bytes(
            leaf_input[offset:offset + LeafInputStructure.CERT_LENGTH_SIZE], 
            'big'
        )
        offset += LeafInputStructure.CERT_LENGTH_SIZE
        
        if len(leaf_input) < offset + tbs_cert_length:
            return None
            
        self.logger.debug(f"🔐 Precertificate: {tbs_cert_length} bytes")
        return leaf_input[offset:offset + tbs_cert_length]
        
    def parse_certificate(self, cert_data: bytes, entry_type: EntryType) -> Optional[x509.Certificate]:
        """Parse certificate data into X509 certificate object"""
        if not cert_data:
            return None
            
        if entry_type == EntryType.X509_LOG_ENTRY:
            try:
                return x509.load_der_x509_certificate(cert_data)
            except Exception as e:
                self.logger.debug(f"Failed to parse X509 certificate: {e}")
                return None
                
        else:  # PRECERT_LOG_ENTRY
            # For precertificates, we can only try to parse as regular certificate
            # Real precert parsing would require handling poison extensions
            try:
                cert = x509.load_der_x509_certificate(cert_data)
                self.logger.debug("✅ Parsed precert as X509 certificate")
                return cert
            except Exception:
                # This is expected for many precertificates
                self.logger.debug("⚠️ Cannot parse precertificate as standard X509 (expected)")
                return None


class HTTPClient:
    """HTTP client with retry logic and rate limiting"""

    def __init__(self, logger: Logger, poll_time: int = Config.DEFAULT_POLL_TIME, rate_limiter=None):
        self.logger = logger
        self.poll_time = poll_time
        self.session = requests.Session()
        self.session.headers.update({'Accept': 'application/json'})
        self.rate_limited_logs = set()
        self.rate_limiter = rate_limiter
        
    def download_json(self, url: str, shutdown_event: threading.Event) -> Dict:
        """Download JSON data with retry logic"""
        retries = 0

        while not shutdown_event.is_set():
            try:
                response = self.session.get(url, timeout=Config.DEFAULT_TIMEOUT, verify=False)
                
                if response.status_code in [429, 503, 504]:  # Rate limited or unavailable
                    if not shutdown_event.is_set():
                        retries += 1
                        log_domain = url.split('/')[2] if '/' in url else url
                        self.rate_limited_logs.add(log_domain)

                        # Record rate limit in adaptive limiter
                        if self.rate_limiter:
                            self.rate_limiter.record_rate_limit(url, response.status_code)
                            sleep_time = self.rate_limiter.get_poll_interval(url)
                        else:
                            sleep_time = min(self.poll_time * (2 ** (retries - 1)), 60)

                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        self.logger.warning(
                            f"[{timestamp}] ⏳ Rate limited - sleeping for {sleep_time}s ({log_domain}) "
                            f"- status {response.status_code}",
                            force=True  # Show even in quiet mode
                        )

                        self._interruptible_sleep(sleep_time, shutdown_event)
                        continue

                response.raise_for_status()

                # Record success in adaptive limiter
                if self.rate_limiter:
                    self.rate_limiter.record_success(url)

                return response.json()
                
            except requests.exceptions.RequestException as e:
                if not shutdown_event.is_set():
                    retries += 1
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    self.logger.error(
                        f"[{timestamp}] ❌ Request failed for {url}: {e}, "
                        f"retrying ({retries})"
                    )
                    
                    self._interruptible_sleep(self.poll_time, shutdown_event)
                    continue
                else:
                    raise
        
        if shutdown_event.is_set():
            return {}  # Return empty dict when shutdown is requested
        
    def fetch_json_once(self, url: str) -> Dict:
        """One request, no retry loop: raises RateLimited on 429/503/504 so the caller decides
        how long to wait. Used by the gap-free fetcher; download_json keeps its 90 s sleeps."""
        response = self.session.get(url, timeout=Config.DEFAULT_TIMEOUT, verify=False)
        if response.status_code in (429, 503, 504):
            raise RateLimited(response.status_code, url.split('/')[2] if '/' in url else url)
        response.raise_for_status()
        return response.json()

    def _interruptible_sleep(self, seconds: float, shutdown_event: threading.Event):
        """Sleep that can be interrupted by shutdown event"""
        # Handle float seconds properly
        total_seconds = int(seconds)
        remaining = seconds - total_seconds

        for _ in range(total_seconds):
            if shutdown_event.is_set():
                return  # Return early instead of raising exception
            time.sleep(1)

        # Sleep remaining fraction if any
        if remaining > 0 and not shutdown_event.is_set():
            time.sleep(remaining)


class CTLogMonitor:
    """Certificate Transparency Log Monitor"""
    
    def __init__(self, log_url: Optional[str] = None, tail_count: int = Config.DEFAULT_TAIL_COUNT,
                 poll_time: int = Config.DEFAULT_POLL_TIME, follow: bool = False,
                 pattern: Optional[str] = None, verbose: bool = False, quiet: bool = False,
                 es_output: bool = False, timeout_minutes: Optional[int] = None,
                 dns_resolve: bool = False, dns_workers: int = 20, dns_cache_size: int = 10000,
                 dns_public: bool = False, state_file: Optional[str] = None,
                 new_fetcher_logs: Optional[str] = None, fetch_workers: Optional[str] = None,
                 max_backlog: int = 2_000_000):
        self.log_url = log_url
        self.tail_count = tail_count
        self.poll_time = poll_time
        self.follow = follow
        self.pattern = re.compile(pattern) if pattern else None
        self.es_output = es_output
        self.timeout_minutes = timeout_minutes
        self.dns_resolve = dns_resolve
        self.dns_workers = dns_workers
        self.dns_cache_size = dns_cache_size
        self.dns_public = dns_public
        # Gap-free fetching (fetcher.py), enabled per log so it can be rolled out one log at a time.
        # new_fetcher_logs: comma-separated substrings of log URLs, or "all". Empty = old behaviour.
        self.new_fetcher_logs = [s.strip() for s in (new_fetcher_logs or '').split(',') if s.strip()]
        # fetch_workers: "substring=N,substring=N" parallel ranges per log (default 1).
        self.fetch_workers = {}
        for item in (fetch_workers or '').split(','):
            if '=' in item:
                key, _, value = item.partition('=')
                self.fetch_workers[key.strip()] = max(1, int(value))
        self.max_backlog = max_backlog
        self.position_store = PositionStore(state_file)

        # Initialize components
        self.logger = Logger(verbose, quiet)
        self.stats = Statistics()

        # Initialize adaptive rate limiter (moved here to be before HTTPClient)
        from rate_limiter import AdaptiveRateLimiter
        self.rate_limiter = AdaptiveRateLimiter(self.logger, default_batch_size=tail_count, default_poll_time=poll_time)

        self.http_client = HTTPClient(self.logger, poll_time, rate_limiter=self.rate_limiter)
        self.cert_parser = CertificateParser(self.logger)

        # Initialize Elasticsearch output if enabled
        if self.es_output:
            try:
                from elasticsearch_output import ElasticsearchOutput
                self.es_output_handler = ElasticsearchOutput()
                self.logger.info("✅ Elasticsearch output initialized")
            except ImportError as e:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(f"[{timestamp}] ❌ Failed to initialize Elasticsearch output: {e}")
                self.es_output = False

        # Initialize DNS resolver if enabled
        self.dns_resolver_thread = None
        self.dns_storage = None
        if self.dns_resolve:
            try:
                from dns_resolver import DNSResolverThread

                # Only create Elasticsearch storage if both DNS and ES output are enabled
                if self.es_output:
                    from dns_elasticsearch import DNSElasticsearchStorage
                    self.dns_storage = DNSElasticsearchStorage()
                    self.logger.info("✅ DNS resolution with Elasticsearch storage enabled")
                else:
                    self.logger.info("✅ DNS resolution enabled (without storage)")

                # Check for forced local resolver (e.g., for unbound on 127.0.0.1)
                force_local_resolver = os.getenv('DNS_LOCAL_RESOLVER')
                if force_local_resolver:
                    self.logger.info(f"🔧 Forcing DNS resolver to: {force_local_resolver}")

                self.dns_resolver_thread = DNSResolverThread(
                    logger=self.logger,
                    batch_size=500,  # Increased from 100 for better throughput
                    flush_interval=5,
                    storage=self.dns_storage,  # Will be None if ES not enabled
                    use_public_resolvers=self.dns_public,
                    force_local_resolver=force_local_resolver,
                    max_concurrent=self.dns_workers * 2,  # Double dns_workers for concurrency
                    num_workers=4  # 4 parallel batch processing threads
                )
            except ImportError as e:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(f"[{timestamp}] ❌ Failed to initialize DNS resolver: {e}")
                self.dns_resolve = False

        # Threading
        self.input_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.shutdown_event = threading.Event()
        self.is_shutting_down = False  # Track if we're already shutting down

        # Initialize public suffix list
        self.psl = publicsuffix2.PublicSuffixList()
    
    def scrub_x509_value(self, s: str) -> str:
        """Clean X509 string values"""
        if not s:
            return ""
        return s.replace('\x00', '').encode('utf-8', errors='ignore').decode('utf-8')
    
    def is_valid_hostname_or_ip(self, name: str) -> bool:
        """Check if name looks like a valid hostname or IP address"""
        if not name:
            return False
            
        if IPValidator.is_ip_address(name):
            return True
            
        # For hostnames, they shouldn't contain spaces or colons (unless IPv6)
        if ' ' in name or ':' in name:
            return False
            
        return True
    
    def get_sth(self, log_url: str) -> Dict:
        """Get Signed Tree Head from CT log"""
        url = f"{log_url.rstrip('/')}/ct/v1/get-sth"
        return self.http_client.download_json(url, self.shutdown_event)
    
    def get_entries(self, log_url: str, start: int, end: int) -> List[Dict]:
        """Get entries from CT log"""
        url = f"{log_url.rstrip('/')}/ct/v1/get-entries?start={start}&end={end}"
        data = self.http_client.download_json(url, self.shutdown_event)
        
        if 'error_message' in data:
            raise Exception(data['error_message'])
            
        return data.get('entries', [])
    
    def get_all_logs(self) -> List[str]:
        """Get all known CT logs from Chrome's log list"""
        self.logger.success(f"🚀 Loading all known logs from {Config.CHROME_LOG_LIST_URL}")
        
        data = self.http_client.download_json(Config.CHROME_LOG_LIST_URL, self.shutdown_event)
        logs = []
        
        for operator in data.get('operators', []):
            for log in operator.get('logs', []):
                if 'url' in log:
                    log_url = log['url']
                    # Filter out example/test domains
                    if 'example.com' in log_url or 'example.org' in log_url:
                        self.logger.debug(f"⚠️ Skipping example/test log: {log_url}")
                        continue
                    # Filter out localhost and other invalid domains
                    if any(invalid in log_url for invalid in ['localhost', '127.0.0.1', '::1']):
                        self.logger.debug(f"⚠️ Skipping invalid log URL: {log_url}")
                        continue
                    logs.append(log_url)
        
        self.logger.info(f"📋 Loaded {len(logs)} log servers")
        return logs
    
    @staticmethod
    def _issuance_identity(cert: x509.Certificate) -> Tuple[Optional[str], bool]:
        """(issuer+serial key, is_precert) for one parsed certificate.

        A precertificate and its final certificate have different SHA-1s but the same issuer and
        serial, so this key lets the output store ONE document per issued certificate. Measured
        2026-09-26 on 6,000 Argon/Xenon entries: Amazon, DigiCert, Microsoft and most Sectigo
        issuance is logged ONLY as a precert, so precerts cannot simply be dropped.
        """
        try:
            is_precert = any(ext.oid.dotted_string == CT_POISON_OID for ext in cert.extensions)
        except Exception:
            is_precert = False
        try:
            issuer = hashlib.sha1(cert.issuer.public_bytes()).hexdigest()[:16]
            return f"{issuer}:{cert.serial_number:x}", is_precert
        except Exception:
            return None, is_precert

    @staticmethod
    def _precert_from_extra_data(extra_data_b64: str) -> Optional[x509.Certificate]:
        """The pre_certificate from a precert entry's extra_data, or None."""
        try:
            extra = base64.b64decode(extra_data_b64)
            if len(extra) < 3:
                return None
            length = int.from_bytes(extra[0:3], 'big')
            if length == 0 or len(extra) < 3 + length:
                return None
            return x509.load_der_x509_certificate(extra[3:3 + length])
        except Exception:
            return None

    def parse_certificate_entry(self, entry: Dict) -> Optional[x509.Certificate]:
        """Parse certificate from CT log entry"""
        try:
            leaf_input = base64.b64decode(entry['leaf_input'])
            self.logger.debug(f"🔬 Parsing certificate entry: {len(leaf_input)} bytes")
            
            entry_type, cert_data, timestamp = self.cert_parser.parse_leaf_input(leaf_input)

            # A precert leaf holds only the TBSCertificate, which does not parse as a certificate,
            # so every precert used to be dropped (37% of one busy log's entries, measured
            # 2026-09-25). RFC 6962 puts the full precertificate first in extra_data
            # (PrecertChainEntry: a 3-byte length, then the DER), which parses normally.
            # Gated to entries from the gap-free fetcher (marked `_v2`) so it rolls out per log.
            if (entry_type == EntryType.PRECERT_LOG_ENTRY and entry.get('_v2')
                    and entry.get('extra_data')):
                precert = self._precert_from_extra_data(entry['extra_data'])
                if precert is not None:
                    return precert

            if not cert_data:
                return None

            return self.cert_parser.parse_certificate(cert_data, entry_type)
            
        except Exception as e:
            self.stats.increment_errors()
            
            # Log errors periodically to avoid spam
            if self.stats.get_stats()['errors'] % Config.ERROR_LOG_FREQUENCY == 1 or self.logger.verbose:
                error_msg = str(e)
                if len(error_msg) > 100:
                    error_msg = error_msg[:100] + "..."
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(
                    f"[{timestamp}] 🚫 Certificate parsing error (#{self.stats.get_stats()['errors']}): {error_msg}"
                )
            
            return None
    
    def extract_names_from_cert(self, cert: x509.Certificate) -> Set[str]:
        """Extract valid domain names from certificate"""
        names = set()
        
        # Extract Common Name
        try:
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    cn = attribute.value.lower()
                    self.logger.debug(f"🏷️ Common Name: {cn}")
                    if self.is_valid_hostname_or_ip(cn):
                        try:
                            # self.psl.get_tld(cn, strict=False)  # DISABLED: was rejecting valid domains
                            names.add(cn)
                            self.logger.debug(f"✅ Added CN: {cn}")
                        except Exception as e:
                            self.logger.debug(f"⚠️ Invalid TLD for CN {cn}: {e}")
        except Exception as e:
            self.logger.debug(f"❌ Error extracting CN: {e}")
        
        # Extract Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_count = 0
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    name = san.value.lower()
                    san_count += 1
                    self.logger.debug(f"🌐 SAN #{san_count}: {name}")
                    if self.is_valid_hostname_or_ip(name):
                        try:
                            # self.psl.get_tld(name, strict=False)  # DISABLED: was rejecting valid domains
                            names.add(name)
                            self.logger.debug(f"✅ Added SAN: {name}")
                        except Exception as e:
                            self.logger.debug(f"⚠️ Invalid TLD for SAN {name}: {e}")
            
            if self.logger.verbose and san_count > 0:
                self.logger.debug(f"📊 Total SANs processed: {san_count}, Valid names: {len(names)}")
                
        except x509.ExtensionNotFound:
            self.logger.debug("⚠️ No SAN extension found")
        except Exception as e:
            self.logger.debug(f"❌ Error extracting SANs: {e}")
        
        return names
    
    def process_certificate(self, entry: Dict) -> List[CTResult]:
        """Process a certificate entry and extract information"""
        self.stats.increment_processed()
        
        self.logger.debug(f"🔍 Processing certificate entry #{self.stats.get_stats()['processed']}")
        
        cert = self.parse_certificate_entry(entry)
        if not cert:
            self.logger.debug(f"❌ Failed to parse certificate entry #{self.stats.get_stats()['processed']}")
            return []
        
        self.stats.increment_input()
        
        self.logger.debug(f"✅ Valid certificate #{self.stats.get_stats()['input']}")
        
        if self.logger.verbose:
            self._log_certificate_details(cert)
        
        # Extract names
        names = self.extract_names_from_cert(cert)
        if not names:
            self.logger.debug("⚠️ No valid names extracted from certificate")
            return []
        
        self.logger.debug(f"🎯 Extracted {len(names)} valid names: {', '.join(sorted(names))}")
        
        # Calculate SHA1 hash
        sha1_hash = hashlib.sha1(cert.public_bytes(Encoding.DER)).hexdigest()
        self.logger.debug(f"🔐 SHA1: {sha1_hash}")
        issuance_key, is_precert = self._issuance_identity(cert)
        
        # Extract additional information
        cn = self._extract_common_name(cert)
        emails = self._extract_email_addresses(cert)
        ips = self._extract_ip_addresses(cert)
        dns_names = list(names)
        
        # Extract timestamp
        timestamp = self._extract_timestamp_from_entry(entry)
        
        # Create results
        results = []
        for name in names:
            if self.pattern and not self.pattern.search(name):
                continue

            if self.pattern:
                self.logger.debug(f"🎯 Pattern MATCH: {name} matches {self.pattern.pattern}")

            # Filter out the current domain name from dns_names (SANs)
            # Only keep SANs that are different from the current domain
            filtered_dns = [d for d in dns_names if d != name] if dns_names else None

            result = CTResult(
                name=name,
                timestamp=timestamp,
                cn=cn,
                sha1=sha1_hash,
                emails=emails if emails else None,
                ips=ips if ips else None,
                dns=filtered_dns if filtered_dns else None,  # Only store if there are other SANs
                issuance_key=issuance_key,
                precert=is_precert,
            )
            results.append(result)
        
        self.logger.debug(f"📤 Generated {len(results)} results for output")
        self.logger.debug(f"{'='*60}")
        
        return results
    
    def _log_certificate_details(self, cert: x509.Certificate):
        """Log certificate details for verbose mode"""
        try:
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            
            self.logger.debug("📋 Certificate Details:")
            self.logger.debug(f"   Subject: {subject}")
            self.logger.debug(f"   Issuer: {issuer}")
            self.logger.debug(f"   Valid: {not_before} to {not_after}")
        except Exception as e:
            self.logger.debug(f"⚠️ Error displaying cert details: {e}")
    
    def _extract_common_name(self, cert: x509.Certificate) -> str:
        """Extract common name from certificate"""
        try:
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    return self.scrub_x509_value(attribute.value.lower())
        except:
            pass
        return ""
    
    def _extract_email_addresses(self, cert: x509.Certificate) -> List[str]:
        """Extract email addresses from certificate"""
        emails = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for san in san_ext.value:
                if isinstance(san, x509.RFC822Name):
                    emails.append(self.scrub_x509_value(san.value.lower()))
        except:
            pass
        
        if emails:
            self.logger.debug(f"📧 Email addresses: {', '.join(emails)}")
        
        return emails
    
    def _extract_ip_addresses(self, cert: x509.Certificate) -> List[str]:
        """Extract IP addresses from certificate"""
        ips = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for san in san_ext.value:
                if isinstance(san, x509.IPAddress):
                    ips.append(str(san.value))
        except:
            pass
        
        if ips:
            self.logger.debug(f"🌐 IP addresses: {', '.join(ips)}")
        
        return ips
    
    def _extract_timestamp_from_entry(self, entry: Dict) -> int:
        """Extract timestamp from CT log entry"""
        try:
            leaf_input = base64.b64decode(entry['leaf_input'])
            
            if len(leaf_input) >= LeafInputStructure.TIMESTAMP_OFFSET + LeafInputStructure.TIMESTAMP_LENGTH:
                timestamp_bytes = leaf_input[
                    LeafInputStructure.TIMESTAMP_OFFSET:
                    LeafInputStructure.TIMESTAMP_OFFSET + LeafInputStructure.TIMESTAMP_LENGTH
                ]
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
                    qs = self.output_queue.qsize()
                    
                self.input_queue.task_done()
                    
            except queue.Empty:
                continue
            except Exception as e:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(f"[{timestamp}] ⚠️ Worker thread error: {e}")
    
    def output_thread(self):
        """Output thread to write results as JSON"""
        last_stats_time = time.time()
        
        while not self.shutdown_event.is_set():
            try:
                # Use non-blocking get to avoid queue.get() hang bug
                qs = self.output_queue.qsize()
                try:
                    result = self.output_queue.get_nowait()
                except queue.Empty:
                    time.sleep(0.1)  # Brief sleep before next iteration
                    continue
                # DEBUG: Log that we received an item
                if result is None:  # Shutdown signal
                    break
                    
                # Filter out None values for cleaner JSON
                data = {k: v for k, v in result.to_dict().items() if v is not None}

                # Add colored emoji prefix for terminal visibility
                domain_type = self._get_domain_type_emoji(result.name)

                # Print with color coding and better formatting
                current_time = time.time()

                # Add to DNS resolution queue if enabled
                if self.dns_resolve and self.dns_resolver_thread:
                    # Queue domain and SANs for resolution
                    cert_sha1 = data.get('sha1')

                    # Add main domain
                    self.dns_resolver_thread.add_domain(result.name, cert_sha1)

                    # Add SANs if present
                    if result.dns:
                        for san_domain in result.dns:
                            if san_domain != result.name:  # Skip if same as main domain
                                self.dns_resolver_thread.add_domain(san_domain, cert_sha1)

                # Send to Elasticsearch if enabled, otherwise output to stdout
                if self.es_output:
                    try:
                        # Get current log URL from monitor context
                        current_log_url = getattr(self, 'current_monitor_log_url', 'unknown')
                        self.es_output_handler.add_to_batch(data, current_log_url)
                        if self.pattern:
                            self.logger.success(f"🎯 MATCH FOUND: {domain_type} {json.dumps(data)} -> ES")
                        else:
                            self.logger.info(f"{domain_type} {json.dumps(data)} -> ES")
                    except Exception as e:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        self.logger.error(f"[{timestamp}] ❌ Failed to send to Elasticsearch: {e}")
                        # Fallback to stdout
                        self.logger.output(json.dumps(data))
                else:
                    # Show match notification for patterns
                    if self.pattern:
                        self.logger.success(f"🎯 MATCH FOUND: {domain_type} {json.dumps(data)}")
                        self.logger.output(json.dumps(data))
                    else:
                        if not self.logger.quiet:
                            self.logger.info(f"{domain_type} {json.dumps(data)}")
                        else:
                            self.logger.output(json.dumps(data))
                
                self.stats.increment_output()
                
                # Periodic status update when using patterns
                if self.pattern and current_time - last_stats_time > Config.STATS_UPDATE_INTERVAL:
                    stats = self.stats.get_stats()
                    self.logger.info(
                        f"📊 Pattern '{self.pattern.pattern}': {stats['output']} matches found "
                        f"from {stats['input']} valid certs"
                    )
                    last_stats_time = current_time
                
                self.output_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(f"[{timestamp}] ⚠️ Output thread error: {e}")
    
    def _get_domain_type_emoji(self, name: str) -> str:
        """Get appropriate emoji for domain type"""
        if IPValidator.is_ipv6(name):
            return "🔢"  # IPv6
        elif IPValidator.is_ipv4(name):
            return "📍"  # IPv4
        return "🌐"  # Domain name
    
    def monitor_log(self, log_url: str):
        """Monitor a single CT log"""
        if self._uses_new_fetcher(log_url):
            return self.monitor_log_v2(log_url)
        iteration = 0
        start_idx = 0

        self.logger.debug(f"🎯 Starting monitor for {log_url}")

        # Check if server is excluded by circuit breaker
        if self.rate_limiter.should_skip_server(log_url):
            server_info = self.rate_limiter.get_server_info(log_url)
            self.logger.warning(
                f"🚫 Skipping {log_url} - excluded until "
                f"{server_info.exclusion_until.strftime('%H:%M:%S')} due to excessive rate limiting",
                force=True
            )
            return

        # Set current log URL for Elasticsearch output context
        if self.es_output:
            self.current_monitor_log_url = log_url

        try:
            while True:
                # Check shutdown at start of loop
                if self.shutdown_event.is_set():
                    self.logger.debug(f"🛑 Shutdown event detected for {log_url}")
                    return
                if iteration > 0:
                    # Get adaptive poll interval for this server
                    poll_interval = self.rate_limiter.get_poll_interval(log_url)

                    if self.logger.verbose:
                        self.logger.debug(
                            f"💤 Iteration {iteration}: Sleeping for {poll_interval}s "
                            f"({log_url}) at index {start_idx}"
                        )
                    else:
                        self.logger.warning(
                            f"💤 Sleeping for {poll_interval}s ({log_url}) at index {start_idx}"
                        )
                    self.http_client._interruptible_sleep(poll_interval, self.shutdown_event)
                
                # Get current tree head
                self.logger.debug(f"📡 Fetching STH from {log_url}")
                
                sth = self.get_sth(log_url)
                if not sth:  # Empty dict means shutdown was requested
                    return
                tree_size = sth.get('tree_size', 0)
                if tree_size == 0:  # Invalid response
                    return
                
                self.logger.debug(
                    f"📊 Tree size: {tree_size}, Tree head timestamp: {sth.get('timestamp', 'N/A')}"
                )
                
                if iteration == 0:
                    # Start from tail
                    start_idx = max(0, tree_size - self.tail_count)
                    self.logger.success(
                        f"🎯 Starting from index {start_idx} (tree size: {tree_size}) for {log_url}"
                    )
                
                # Download entries in batches
                entries_processed = 0
                # Get adaptive batch size for this server
                batch_size = self.rate_limiter.get_batch_size(log_url)

                for idx in range(start_idx, tree_size, batch_size):
                    if self.shutdown_event.is_set():
                        self.logger.debug(f"🛑 Shutdown event detected for {log_url}")
                        return

                    end_idx = min(idx + batch_size - 1, tree_size - 1)
                    
                    self.logger.debug(f"📥 Downloading entries {idx}-{end_idx} from {log_url}")
                    
                    try:
                        entries = self.get_entries(log_url, idx, end_idx)
                        
                        self.logger.debug(f"✅ Downloaded {len(entries)} entries from {log_url}")
                        
                        for entry in entries:
                            if self.shutdown_event.is_set():
                                return
                            self.input_queue.put(entry)
                            entries_processed += 1
                        
                        # Progress indicator
                        if entries_processed > 0 and entries_processed % Config.PROGRESS_UPDATE_INTERVAL == 0:
                            self._log_progress(entries_processed, log_url)
                            
                    except Exception as e:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        self.logger.error(f"[{timestamp}] 💥 Failed to download entries for {log_url}: index {idx} -> {e}")
                        if self.logger.verbose:
                            import traceback
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            self.logger.error(f"[{timestamp}] 🔍 Full traceback: {traceback.format_exc()}")
                        return
                
                if entries_processed > 0:
                    self._log_batch_complete(entries_processed, log_url)
                
                start_idx = tree_size
                iteration += 1
                
                self.logger.debug(f"🔄 Completed iteration {iteration} for {log_url}")
                
                if not self.follow:
                    self.logger.debug(f"🏁 Finished monitoring {log_url} (follow mode disabled)")
                    break
                    
        except Exception as e:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.error(f"[{timestamp}] 💀 Failed to monitor log {log_url}: {e}")
            if self.logger.verbose:
                import traceback
                self.logger.error(f"🔍 Full traceback: {traceback.format_exc()}")
    
    def _uses_new_fetcher(self, log_url: str) -> bool:
        if not self.new_fetcher_logs:
            return False
        return 'all' in self.new_fetcher_logs or any(s in log_url for s in self.new_fetcher_logs)

    def _fetch_workers_for(self, log_url: str) -> int:
        for key, n in self.fetch_workers.items():
            if key in log_url:
                return n
        return 1

    def _enqueue_v2(self, entry: Dict) -> None:
        entry['_v2'] = True  # enables precert parsing for this entry (see parse_certificate_entry)
        self.input_queue.put(entry)

    def monitor_log_v2(self, log_url: str):
        """Monitor one log without gaps: advance by entries RETURNED, fetch ranges in parallel,
        never give up on a log, and resume from the persisted cursor after a restart."""
        workers = self._fetch_workers_for(log_url)
        def get_entries_once(a: int, b: int) -> List[Dict]:
            data = self.http_client.fetch_json_once(
                f"{log_url.rstrip('/')}/ct/v1/get-entries?start={a}&end={b}")
            if 'error_message' in data:
                raise Exception(data['error_message'])
            return data.get('entries', [])

        def on_rate_limited(err: RateLimited, delay: float) -> None:
            # Same wording as download_json's line, so per-host 429 counts stay comparable.
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.warning(f"[{timestamp}] ⏳ Rate limited - backing off {delay:.1f}s "
                                f"({err.host}) - status {err.status} (gap-free)", force=True)

        fetcher = RangeFetcher(
            get_entries=get_entries_once,
            on_rate_limited=on_rate_limited,
            on_entry=self._enqueue_v2,
            workers=workers,
            retry_sleep=self.poll_time / 6,
            shutdown_event=self.shutdown_event,
            sleep=lambda secs: self.http_client._interruptible_sleep(secs, self.shutdown_event),
        )
        cursor = self.position_store.get(log_url)
        first = True
        # Skip the poll sleep while behind, but only after a pass that made progress: a pass that
        # fetched nothing (a failing range) still sleeps, so an outage cannot become a hot loop.
        behind = False
        self.logger.warning(f"🧭 Gap-free fetcher for {log_url} (workers={workers}, "
                            f"saved cursor={cursor})", force=True)
        while not self.shutdown_event.is_set():
            try:
                if not first and not behind:
                    self.http_client._interruptible_sleep(
                        self.rate_limiter.get_poll_interval(log_url), self.shutdown_event)
                    if self.shutdown_event.is_set():
                        break
                first_pass, first = first, False

                if self.rate_limiter.should_skip_server(log_url):
                    continue  # excluded for now; check again after the next poll interval

                sth = self.get_sth(log_url)
                tree_size = (sth or {}).get('tree_size', 0)
                if not tree_size:
                    continue

                if first_pass:
                    if cursor is None or cursor > tree_size:
                        cursor = max(0, tree_size - self.tail_count)
                    elif tree_size - cursor > self.max_backlog:
                        skipped = tree_size - self.max_backlog - cursor
                        self.logger.warning(
                            f"⏭️ {log_url}: backlog {tree_size - cursor} exceeds --max-backlog "
                            f"{self.max_backlog}; skipping {skipped} entries", force=True)
                        cursor = tree_size - self.max_backlog

                before = cursor
                cursor = fetcher.fetch(
                    cursor, tree_size,
                    on_progress=lambda c: self.position_store.set(log_url, c))
                head = self.get_sth(log_url) or {}
                behind = cursor > before and head.get('tree_size', 0) - cursor > 1000
                self.logger.warning(
                    f"📍 {log_url} cursor={cursor} head={tree_size} lag={tree_size - cursor} "
                    f"fetched={cursor - before}", force=True)
                if not self.follow:
                    break  # one pass only, like the classic loop without -f
            except Exception as e:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(f"[{timestamp}] 💥 {log_url}: {e}; retrying after the poll interval")
        self.position_store.flush()

    def _log_progress(self, entries_processed: int, log_url: str):
        """Log progress update"""
        self.logger.info(f"📊 Progress: {entries_processed} entries processed from {log_url}")
        
        stats = self.stats.get_stats()
        if stats['errors'] > 0:
            error_rate = (stats['errors'] / max(stats['processed'], 1)) * 100
            self.logger.warning(
                f"📈 Stats: {stats['input']} valid certs, "
                f"{stats['errors']} parse errors ({error_rate:.1f}%)"
            )
    
    def _log_batch_complete(self, entries_processed: int, log_url: str):
        """Log batch completion"""
        stats = self.stats.get_stats()
        success_rate = (stats['input'] / max(stats['processed'], 1)) * 100
        self.logger.success(
            f"✅ Batch complete: {entries_processed} entries, "
            f"{stats['input']} valid certs ({success_rate:.1f}%) from {log_url}"
        )
    
    def run(self):
        """Main execution method"""
        exit_code = 0
        try:
            self.logger.info(f"{Style.BRIGHT}🔍 Certificate Transparency Log Monitor Starting...{Style.RESET_ALL}")

            # Determine which logs to monitor
            if self.log_url:
                logs = [self.log_url]
                self.logger.success(f"🎯 Monitoring single log: {self.log_url}")
            else:
                logs = self.get_all_logs()

            # Show pattern info
            if self.pattern:
                self.logger.info(f"🔍 Searching for pattern: {self.pattern.pattern}")
                self.logger.warning("💡 Tip: This will only show certificates matching your pattern!")

            # Start worker threads
            num_workers = min(Config.WORKER_THREAD_COUNT, len(logs))
            workers = []
            self.logger.info(f"🔧 Starting {num_workers} worker threads")
            for _ in range(num_workers):
                worker = threading.Thread(target=self.worker_thread, daemon=True)
                worker.start()
                workers.append(worker)

            # Start output thread
            self.logger.info("📝 Starting output thread")
            output_worker = threading.Thread(target=self.output_thread, daemon=True)
            output_worker.start()

            # Set up timeout if specified
            if self.timeout_minutes:
                timeout_seconds = self.timeout_minutes * 60
                self.logger.info(f"⏰ Timeout set: {self.timeout_minutes} minutes ({timeout_seconds} seconds)")
                self.start_time = time.time()

            # Monitor logs
            self.logger.success(f"🚀 Beginning log monitoring with {len(logs)} log(s)")

            executor = ThreadPoolExecutor(max_workers=len(logs))
            try:
                futures = [executor.submit(self.monitor_log, log_url) for log_url in logs]

                # Wait for completion or interruption
                last_retry_time = time.time()
                try:
                    for future in as_completed(futures):
                        if self.shutdown_event.is_set():
                            # Cancel remaining futures
                            for f in futures:
                                f.cancel()
                            break

                        # Check timeout if specified
                        if self.timeout_minutes and time.time() - self.start_time >= timeout_seconds:
                            self.logger.info(f"⏰ Timeout reached after {self.timeout_minutes} minutes, shutting down...")
                            self.shutdown_event.set()
                            # Cancel remaining futures
                            for f in futures:
                                f.cancel()
                            break

                        # Periodically retry failed Elasticsearch batches (every 30 seconds)
                        current_time = time.time()
                        if (self.es_output and hasattr(self, 'es_output_handler') and
                            current_time - last_retry_time >= 30):
                            try:
                                self.es_output_handler.retry_failed_batches()
                            except Exception as e:
                                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                self.logger.error(f"[{timestamp}] ❌ Failed to retry ES batches: {e}")
                            last_retry_time = current_time

                        try:
                            future.result(timeout=0.5)  # Check result with timeout
                        except TimeoutError:
                            continue  # Future not done yet, check shutdown again
                        except Exception as e:
                            if not self.shutdown_event.is_set():
                                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                self.logger.error(f"[{timestamp}] 💥 Log monitoring error: {e}")
                except KeyboardInterrupt:
                    # Cancel all futures on interrupt
                    for f in futures:
                        f.cancel()
                    # Don't re-raise if we're already shutting down
                    if not self.shutdown_event.is_set():
                        raise
            finally:
                # Shutdown executor immediately without waiting for tasks to complete
                executor.shutdown(wait=False)
            
        except KeyboardInterrupt:
            if not self.is_shutting_down:
                self.is_shutting_down = True
                self.shutdown_event.set()  # Signal all threads to stop
                self.logger.warning("\n🛑 Interrupt received, exiting...", force=True)
            else:
                # Second Ctrl+C - force immediate exit
                self.logger.warning("\n⚠️ Force exit requested", force=True)
                os._exit(1)
        except Exception as e:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.error(f"[{timestamp}] 💀 Fatal error: {e}")
            exit_code = 1
        finally:
            # Signal shutdown to all threads and print stats
            self.shutdown_event.set()
            self.is_shutting_down = True

            # Clean up DNS resolver if enabled
            if self.dns_resolve:
                if self.dns_resolver_thread:
                    try:
                        self.dns_resolver_thread.close()
                        self.logger.info("✅ DNS resolver closed")
                    except Exception as e:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        self.logger.error(f"[{timestamp}] ❌ Error closing DNS resolver: {e}")

                if self.dns_storage:
                    try:
                        self.dns_storage.close()
                        self.logger.info("✅ DNS storage closed")
                    except Exception as e:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        self.logger.error(f"[{timestamp}] ❌ Error closing DNS storage: {e}")

            # Clean up Elasticsearch connection if enabled
            if self.es_output and hasattr(self, 'es_output_handler'):
                try:
                    self.es_output_handler.close()
                    self.logger.info("✅ Elasticsearch connection closed")
                except Exception as e:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    self.logger.error(f"[{timestamp}] ❌ Error closing Elasticsearch connection: {e}")

            self._print_final_statistics()
        
        return exit_code
    
    def _print_final_statistics(self):
        """Print final statistics summary"""
        stats = self.stats.get_stats()
        total_processed = max(stats['processed'], 1)
        success_rate = (stats['input'] / total_processed) * 100
        error_rate = (stats['errors'] / total_processed) * 100
        domains_per_cert = (stats['output'] / max(stats['input'], 1))
        
        # Always show final statistics
        self.logger.info("\n📊 Final Statistics:", force=True)
        self.logger.success(f"  🎯 Total entries processed: {Style.BRIGHT}{total_processed}{Style.RESET_ALL}", force=True)
        self.logger.success(f"  ✅ Valid certificates: {Style.BRIGHT}{stats['input']}{Style.RESET_ALL} ({success_rate:.1f}%)", force=True)
        self.logger.error(f"  ❌ Parse errors: {Style.BRIGHT}{stats['errors']}{Style.RESET_ALL} ({error_rate:.1f}%)", force=True)
        
        if self.pattern:
            match_rate = (stats['output'] / max(stats['input'], 1)) * 100
            self.logger.info(
                f"  🎯 Pattern matches: {Style.BRIGHT}{stats['output']}{Style.RESET_ALL} "
                f"({match_rate:.1f}% of valid certs)",
                force=True
            )
            if stats['output'] == 0:
                self.logger.warning(
                    "  💡 No matches found - try a broader pattern or increase -n (tail count)",
                    force=True
                )
        else:
            self.logger.info(
                f"  📝 Domain names output: {Style.BRIGHT}{stats['output']}{Style.RESET_ALL} "
                f"(avg {domains_per_cert:.1f} domains per cert)",
                force=True
            )
        
        # Show rate limiting summary
        if self.http_client.rate_limited_logs:
            self.logger.warning(
                f"  ⚠️ Rate limited logs: {len(self.http_client.rate_limited_logs)} "
                f"(consider using -p with higher value)",
                force=True
            )

        # Show adaptive rate limiting status
        rate_summary = self.rate_limiter.get_summary()
        if rate_summary:
            self.logger.info("", force=True)  # Empty line
            self.logger.info(rate_summary, force=True)


def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}🔍 Certificate Transparency Log Monitor v{__version__}{Style.RESET_ALL} - Extracts domain names from CT logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.GREEN}Examples:{Style.RESET_ALL}
  {Fore.YELLOW}python ct-monitor.py -l https://ct.googleapis.com/logs/xenon2024/{Style.RESET_ALL}
  {Fore.YELLOW}python ct-monitor.py -f -n 1000{Style.RESET_ALL}
  {Fore.YELLOW}python ct-monitor.py -m ".*\\.example\\.com$" -p 30{Style.RESET_ALL}
  {Fore.YELLOW}python ct-monitor.py -v -m "microsoft" -n 500{Style.RESET_ALL}
  {Fore.YELLOW}python ct-monitor.py -q -m "github" -n 1000 > domains.json{Style.RESET_ALL}
  {Fore.YELLOW}python ct-monitor.py --es-output --timeout 30 -f{Style.RESET_ALL}
  {Fore.YELLOW}python ct-monitor.py --es-output -n 5000{Style.RESET_ALL}

{Fore.BLUE}Output Emojis:{Style.RESET_ALL}
  🌐 Domain name
  📍 IPv4 address  
  🔢 IPv6 address

{Fore.CYAN}Version: {__version__} | License: {__license__}{Style.RESET_ALL}
        """
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('-l', '--log-url', help='Only read from the specified CT log URL')
    parser.add_argument('-n', '--tail-count', type=int, default=Config.DEFAULT_TAIL_COUNT, 
                       help=f'Number of entries from the end to start from (default: {Config.DEFAULT_TAIL_COUNT})')
    parser.add_argument('-p', '--poll-time', type=int, default=Config.DEFAULT_POLL_TIME,
                       help=f'Number of seconds to wait between polls (default: {Config.DEFAULT_POLL_TIME})')
    parser.add_argument('-f', '--follow', action='store_true',
                       help='Follow the tail of the CT log')
    parser.add_argument('-m', '--pattern', help='Only show entries matching this regex pattern')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output showing detailed certificate processing')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode - suppress all status messages, only output results')
    parser.add_argument('--timeout', type=int, metavar='MINUTES',
                       help='Run for specified minutes then exit (useful for testing)')
    parser.add_argument('--es-output', action='store_true',
                       help='Output to Elasticsearch instead of stdout')
    parser.add_argument('--dns-resolve', action='store_true',
                       help='Enable DNS resolution for discovered domains')
    parser.add_argument('--dns-workers', type=int, default=20,
                       help='Number of concurrent DNS resolution workers (default: 20)')
    parser.add_argument('--dns-cache-size', type=int, default=10000,
                       help='DNS cache size (default: 10000)')
    parser.add_argument('--dns-public', action='store_true',
                       help='Use public DNS resolvers (1.1.1.1, 8.8.8.8, etc.) with round-robin')
    parser.add_argument('--state-file', metavar='PATH',
                       help='Persist each log\'s position here and resume from it after a restart')
    parser.add_argument('--new-fetcher-logs', metavar='SUBSTRINGS',
                       help='Use the gap-free fetcher for logs whose URL contains any of these '
                            'comma-separated substrings, or "all"')
    parser.add_argument('--fetch-workers', metavar='MAP',
                       help='Parallel ranges per log for the gap-free fetcher, e.g. "argon2026h2=4"')
    parser.add_argument('--max-backlog', type=int, default=2_000_000,
                       help='On start, skip ahead if the saved position is further behind than this '
                            '(default: 2000000)')

    args = parser.parse_args()
    
    # Validate conflicting options
    if args.verbose and args.quiet:
        parser.error("Cannot use both --verbose and --quiet options together")
    
    # Initialize logger for startup banner
    logger = Logger(args.verbose, args.quiet)
    
    # Print startup banner (only if not quiet)
    if not args.quiet:
        verbose_status = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if args.verbose else f"{Fore.YELLOW}No{Style.RESET_ALL}"
        quiet_status = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if args.quiet else f"{Fore.YELLOW}No{Style.RESET_ALL}"
        logger.info(f"""
{Fore.CYAN}{Style.BRIGHT}🔍 Certificate Transparency Log Monitor v{__version__}{Style.RESET_ALL}
{Fore.BLUE}{'='*60}{Style.RESET_ALL}
{Fore.GREEN}🎯 Target:{Style.RESET_ALL} {'Single log' if args.log_url else 'All known logs'}
{Fore.GREEN}📊 Tail count:{Style.RESET_ALL} {args.tail_count}
{Fore.GREEN}⏱️  Poll interval:{Style.RESET_ALL} {args.poll_time}s
{Fore.GREEN}🔄 Follow mode:{Style.RESET_ALL} {'Yes' if args.follow else 'No'}
{Fore.GREEN}🔍 Pattern:{Style.RESET_ALL} {args.pattern if args.pattern else 'None'}
{Fore.GREEN}🗣️  Verbose mode:{Style.RESET_ALL} {verbose_status}
{Fore.GREEN}🤫 Quiet mode:{Style.RESET_ALL} {quiet_status}
{Fore.BLUE}{'='*60}{Style.RESET_ALL}
        """)
        
        if args.verbose:
            logger.info("🔍 Verbose mode enabled - detailed certificate processing information will be shown")
        
        if args.quiet:
            logger.info("🤫 Quiet mode enabled - only results will be output")

        if args.es_output:
            logger.info("📊 Elasticsearch output enabled - sending to ES instead of stdout")

        if args.dns_resolve:
            resolver_info = "public resolvers" if args.dns_public else "system resolver"
            logger.info(f"🔍 DNS resolution enabled - {args.dns_workers} workers, cache: {args.dns_cache_size}, using {resolver_info}")
    
    monitor = CTLogMonitor(
        log_url=args.log_url,
        tail_count=args.tail_count,
        poll_time=args.poll_time,
        follow=args.follow,
        pattern=args.pattern,
        verbose=args.verbose,
        quiet=args.quiet,
        es_output=args.es_output,
        timeout_minutes=args.timeout,
        dns_resolve=args.dns_resolve,
        dns_workers=args.dns_workers,
        dns_cache_size=args.dns_cache_size,
        dns_public=args.dns_public,
        state_file=args.state_file,
        new_fetcher_logs=args.new_fetcher_logs,
        fetch_workers=args.fetch_workers,
        max_backlog=args.max_backlog
    )
    
    return monitor.run()


if __name__ == '__main__':
    sys.exit(main())
