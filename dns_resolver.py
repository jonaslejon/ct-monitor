#!/usr/bin/env python3
"""
DNS Resolver module for CT Monitor
Efficiently resolves domains from CT logs with caching, deduplication, and Elasticsearch storage
"""

import asyncio
import socket
import hashlib
import time
from typing import Dict, List, Optional, Tuple
from collections import deque, OrderedDict
from datetime import datetime, timedelta
import logging
import json
import struct
import ipaddress
from dataclasses import dataclass, asdict
from threading import Lock
import concurrent.futures

try:
    import dns.asyncresolver
    import dns.resolver
    import dns.exception
    ASYNC_DNS_AVAILABLE = True
except ImportError:
    ASYNC_DNS_AVAILABLE = False
    import socket  # Fallback to socket resolution

@dataclass
class DNSResult:
    """Represents a DNS resolution result"""
    domain: str
    ips: List[str]
    cert_sha1: Optional[str] = None
    record_type: str = "A"
    timestamp: int = None
    ttl: int = 3600
    is_wildcard: bool = False
    root_domain: Optional[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = int(time.time())

    def to_es_doc(self) -> Dict:
        """Convert to Elasticsearch document format"""
        doc = {
            "d": self.domain,
            "ts": self.timestamp,
            "t": self.record_type,
            "ttl": self.ttl,
            "w": self.is_wildcard
        }

        if self.ips:
            doc["i"] = self.ips
            # Store IPv4 as integers for efficient range queries
            doc["ii"] = []
            for ip in self.ips:
                try:
                    if ":" not in ip:  # IPv4
                        doc["ii"].append(struct.unpack("!I", socket.inet_aton(ip))[0])
                except:
                    pass

        if self.cert_sha1:
            doc["c"] = self.cert_sha1

        if self.root_domain:
            doc["r"] = self.root_domain

        if self.error:
            doc["e"] = self.error

        # Add deduplication hash
        hash_str = f"{self.domain}:{','.join(sorted(self.ips or []))}:{self.cert_sha1 or ''}"
        doc["h"] = hashlib.sha256(hash_str.encode()).hexdigest()[:16]

        return doc


class LRUCache:
    """Thread-safe LRU cache for DNS results"""

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 300):
        self.cache: OrderedDict[str, Tuple[DNSResult, float]] = OrderedDict()
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.lock = Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[DNSResult]:
        with self.lock:
            if key in self.cache:
                result, expiry = self.cache[key]
                if time.time() < expiry:
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    self.hits += 1
                    return result
                else:
                    # Expired
                    del self.cache[key]

            self.misses += 1
            return None

    def put(self, key: str, value: DNSResult):
        with self.lock:
            # Skip caching if max_size is 0
            if self.max_size == 0:
                return

            # Remove oldest if at capacity
            if len(self.cache) >= self.max_size and len(self.cache) > 0:
                self.cache.popitem(last=False)

            expiry = time.time() + self.ttl_seconds
            self.cache[key] = (value, expiry)
            self.cache.move_to_end(key)

    def get_stats(self) -> Dict:
        with self.lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0
            return {
                "size": len(self.cache),
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": hit_rate
            }


class DNSResolver:
    """Async DNS resolver with batching and caching"""

    # Public DNS resolvers for round-robin
    PUBLIC_RESOLVERS = [
        '1.1.1.1',      # Cloudflare
        '8.8.8.8',      # Google
        '8.8.4.4',      # Google Secondary
        '1.0.0.1',      # Cloudflare Secondary
        '9.9.9.9',      # Quad9
        '149.112.112.112'  # Quad9 Secondary
    ]

    def __init__(self,
                 logger: logging.Logger,
                 max_concurrent: int = 20,
                 timeout: float = 2.0,
                 cache_size: int = 10000,
                 cache_ttl: int = 300,
                 use_public_resolvers: bool = False,
                 force_local_resolver: str = None):

        self.logger = logger
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.use_public_resolvers = use_public_resolvers

        # Caching
        self.cache = LRUCache(cache_size, cache_ttl)

        # Round-robin resolver index
        self.resolver_index = 0
        self.resolver_lock = Lock()

        # Statistics
        self.stats = {
            "total_queries": 0,
            "successful": 0,
            "failed": 0,
            "cached": 0,
            "wildcards_expanded": 0,
            "resolver_usage": {ip: 0 for ip in self.PUBLIC_RESOLVERS} if use_public_resolvers else {}
        }

        # Setup resolver
        if ASYNC_DNS_AVAILABLE:
            if use_public_resolvers:
                # Create multiple resolvers for public DNS
                self.resolvers = []
                for dns_server in self.PUBLIC_RESOLVERS:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.nameservers = [dns_server]
                    resolver.timeout = timeout
                    resolver.lifetime = timeout * 2
                    self.resolvers.append(resolver)
                self.logger.info(f"✅ Using public DNS resolvers (round-robin): {', '.join(self.PUBLIC_RESOLVERS)}")
            else:
                # Use system resolver - it automatically reads system configuration
                self.async_resolver = dns.asyncresolver.Resolver()

                # Check for forced local resolver (for unbound/local DNS)
                if force_local_resolver:
                    self.async_resolver.nameservers = [force_local_resolver]
                    self.logger.info(f"✅ Forcing local DNS resolver: {force_local_resolver}")

                self.async_resolver.timeout = timeout
                self.async_resolver.lifetime = timeout * 2

                # Log which nameservers are being used (from system config)
                nameservers = self.async_resolver.nameservers[:3] if self.async_resolver.nameservers else ["system default"]

                # Detect systemd-resolved
                if nameservers and nameservers[0] == '127.0.0.53':
                    self.logger.info(f"✅ Using systemd-resolved stub resolver at 127.0.0.53")
                    self.logger.info("   ℹ️  DNS queries go through systemd-resolved → upstream resolver")
                    self.logger.info("   💡 To bypass: export DNS_LOCAL_RESOLVER=127.0.0.1")
                else:
                    self.logger.info(f"✅ Using system DNS resolver: {', '.join(map(str, nameservers))}")
        else:
            self.logger.warning("⚠️ dnspython not installed - using fallback socket resolution")
            self.logger.warning("   Install dnspython for proper DNS resolver support: pip install dnspython")

    def get_next_resolver(self):
        """Get next resolver in round-robin fashion"""
        if not self.use_public_resolvers:
            return self.async_resolver

        with self.resolver_lock:
            resolver = self.resolvers[self.resolver_index]
            current_dns = self.PUBLIC_RESOLVERS[self.resolver_index]

            # Track usage
            self.stats["resolver_usage"][current_dns] += 1

            # Move to next resolver
            self.resolver_index = (self.resolver_index + 1) % len(self.resolvers)

            return resolver

    def extract_root_domain(self, domain: str) -> str:
        """Extract root domain from subdomain"""
        parts = domain.split('.')
        if len(parts) >= 2:
            # Simple extraction - can be enhanced with PSL
            return '.'.join(parts[-2:])
        return domain

    def expand_wildcard(self, domain: str) -> List[str]:
        """Expand wildcard domain to common subdomains"""
        if not domain.startswith('*.'):
            return [domain]

        base = domain[2:]  # Remove *.
        common_subdomains = ['www', 'mail', 'api', 'app', 'admin', 'ftp', 'smtp', 'pop', 'imap']

        expanded = [base]  # Include base domain
        for sub in common_subdomains:
            expanded.append(f"{sub}.{base}")

        self.stats["wildcards_expanded"] += 1
        return expanded

    def is_internal_domain(self, domain: str) -> bool:
        """Check if domain is internal/private"""
        internal_tlds = ['.local', '.internal', '.lan', '.home', '.corp', '.private']

        # Check TLD
        for tld in internal_tlds:
            if domain.endswith(tld):
                return True

        # Check for IP-like domains
        try:
            ipaddress.ip_address(domain)
            return True
        except:
            pass

        # Check for localhost variants
        if domain in ['localhost', 'localhost.localdomain']:
            return True

        return False

    async def resolve_domain_async(self, domain: str, cert_sha1: Optional[str] = None) -> DNSResult:
        """Resolve a single domain asynchronously"""

        # Check cache first
        cache_key = f"{domain}:{cert_sha1 or ''}"
        cached = self.cache.get(cache_key)
        if cached:
            self.stats["cached"] += 1
            return cached

        self.stats["total_queries"] += 1

        # Check for internal domains
        if self.is_internal_domain(domain):
            result = DNSResult(
                domain=domain,
                ips=[],
                cert_sha1=cert_sha1,
                error="internal_domain",
                root_domain=self.extract_root_domain(domain)
            )
            self.cache.put(cache_key, result)
            return result

        try:
            if ASYNC_DNS_AVAILABLE:
                # Get the appropriate resolver (system or round-robin public)
                resolver = self.get_next_resolver()

                # Use async DNS resolution
                # Debug log the actual nameserver being used
                if not self.use_public_resolvers:
                    self.logger.debug(f"Resolving {domain} using nameserver: {resolver.nameservers[0]}:{resolver.port}")

                answers = await resolver.resolve(domain, 'A')
                ips = [str(rdata) for rdata in answers]
                ttl = answers.response.answer[0].ttl if answers.response.answer else 3600

                # Log which resolver was used if public resolvers enabled
                if self.use_public_resolvers:
                    used_dns = self.PUBLIC_RESOLVERS[(self.resolver_index - 1) % len(self.PUBLIC_RESOLVERS)]
                    self.logger.debug(f"Resolved {domain} via {used_dns}")
            else:
                # Fallback to socket resolution
                ips = await asyncio.get_event_loop().run_in_executor(
                    None, self._socket_resolve, domain
                )
                ttl = 3600  # Default TTL

            result = DNSResult(
                domain=domain,
                ips=ips,
                cert_sha1=cert_sha1,
                ttl=ttl,
                root_domain=self.extract_root_domain(domain)
            )

            self.stats["successful"] += 1
            self.cache.put(cache_key, result)
            return result

        except Exception as e:
            error_type = self._classify_error(e)
            result = DNSResult(
                domain=domain,
                ips=[],
                cert_sha1=cert_sha1,
                error=error_type,
                root_domain=self.extract_root_domain(domain)
            )

            self.stats["failed"] += 1
            self.cache.put(cache_key, result)
            return result

    def _socket_resolve(self, domain: str) -> List[str]:
        """Fallback socket-based resolution

        Note: This method uses the system's resolver through socket.getaddrinfo()
        For proper DNS resolver usage (respecting /etc/resolv.conf), install dnspython
        """
        try:
            # socket.getaddrinfo uses the system resolver (via glibc)
            # This should respect /etc/resolv.conf and nsswitch.conf
            result = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list(set([addr[4][0] for addr in result]))
            return ips
        except:
            return []

    def _classify_error(self, error: Exception) -> str:
        """Classify DNS error type"""
        error_str = str(error).lower()

        if 'nxdomain' in error_str or 'not exist' in error_str:
            return 'nxdomain'
        elif 'timeout' in error_str:
            return 'timeout'
        elif 'servfail' in error_str:
            return 'servfail'
        elif 'refused' in error_str:
            return 'refused'
        else:
            return 'unknown'

    async def resolve_batch(self,
                           domains: List[Tuple[str, Optional[str]]]) -> List[DNSResult]:
        """Resolve a batch of domains concurrently"""

        # Deduplicate
        unique_domains = {}
        for domain, cert_sha1 in domains:
            key = f"{domain}:{cert_sha1 or ''}"
            if key not in unique_domains:
                unique_domains[key] = (domain, cert_sha1)

        # Create tasks with semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def resolve_with_semaphore(domain: str, cert_sha1: Optional[str]):
            async with semaphore:
                return await self.resolve_domain_async(domain, cert_sha1)

        tasks = []
        for domain, cert_sha1 in unique_domains.values():
            # Handle wildcards
            if domain.startswith('*.'):
                expanded = self.expand_wildcard(domain)
                for exp_domain in expanded[:3]:  # Limit expansion to first 3
                    tasks.append(resolve_with_semaphore(exp_domain, cert_sha1))
            else:
                tasks.append(resolve_with_semaphore(domain, cert_sha1))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, DNSResult):
                valid_results.append(result)
            else:
                self.logger.debug(f"Resolution error: {result}")

        return valid_results

    def get_stats(self) -> Dict:
        """Get resolver statistics"""
        stats = self.stats.copy()
        stats["cache_stats"] = self.cache.get_stats()
        return stats


class DNSResolverThread:
    """Thread-based wrapper for DNS resolution with parallel processing"""

    # Maximum queue size to prevent memory leaks (default 1M domains ~ 150MB)
    DEFAULT_MAX_QUEUE_SIZE = 1000000

    def __init__(self,
                 logger: logging.Logger,
                 batch_size: int = 500,  # Increased from 100 for better throughput
                 flush_interval: int = 5,
                 storage=None,
                 use_public_resolvers: bool = False,
                 force_local_resolver: str = None,
                 max_queue_size: int = None,
                 max_concurrent: int = 100,  # Increased from 50 for more parallelism
                 num_workers: int = 4):  # Multiple worker threads for parallel batch processing

        self.logger = logger
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.storage = storage
        self.max_queue_size = max_queue_size or self.DEFAULT_MAX_QUEUE_SIZE
        self.num_workers = num_workers

        self.resolver = DNSResolver(logger,
                                   max_concurrent=max_concurrent,
                                   use_public_resolvers=use_public_resolvers,
                                   force_local_resolver=force_local_resolver)
        self.queue: deque = deque(maxlen=self.max_queue_size)
        self.queue_lock = Lock()
        self.last_flush = time.time()
        self.last_stats_log = time.time()
        self.dropped_domains = 0  # Track domains dropped due to queue overflow

        # Background thread pool - multiple workers for parallel batch processing
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_workers)
        self.active_workers = 0
        self.workers_lock = Lock()
        self.loop = None
        self.running = False
        self.shutting_down = False

        # Async storage queue for non-blocking ES writes
        self.storage_queue: deque = deque(maxlen=50000)  # Buffer for async storage
        self.storage_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.storage_running = False

    def add_domain(self, domain: str, cert_sha1: Optional[str] = None):
        """Add domain to resolution queue"""
        if self.shutting_down:
            return  # Don't accept new domains during shutdown

        with self.queue_lock:
            # Track if queue is at capacity (deque with maxlen drops oldest)
            was_full = len(self.queue) >= self.max_queue_size
            self.queue.append((domain, cert_sha1))
            if was_full:
                self.dropped_domains += 1

            # Trigger flush if batch is full or enough time has passed
            current_time = time.time()
            if len(self.queue) >= self.batch_size or (current_time - self.last_flush) >= self.flush_interval:
                self._trigger_flush()
                self.last_flush = current_time

            # Log queue stats periodically (every 60 seconds)
            if current_time - self.last_stats_log >= 60:
                queue_size = len(self.queue)
                if queue_size > 1000 or self.dropped_domains > 0:
                    self.logger.warning(
                        f"DNS queue: {queue_size:,} pending, {self.dropped_domains:,} dropped"
                    )
                self.last_stats_log = current_time

    def _trigger_flush(self):
        """Trigger batch resolution - spawn workers up to num_workers limit"""
        with self.workers_lock:
            # Spawn new workers if we have capacity and work to do
            while self.active_workers < self.num_workers:
                with self.queue_lock:
                    if len(self.queue) < self.batch_size and self.active_workers > 0:
                        break  # Don't spawn more workers for small remaining queues
                self.active_workers += 1
                self.executor.submit(self._run_batch_resolution)

        # Also trigger async storage flush if needed
        self._trigger_storage_flush()

    def _trigger_storage_flush(self):
        """Trigger async storage flush"""
        if not self.storage_running and len(self.storage_queue) > 0:
            self.storage_running = True
            self.storage_executor.submit(self._run_storage_flush)

    def _run_storage_flush(self):
        """Flush storage queue to Elasticsearch asynchronously"""
        try:
            while not self.shutting_down and self.storage_queue:
                # Get batch of results to store
                batch = []
                for _ in range(min(2000, len(self.storage_queue))):  # ES batch size 2000
                    if self.storage_queue:
                        batch.append(self.storage_queue.popleft())

                if batch and self.storage:
                    for result in batch:
                        self.storage.add_result(result)
                    self.storage.flush()
        finally:
            self.storage_running = False

    def _run_batch_resolution(self):
        """Run batch resolution in thread - processes continuously while queue has work"""
        # Create event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            # Process batches continuously while queue has work
            while not self.shutting_down:
                # Get batch
                with self.queue_lock:
                    if len(self.queue) == 0:
                        break  # No more work
                    batch = []
                    for _ in range(min(self.batch_size, len(self.queue))):
                        if self.queue:
                            batch.append(self.queue.popleft())

                if not batch:
                    break

                # Run async resolution
                results = loop.run_until_complete(
                    self.resolver.resolve_batch(batch)
                )

                # Queue results for async storage (non-blocking)
                self._queue_results_for_storage(results)

        finally:
            with self.workers_lock:
                self.active_workers -= 1
            loop.close()

    def _queue_results_for_storage(self, results: List[DNSResult]):
        """Queue results for async storage - non-blocking"""
        for result in results:
            if result.ips:
                self.logger.debug(f"Resolved {result.domain} -> {', '.join(result.ips)}")
            else:
                self.logger.debug(f"Failed to resolve {result.domain}: {result.error}")

            # Add to storage queue for async processing
            if self.storage:
                self.storage_queue.append(result)

        # Trigger async storage if queue is getting large
        if len(self.storage_queue) >= 1000:
            self._trigger_storage_flush()

    def _process_results(self, results: List[DNSResult]):
        """Process resolution results (legacy sync method)"""
        for result in results:
            if result.ips:
                self.logger.debug(f"Resolved {result.domain} -> {', '.join(result.ips)}")
            else:
                self.logger.debug(f"Failed to resolve {result.domain}: {result.error}")

            # Store in Elasticsearch if storage is configured
            if self.storage:
                self.storage.add_result(result)

        # Flush storage if configured
        if self.storage:
            self.storage.flush()

    def get_queue_stats(self) -> Dict:
        """Get queue statistics"""
        with self.queue_lock:
            return {
                "queue_size": len(self.queue),
                "max_queue_size": self.max_queue_size,
                "dropped_domains": self.dropped_domains,
                "active_workers": self.active_workers,
                "storage_queue_size": len(self.storage_queue),
                "resolver_stats": self.resolver.get_stats()
            }

    def close(self):
        """Cleanup resources"""
        # Mark as shutting down to prevent new domains
        self.shutting_down = True

        # Process any remaining domains
        with self.queue_lock:
            if self.queue:
                # Only trigger flush if we have a small number of domains
                # Don't block on shutdown for large queues
                if len(self.queue) < 500:
                    self._trigger_flush()
                else:
                    self.logger.info(f"Skipping {len(self.queue)} pending DNS resolutions on shutdown")

        # Wait briefly for processing to complete (non-blocking)
        # Use a shorter timeout on shutdown
        time.sleep(1.0)

        # Flush remaining storage queue
        if self.storage and self.storage_queue:
            self.logger.info(f"Flushing {len(self.storage_queue)} remaining storage items...")
            try:
                for result in self.storage_queue:
                    self.storage.add_result(result)
                self.storage.flush()
            except:
                pass  # Ignore errors during shutdown

        # Final flush of storage
        if self.storage:
            try:
                self.storage.flush()
            except:
                pass  # Ignore errors during shutdown

        # Shutdown executors with timeout
        try:
            self.executor.shutdown(wait=True, timeout=2.0)
        except:
            # Force shutdown if it takes too long
            self.executor.shutdown(wait=False)

        try:
            self.storage_executor.shutdown(wait=True, timeout=2.0)
        except:
            self.storage_executor.shutdown(wait=False)