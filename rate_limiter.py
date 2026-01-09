#!/usr/bin/env python3
"""
Adaptive Rate Limiter for CT Log Servers

Implements per-server rate limiting with:
- Adaptive batch size reduction
- Dynamic polling interval adjustment
- Operator-specific baseline polling intervals
- Circuit breaker pattern for problematic servers
- Gradual recovery when servers become responsive
"""

import re

import time
from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading


# Operator-specific baseline polling intervals (seconds)
# Based on research: Cloudflare most permissive, DigiCert most aggressive
OPERATOR_POLL_INTERVALS = {
    'cloudflare.com': 60,      # Cloudflare Nimbus - 100 req/10s per IP (permissive)
    'googleapis.com': 90,      # Google CT logs - moderate limits
    'ct.sectigo.com': 90,      # Sectigo - moderate limits
    'letsencrypt.org': 90,     # Let's Encrypt Oak - moderate limits
    'trustasia.com': 90,       # TrustAsia - moderate limits
    'digicert.com': 180,       # DigiCert - 2 req/sec per IP (aggressive)
    'geomys': 90,              # Geomys Tuscolo - moderate
    'default': 90              # Default for unknown operators
}


def get_operator_poll_interval(server_url: str) -> int:
    """Determine baseline poll interval based on operator"""
    url_lower = server_url.lower()
    for operator, interval in OPERATOR_POLL_INTERVALS.items():
        if operator != 'default' and operator in url_lower:
            return interval
    return OPERATOR_POLL_INTERVALS['default']


@dataclass
class ServerRateInfo:
    """Track rate limiting info per server"""
    server_name: str
    server_url: str = ""  # Store full URL for operator detection
    rate_limit_count: int = 0
    last_rate_limit: Optional[datetime] = None
    last_success: Optional[datetime] = None
    consecutive_failures: int = 0
    batch_size: int = 1000  # Increased default from 100 to 1000
    poll_interval_multiplier: float = 1.0  # Multiplier for poll interval
    base_poll_interval: int = 90  # Operator-specific baseline
    is_excluded: bool = False
    exclusion_until: Optional[datetime] = None
    window_start: datetime = field(default_factory=datetime.now)
    rate_limits_in_window: list = field(default_factory=list)

    # Configuration
    original_batch_size: int = 1000  # Increased from 100
    min_batch_size: int = 50  # Increased from 10
    max_poll_multiplier: float = 8.0

    def record_rate_limit(self):
        """Record a rate limit event"""
        now = datetime.now()
        self.rate_limit_count += 1
        self.consecutive_failures += 1
        self.last_rate_limit = now

        # Clean old entries from window (keep last hour)
        cutoff = now - timedelta(hours=1)
        self.rate_limits_in_window = [t for t in self.rate_limits_in_window if t > cutoff]
        self.rate_limits_in_window.append(now)

        # Adaptive adjustments based on consecutive failures
        if self.consecutive_failures >= 3 and self.batch_size > self.min_batch_size:
            # Reduce batch size by 50%
            self.batch_size = max(self.min_batch_size, self.batch_size // 2)

        if self.consecutive_failures >= 5:
            # Double the polling interval
            self.poll_interval_multiplier = min(self.max_poll_multiplier, self.poll_interval_multiplier * 2)

        if self.consecutive_failures >= 10:
            # Circuit breaker: exclude server for 30 minutes
            self.is_excluded = True
            self.exclusion_until = now + timedelta(minutes=30)

    def record_success(self):
        """Record a successful request"""
        now = datetime.now()
        self.last_success = now

        # Only reset consecutive failures if we haven't had a rate limit recently
        # This prevents successes on one endpoint from resetting failures when
        # other endpoints of the same server are still being rate limited
        if self.last_rate_limit is None or (now - self.last_rate_limit).total_seconds() > 60:
            # No recent rate limits, safe to reset
            self.consecutive_failures = 0
        # If we had a rate limit within the last minute, don't reset the counter

        # If server was excluded but responded successfully, lift exclusion early
        if self.is_excluded:
            self.is_excluded = False
            self.exclusion_until = None
            # Keep conservative settings initially after exclusion lift
            self.batch_size = max(self.min_batch_size, self.original_batch_size // 4)
            self.poll_interval_multiplier = 2.0
            self.consecutive_failures = 0  # Reset on exclusion lift
            return  # Don't apply gradual recovery on exclusion lift

        # Only apply gradual recovery if we're truly recovering (no recent rate limits)
        if self.consecutive_failures == 0:
            # Gradually recover: increase batch size and reduce poll multiplier
            if self.batch_size < self.original_batch_size:
                # Increase batch size by 25%
                self.batch_size = min(self.original_batch_size, int(self.batch_size * 1.25))

            if self.poll_interval_multiplier > 1.0:
                # Reduce multiplier by 25%
                self.poll_interval_multiplier = max(1.0, self.poll_interval_multiplier * 0.75)

    def is_currently_excluded(self) -> bool:
        """Check if server is currently excluded"""
        if not self.is_excluded:
            return False

        now = datetime.now()
        if self.exclusion_until and now > self.exclusion_until:
            # Exclusion period has ended
            self.is_excluded = False
            self.exclusion_until = None
            # Reset some parameters but keep reduced settings initially
            self.consecutive_failures = 0
            self.batch_size = max(self.min_batch_size, self.original_batch_size // 4)
            self.poll_interval_multiplier = 2.0
            return False

        return True

    def get_rate_limit_score(self) -> float:
        """Get a score indicating how problematic this server is (0=good, 1=bad)"""
        now = datetime.now()

        # Count recent rate limits (last hour)
        recent_count = len(self.rate_limits_in_window)

        # Factor in consecutive failures
        failure_score = min(1.0, self.consecutive_failures / 10.0)

        # Factor in recent rate limit frequency
        frequency_score = min(1.0, recent_count / 20.0)  # 20+ rate limits/hour = max score

        # Factor in time since last success
        if self.last_success:
            time_since_success = (now - self.last_success).total_seconds()
            staleness_score = min(1.0, time_since_success / 3600.0)  # 1 hour = max score
        else:
            staleness_score = 0.5  # No success recorded yet

        # Weighted average
        return (failure_score * 0.4 + frequency_score * 0.4 + staleness_score * 0.2)

    def get_status_emoji(self) -> str:
        """Get emoji indicating server status"""
        if self.is_currently_excluded():
            return "🚫"  # Excluded

        score = self.get_rate_limit_score()
        if score < 0.2:
            return "✅"  # Healthy
        elif score < 0.5:
            return "⚠️"  # Warning
        elif score < 0.8:
            return "⛔"  # Problematic
        else:
            return "❌"  # Severe issues


class AdaptiveRateLimiter:
    """Manages per-server rate limiting with adaptive behavior"""

    def __init__(self, logger, default_batch_size: int = 1000, default_poll_time: int = 90):
        self.logger = logger
        self.default_batch_size = default_batch_size
        self.default_poll_time = default_poll_time
        self.servers: Dict[str, ServerRateInfo] = {}
        self.lock = threading.Lock()

    def get_server_info(self, server_url: str) -> ServerRateInfo:
        """Get or create rate info for a server (not per endpoint)"""
        # Track rate limits at the server level, not per year endpoint
        # This prevents successes on one year endpoint from resetting
        # failures on another year endpoint of the same server
        if '://' in server_url:
            parts = server_url.split('/')
            server_name = parts[2] if len(parts) > 2 else server_url

            # Always use just the domain as the key
            # This ensures all year endpoints share the same rate limit tracking
            endpoint_key = '/'.join(parts[:3])  # Just https://domain
        else:
            endpoint_key = server_url
            server_name = server_url

        with self.lock:
            if endpoint_key not in self.servers:
                # Determine operator-specific poll interval
                base_poll = get_operator_poll_interval(server_url)

                self.servers[endpoint_key] = ServerRateInfo(
                    server_name=server_name,
                    server_url=server_url,
                    batch_size=self.default_batch_size,
                    original_batch_size=self.default_batch_size,
                    base_poll_interval=base_poll
                )

                # Log operator detection
                operator_name = 'Unknown'
                for op in OPERATOR_POLL_INTERVALS.keys():
                    if op != 'default' and op in server_url.lower():
                        operator_name = op
                        break

                self.logger.debug(
                    f"Initialized {server_name}: operator={operator_name}, "
                    f"base_poll={base_poll}s, batch_size={self.default_batch_size}"
                )

            return self.servers[endpoint_key]

    def record_rate_limit(self, server_url: str, status_code: int):
        """Record that a server returned a rate limit"""
        server_info = self.get_server_info(server_url)
        prev_failures = server_info.consecutive_failures
        server_info.record_rate_limit()

        # Debug logging
        self.logger.debug(
            f"Rate limit recorded for {server_info.server_name}: "
            f"consecutive_failures={server_info.consecutive_failures}, "
            f"batch_size={server_info.batch_size}, "
            f"poll_multiplier={server_info.poll_interval_multiplier:.1f}x"
        )

        # Log adaptive action taken (only on threshold crossings)
        # Include endpoint info in logs for clarity
        endpoint_info = self._extract_endpoint_info(server_url)

        if server_info.is_excluded and prev_failures < 10:
            self.logger.warning(
                f"🚫 Server {server_info.server_name}{endpoint_info} excluded until "
                f"{server_info.exclusion_until.strftime('%H:%M:%S')} "
                f"(hit {server_info.consecutive_failures} consecutive rate limits)",
                force=True
            )
        elif server_info.consecutive_failures == 3 and prev_failures < 3:
            self.logger.info(
                f"📉 Reduced batch size to {server_info.batch_size} for {server_info.server_name}{endpoint_info}",
                force=True
            )
        elif server_info.consecutive_failures == 5 and prev_failures < 5:
            self.logger.info(
                f"⏰ Increased poll interval {server_info.poll_interval_multiplier:.1f}x "
                f"for {server_info.server_name}{endpoint_info}",
                force=True
            )

    def record_success(self, server_url: str):
        """Record a successful request to a server"""
        server_info = self.get_server_info(server_url)
        prev_batch = server_info.batch_size
        prev_multiplier = server_info.poll_interval_multiplier
        was_excluded = server_info.is_excluded

        server_info.record_success()

        # Log recovery if parameters changed
        endpoint_info = self._extract_endpoint_info(server_url)

        # Log exclusion lift
        if was_excluded and not server_info.is_excluded:
            self.logger.info(
                f"✅ Exclusion lifted for {server_info.server_name}{endpoint_info} - server responding normally",
                force=True
            )

        if server_info.batch_size > prev_batch:
            self.logger.debug(f"📈 Increased batch size to {server_info.batch_size} for {server_info.server_name}{endpoint_info}")
        if server_info.poll_interval_multiplier < prev_multiplier:
            self.logger.debug(f"⚡ Reduced poll delay to {server_info.poll_interval_multiplier:.1f}x for {server_info.server_name}{endpoint_info}")

    def should_skip_server(self, server_url: str) -> bool:
        """Check if a server should be skipped due to circuit breaker"""
        server_info = self.get_server_info(server_url)
        return server_info.is_currently_excluded()

    def get_batch_size(self, server_url: str) -> int:
        """Get the current batch size for a server"""
        server_info = self.get_server_info(server_url)
        return server_info.batch_size

    def get_poll_interval(self, server_url: str) -> float:
        """Get the adjusted poll interval for a server (operator-specific baseline + multiplier)"""
        server_info = self.get_server_info(server_url)
        # Use operator-specific baseline instead of global default
        return server_info.base_poll_interval * server_info.poll_interval_multiplier

    def get_statistics(self) -> Dict:
        """Get statistics about rate limiting"""
        with self.lock:
            total_servers = len(self.servers)
            excluded_servers = sum(1 for s in self.servers.values() if s.is_currently_excluded())
            problematic_servers = sum(1 for s in self.servers.values() if s.get_rate_limit_score() > 0.5)

            return {
                'total_servers': total_servers,
                'excluded_servers': excluded_servers,
                'problematic_servers': problematic_servers,
                'servers': {
                    name: {
                        'status': info.get_status_emoji(),
                        'rate_limits': info.rate_limit_count,
                        'consecutive_failures': info.consecutive_failures,
                        'batch_size': info.batch_size,
                        'poll_multiplier': info.poll_interval_multiplier,
                        'base_poll_interval': info.base_poll_interval,
                        'excluded': info.is_currently_excluded(),
                        'score': round(info.get_rate_limit_score(), 2)
                    }
                    for name, info in self.servers.items()
                }
            }

    def get_summary(self) -> str:
        """Get a summary of problematic servers"""
        with self.lock:
            # Include both problematic servers and currently excluded servers
            problematic = [(name, info) for name, info in self.servers.items()
                          if info.get_rate_limit_score() > 0.3 or info.is_currently_excluded()]

            if not problematic:
                return ""

            # Sort by score (worst first), but put excluded servers first
            problematic.sort(key=lambda x: (not x[1].is_currently_excluded(), -x[1].get_rate_limit_score()))

            lines = ["📊 Rate Limit Status:"]
            for name, info in problematic[:5]:  # Show top 5
                status = info.get_status_emoji()
                if info.is_currently_excluded():
                    exclusion_time = info.exclusion_until.strftime('%H:%M:%S') if info.exclusion_until else "unknown"
                    lines.append(f"  {status} {name}: EXCLUDED until {exclusion_time}")
                else:
                    lines.append(
                        f"  {status} {name}: batch={info.batch_size}, "
                        f"delay={info.poll_interval_multiplier:.1f}x (base={info.base_poll_interval}s), "
                        f"failures={info.consecutive_failures}"
                    )

            if len(problematic) > 5:
                lines.append(f"  ... and {len(problematic) - 5} more servers with issues")

            return "\n".join(lines)

    def _extract_endpoint_info(self, server_url: str) -> str:
        """Extract year/period identifier from URL for logging"""
        # Pattern to match year and period like 2024h1, 2025h2, 2026h1, etc.
        year_pattern = r'(\d{4}h[12])'

        # Search in the entire URL (could be in path or subdomain)
        match = re.search(year_pattern, server_url.lower())
        if match:
            return f" [{match.group(1).upper()}]"

        # If no year pattern found, try to extract any path segment that looks like a log identifier
        if '/' in server_url:
            parts = server_url.split('/')
            # Check if there's a path segment after the domain that's not 'ct'
            if len(parts) > 3 and parts[3] != 'ct' and parts[3] != '':
                return f" [{parts[3]}]"

        return ""
