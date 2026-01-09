#!/usr/bin/env python3
"""
Elasticsearch output module for CT Monitor
Sends certificate data to Elasticsearch with minimal storage format
"""

import json
import requests
from datetime import datetime
from typing import Dict, List, Optional
import logging
import os
from dotenv import load_dotenv
import sys

# Load environment variables from .env file
load_dotenv()

class ElasticsearchOutput:
    """Handles output to Elasticsearch with minimal storage format"""

    def __init__(self,
                 es_host: Optional[str] = None,
                 es_user: Optional[str] = None,
                 es_password: Optional[str] = None,
                 index_prefix: str = "ct-domains",
                 batch_size: int = 1000):

        # Use environment variables or fallback to defaults
        self.es_host = (es_host or os.getenv('ES_HOST', 'http://localhost:9200')).rstrip('/')
        self.es_user = es_user or os.getenv('ES_USER', 'elastic')
        self.es_password = es_password or os.getenv('ES_PASSWORD', '')
        self.index_prefix = index_prefix
        self.batch_size = batch_size

        self.batch: List[Dict] = []
        self.failed_batches: List[List[Dict]] = []  # Queue for retrying failed batches
        self.session = requests.Session()
        self.session.auth = (self.es_user, self.es_password)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

        # Log source mapping (single character codes)
        self.log_source_map = {
            'google': 'g',
            'sectigo': 's',
            'digicert': 'd',
            'letsencrypt': 'l',
            'default': 'x'
        }

        # Set logging level based on environment or default to WARNING
        log_level = os.getenv('ES_LOG_LEVEL', 'WARNING')
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.WARNING))
        
        # Configure handler to output to stderr for systemd journal
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)

        # Validate connection during initialization
        self._validate_connection()

    def _get_log_source_code(self, log_url: str) -> str:
        """Extract single character log source code from URL"""
        if 'google' in log_url:
            return 'g'
        elif 'sectigo' in log_url:
            return 's'
        elif 'digicert' in log_url:
            return 'd'
        elif 'letsencrypt' in log_url:
            return 'l'
        return 'x'

    def _validate_connection(self):
        """Validate Elasticsearch connection during initialization"""
        try:
            response = self.session.get(f"{self.es_host}/", timeout=10)
            response.raise_for_status()
            self.logger.info(f"✅ Elasticsearch connection validated: {self.es_host}")
        except requests.exceptions.RequestException as e:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.error(f"[{timestamp}] ❌ Elasticsearch connection failed: {e}")
            if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 401:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(f"[{timestamp}] ❌ Authentication failed - check ES_USER and ES_PASSWORD")
            elif isinstance(e, requests.exceptions.ConnectionError):
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(f"[{timestamp}] ❌ Connection failed - check ES_HOST and Elasticsearch status")
            raise SystemExit("Fatal: Elasticsearch connection failed") from e

    def _get_index_name(self) -> str:
        """Get daily index name"""
        date_str = datetime.now().strftime('%Y-%m-%d')
        return f"{self.index_prefix}-{date_str}"

    def transform_to_minimal(self, ct_result: Dict, log_url: str) -> Dict:
        """Transform CT result to minimal storage format"""
        return {
            "d": ct_result.get('name', ''),           # domain
            "t": ct_result.get('ts', 0),              # timestamp
            "h": ct_result.get('sha1', ''),           # full hash (40 chars)
            "l": self._get_log_source_code(log_url),  # log source
            "s": ct_result.get('dns', [])             # full SAN list
        }

    def add_to_batch(self, ct_result: Dict, log_url: str):
        """Add result to batch, flush if batch size reached"""
        minimal_data = self.transform_to_minimal(ct_result, log_url)

        # Debug: Log SAN data summary (only in DEBUG mode)
        if self.logger.isEnabledFor(logging.DEBUG) and 's' in minimal_data and minimal_data['s']:
            sample = minimal_data['s'][:3] if len(minimal_data['s']) > 3 else minimal_data['s']
            self.logger.debug(f"SAN: {sample}... ({len(minimal_data['s'])} domains)")

        self.batch.append(minimal_data)

        if len(self.batch) >= self.batch_size:
            self.flush()

    def flush(self):
        """Flush current batch to Elasticsearch"""
        if not self.batch:
            return

        index_name = self._get_index_name()
        bulk_data = []

        for doc in self.batch:
            # Bulk API format: index operation + document
            bulk_data.append(json.dumps({"index": {"_index": index_name}}))
            bulk_data.append(json.dumps(doc))

        bulk_payload = '\n'.join(bulk_data) + '\n'

        try:
            response = self.session.post(
                f"{self.es_host}/_bulk",
                data=bulk_payload,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('errors', False):
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    self.logger.error(f"[{timestamp}] ❌ Elasticsearch bulk errors: {result}")
                    # Add to retry queue
                    self.failed_batches.append(self.batch.copy())
                else:
                    self.logger.info(f"✅ Indexed {len(self.batch)} documents to {index_name}")
            else:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(f"[{timestamp}] ❌ Elasticsearch error: {response.status_code} - {response.text}")
                # Add to retry queue
                self.failed_batches.append(self.batch.copy())

        except Exception as e:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.error(f"[{timestamp}] ❌ Failed to send batch to Elasticsearch: {e}")
            # Add to retry queue
            self.failed_batches.append(self.batch.copy())

        self.batch.clear()

    def retry_failed_batches(self):
        """Retry sending failed batches"""
        if not self.failed_batches:
            return

        self.logger.info(f"🔄 Retrying {len(self.failed_batches)} failed batches")

        # Move failed batches to temporary list to avoid modification during iteration
        batches_to_retry = self.failed_batches.copy()
        self.failed_batches = []

        for batch in batches_to_retry:
            # Temporarily set current batch and flush
            original_batch = self.batch
            self.batch = batch
            self.flush()
            self.batch = original_batch

    def close(self):
        """Flush any remaining data, retry failed batches, and close connections"""
        if self.batch:
            self.flush()

        # Retry any failed batches before closing
        if self.failed_batches:
            self.logger.info(f"🔄 Retrying {len(self.failed_batches)} failed batches before shutdown")
            self.retry_failed_batches()
        self.session.close()

# Example usage
if __name__ == "__main__":
    # Test with sample data
    es_output = ElasticsearchOutput()

    sample_data = {
        "name": "example.com",
        "ts": 1750518406484,
        "sha1": "abc123def4567890",
        "cn": "example.com"
    }

    es_output.add_to_batch(sample_data, "https://ct.googleapis.com/logs/xenon2025/")
    es_output.close()