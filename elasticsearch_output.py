#!/usr/bin/env python3
"""
Elasticsearch output module for CT Monitor
Sends certificate data to Elasticsearch with minimal storage format
"""

import json
import requests
import xxhash
from collections import OrderedDict
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

        # Each entry is (index_name, doc_id, doc). The index is fixed when the doc is
        # queued, so a batch retried after midnight still lands in its own day's index
        # and its ids still match that day's copies.
        self.batch: List[tuple] = []
        self.failed_batches: List[List[tuple]] = []  # Queue for retrying failed batches

        # Duplicate suppression. The same (domain, cert) pair reaches us several times,
        # a few seconds apart (measured 2026-09-24: ~3.7 identical copies per pair per
        # day, differing only in `t`). The document _id is derived from the pair and
        # written with op_type=create, so Elasticsearch keeps the FIRST copy and answers
        # 409 for the rest. This small LRU of recent ids drops most copies before they
        # are sent at all; it is an optimisation only, the _id is what guarantees it.
        # doc_id -> True once the FINAL certificate was queued, False while only its precert was
        self.recent_ids: "OrderedDict[str, bool]" = OrderedDict()
        self.recent_ids_index: Optional[str] = None
        self.recent_ids_max = int(os.getenv('ES_DEDUP_CACHE_SIZE', '200000'))
        self.stats = {'queued': 0, 'skipped_local': 0, 'created': 0,
                      'duplicate_409': 0, 'retried': 0, 'dropped': 0}
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

    @staticmethod
    def doc_id(domain: str, cert_hash: str) -> str:
        """Deterministic _id for one (domain, certificate) pair.

        xxh3_64 is a fast non-cryptographic hash (~95 ns vs ~500 ns for sha1). 64 bits
        is ample here: ids only need to be unique within one daily index (~60M pairs),
        where a collision is ~1e-4 per day and would cost one dropped row.
        """
        return xxhash.xxh3_64_hexdigest(f"{domain}|{cert_hash}")

    def _seen_recently(self, index_name: str, doc_id: str, final: bool = True) -> bool:
        """True if doc_id was already queued for this index; records it otherwise.

        A precert is skipped once anything was queued for its issuance; a final certificate is
        skipped only once a FINAL was queued, so it can still replace a precert queued earlier.
        """
        if index_name != self.recent_ids_index:
            # New day, new index: the same pair is stored once per day, as before.
            self.recent_ids.clear()
            self.recent_ids_index = index_name
        seen_final = self.recent_ids.get(doc_id)
        if seen_final is not None and (seen_final or not final):
            return True
        self.recent_ids[doc_id] = final or bool(seen_final)
        self.recent_ids.move_to_end(doc_id)
        if len(self.recent_ids) > self.recent_ids_max:
            self.recent_ids.popitem(last=False)
        return False

    def add_to_batch(self, ct_result: Dict, log_url: str):
        """Add result to batch, flush if batch size reached"""
        minimal_data = self.transform_to_minimal(ct_result, log_url)
        index_name = self._get_index_name()
        # One document per ISSUED certificate: key on issuer+serial (`ik`), which a precert and
        # its final certificate share, so the pair no longer shows as two certificates. A final
        # certificate is written with `index` so it replaces its precert (and its SHA-1 is the one
        # a browser is served); a precert uses `create` so it never replaces a final. Docs from
        # before 2026-09-26 are keyed on the SHA-1 and do not collapse.
        is_precert = bool(ct_result.get('pc'))
        doc_id = self.doc_id(minimal_data['d'], ct_result.get('ik') or minimal_data['h'])
        if self._seen_recently(index_name, doc_id, final=not is_precert):
            self.stats['skipped_local'] += 1
            return
        self.stats['queued'] += 1

        # Debug: Log SAN data summary (only in DEBUG mode)
        if self.logger.isEnabledFor(logging.DEBUG) and 's' in minimal_data and minimal_data['s']:
            sample = minimal_data['s'][:3] if len(minimal_data['s']) > 3 else minimal_data['s']
            self.logger.debug(f"SAN: {sample}... ({len(minimal_data['s'])} domains)")

        self.batch.append((index_name, doc_id, minimal_data, 'create' if is_precert else 'index'))

        if len(self.batch) >= self.batch_size:
            self.flush()

    def flush(self):
        """Flush current batch to Elasticsearch.

        Uses op_type=create with a deterministic _id, so re-sending a document is
        harmless: Elasticsearch answers 409 and keeps the original. Results are read
        PER ITEM - only items that failed with a retryable status (429 / 5xx) are
        queued again. Previously any item error re-queued the whole batch with plain
        `index` ops, which re-wrote every document that had already succeeded.
        """
        if not self.batch:
            return

        batch = self.batch
        self.batch = []
        bulk_data = []
        for index_name, doc_id, doc, op in batch:
            bulk_data.append(json.dumps({op: {"_index": index_name, "_id": doc_id}}))
            bulk_data.append(json.dumps(doc))
        bulk_payload = '\n'.join(bulk_data) + '\n'

        try:
            response = self.session.post(
                f"{self.es_host}/_bulk?filter_path=errors,items.*.status,items.*.error.type,items.*.error.reason",
                data=bulk_payload,
                timeout=30
            )
        except Exception as e:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.error(f"[{timestamp}] ❌ Failed to send batch to Elasticsearch: {e}")
            self.failed_batches.append(batch)
            return

        if response.status_code != 200:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.error(f"[{timestamp}] ❌ Elasticsearch error: {response.status_code} - {response.text[:500]}")
            self.failed_batches.append(batch)
            return

        result = response.json()
        items = result.get('items') or []
        if len(items) != len(batch):
            # Cannot map results to documents; resend all (safe: create is idempotent, and index rewrites the same content).
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.error(f"[{timestamp}] ❌ Bulk returned {len(items)} items for {len(batch)} docs - retrying batch")
            self.failed_batches.append(batch)
            return

        created = duplicates = replaced = 0
        retry, dropped_errors = [], []
        for entry, item in zip(batch, items):
            res = next(iter(item.values()))
            status = res.get('status', 0)
            if status == 201:
                created += 1
            elif status == 200:
                replaced += 1  # a final certificate overwrote its precert (or a re-logged final)
            elif status == 409:
                duplicates += 1
            elif status == 429 or status >= 500:
                retry.append(entry)
            else:
                dropped_errors.append(res.get('error'))

        self.stats['created'] += created
        self.stats['replaced'] = self.stats.get('replaced', 0) + replaced
        self.stats['duplicate_409'] += duplicates
        if retry:
            self.stats['retried'] += len(retry)
            self.failed_batches.append(retry)
        if dropped_errors:
            self.stats['dropped'] += len(dropped_errors)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.error(f"[{timestamp}] ❌ Dropped {len(dropped_errors)} docs with non-retryable errors, first: {dropped_errors[0]}")
        self.logger.info(
            f"✅ Indexed {created} documents to {batch[0][0]} "
            f"({replaced} replaced, {duplicates} already present, {len(retry)} to retry; "
            f"skipped locally so far: {self.stats['skipped_local']})"
        )

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