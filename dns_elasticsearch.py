#!/usr/bin/env python3
"""
DNS Elasticsearch integration for CT Monitor
Handles storage and retrieval of DNS resolution data
"""

import json
import requests
from datetime import datetime
from typing import Dict, List, Optional
import logging
import os
from dotenv import load_dotenv
from dns_resolver import DNSResult

# Load environment variables
load_dotenv()


class DNSElasticsearchStorage:
    """Handles DNS data storage in Elasticsearch with bidirectional lookups"""

    def __init__(self,
                 es_host: Optional[str] = None,
                 es_user: Optional[str] = None,
                 es_password: Optional[str] = None,
                 index_prefix: str = "ct-dns",
                 batch_size: int = 2000):  # Increased from 500 for better ES throughput

        # Use environment variables or defaults
        self.es_host = (es_host or os.getenv('ES_HOST', 'http://localhost:9200')).rstrip('/')
        self.es_user = es_user or os.getenv('ES_USER', 'elastic')
        self.es_password = es_password or os.getenv('ES_PASSWORD', '')
        self.index_prefix = index_prefix
        self.batch_size = batch_size

        self.batch: List[Dict] = []
        self.session = requests.Session()
        self.session.auth = (self.es_user, self.es_password)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

        self.logger = logging.getLogger(__name__)

        # Initialize index if needed
        self._ensure_index_template()

    def _ensure_index_template(self):
        """Create or update index template for DNS data"""
        template = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "30s",
                    "codec": "best_compression"
                },
                "mappings": {
                    "properties": {
                        "d": {"type": "keyword"},           # domain
                        "i": {"type": "ip"},                # IPs array
                        "ii": {"type": "long"},             # IPv4 as integers
                        "c": {"type": "keyword"},           # cert SHA1
                        "r": {"type": "keyword"},           # root domain
                        "t": {"type": "keyword"},           # record type
                        "ts": {
                            "type": "date",
                            "format": "epoch_second"
                        },
                        "ttl": {"type": "integer"},
                        "w": {"type": "boolean"},           # is_wildcard
                        "e": {"type": "keyword"},           # error type
                        "h": {
                            "type": "keyword",
                            "index": False                   # dedup hash
                        }
                    }
                }
            }
        }

        try:
            url = f"{self.es_host}/_index_template/{self.index_prefix}-template"
            response = self.session.put(url, json=template)

            if response.status_code in [200, 201]:
                self.logger.info(f"✅ DNS index template created/updated")
            else:
                self.logger.warning(f"⚠️ Failed to create index template: {response.text}")

        except Exception as e:
            self.logger.error(f"❌ Error creating index template: {e}")

    def get_current_index(self) -> str:
        """Get current index name based on date (daily)"""
        return f"{self.index_prefix}-{datetime.now().strftime('%Y-%m-%d')}"

    def add_result(self, result: DNSResult):
        """Add a DNS resolution result to batch"""
        doc = result.to_es_doc()

        # Add metadata
        doc["@timestamp"] = datetime.fromtimestamp(result.timestamp).isoformat()

        self.batch.append(doc)

        if len(self.batch) >= self.batch_size:
            self.flush()

    def flush(self):
        """Send batch to Elasticsearch"""
        if not self.batch:
            return

        try:
            # Build bulk request
            bulk_data = []
            index = self.get_current_index()

            for doc in self.batch:
                # Check for duplicate using hash
                bulk_data.append(json.dumps({
                    "index": {
                        "_index": index,
                        "_id": doc.get("h")  # Use hash as document ID
                    }
                }))
                bulk_data.append(json.dumps(doc))

            # Send bulk request
            url = f"{self.es_host}/_bulk"
            data = '\n'.join(bulk_data) + '\n'

            response = self.session.post(url, data=data)

            if response.status_code == 200:
                result = response.json()
                if result.get('errors'):
                    # Log specific errors
                    for item in result.get('items', []):
                        if item.get('index', {}).get('error'):
                            error = item['index']['error']
                            if error.get('type') != 'version_conflict_engine_exception':
                                # Ignore duplicate conflicts
                                self.logger.error(f"❌ Bulk error: {error}")
                else:
                    self.logger.debug(f"✅ Stored {len(self.batch)} DNS results")
            else:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.logger.error(f"[{timestamp}] ❌ ES error: {response.status_code}")

        except Exception as e:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logger.error(f"[{timestamp}] ❌ Failed to store DNS results: {e}")

        self.batch.clear()

    def lookup_domain(self, domain: str, limit: int = 10) -> List[Dict]:
        """Look up IPs for a domain"""
        query = {
            "query": {"term": {"d": domain}},
            "size": limit,
            "sort": [{"ts": "desc"}]
        }

        try:
            url = f"{self.es_host}/{self.index_prefix}-*/_search"
            response = self.session.post(url, json=query)

            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                return [hit['_source'] for hit in hits]
            else:
                self.logger.error(f"❌ Lookup failed: {response.text}")
                return []

        except Exception as e:
            self.logger.error(f"❌ Domain lookup error: {e}")
            return []

    def lookup_ip(self, ip: str, limit: int = 100) -> List[Dict]:
        """Look up domains for an IP"""
        query = {
            "query": {"term": {"i": ip}},
            "size": 0,  # We only want aggregations
            "aggs": {
                "unique_domains": {
                    "terms": {
                        "field": "d",
                        "size": limit
                    },
                    "aggs": {
                        "latest": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"ts": "desc"}]
                            }
                        }
                    }
                }
            }
        }

        try:
            url = f"{self.es_host}/{self.index_prefix}-*/_search"
            response = self.session.post(url, json=query)

            if response.status_code == 200:
                buckets = response.json().get('aggregations', {}).get('unique_domains', {}).get('buckets', [])
                results = []
                for bucket in buckets:
                    doc = bucket['latest']['hits']['hits'][0]['_source']
                    results.append(doc)
                return results
            else:
                self.logger.error(f"❌ IP lookup failed: {response.text}")
                return []

        except Exception as e:
            self.logger.error(f"❌ IP lookup error: {e}")
            return []

    def lookup_certificate(self, cert_sha1: str, limit: int = 100) -> List[Dict]:
        """Look up all domains and IPs for a certificate"""
        query = {
            "query": {"term": {"c": cert_sha1}},
            "size": limit,
            "sort": [{"ts": "desc"}]
        }

        try:
            url = f"{self.es_host}/{self.index_prefix}-*/_search"
            response = self.session.post(url, json=query)

            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                return [hit['_source'] for hit in hits]
            else:
                self.logger.error(f"❌ Certificate lookup failed: {response.text}")
                return []

        except Exception as e:
            self.logger.error(f"❌ Certificate lookup error: {e}")
            return []

    def get_stats(self) -> Dict:
        """Get DNS storage statistics"""
        try:
            # Get document count
            url = f"{self.es_host}/{self.index_prefix}-*/_count"
            response = self.session.get(url)

            if response.status_code == 200:
                count = response.json().get('count', 0)

                # Get unique counts
                stats_query = {
                    "size": 0,
                    "aggs": {
                        "unique_domains": {"cardinality": {"field": "d"}},
                        "unique_ips": {"cardinality": {"field": "i"}},
                        "unique_certs": {"cardinality": {"field": "c"}}
                    }
                }

                url = f"{self.es_host}/{self.index_prefix}-*/_search"
                response = self.session.post(url, json=stats_query)

                if response.status_code == 200:
                    aggs = response.json().get('aggregations', {})
                    return {
                        "total_records": count,
                        "unique_domains": aggs.get('unique_domains', {}).get('value', 0),
                        "unique_ips": aggs.get('unique_ips', {}).get('value', 0),
                        "unique_certificates": aggs.get('unique_certs', {}).get('value', 0),
                        "pending_batch": len(self.batch)
                    }

        except Exception as e:
            self.logger.error(f"❌ Error getting stats: {e}")

        return {"error": "Failed to get statistics"}

    def close(self):
        """Flush pending data and close connections"""
        if self.batch:
            self.flush()
        self.session.close()