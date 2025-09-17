#!/usr/bin/env python3
"""
Test script for DNS resolution functionality
"""

import asyncio
import logging
import time
from dns_resolver import DNSResolver, DNSResolverThread, DNSResult
from dns_elasticsearch import DNSElasticsearchStorage

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_basic_resolution():
    """Test basic DNS resolution"""
    print("\n=== Testing Basic DNS Resolution ===")

    resolver = DNSResolver(logger, max_concurrent=5)

    # Test domains
    test_domains = [
        ("google.com", None),
        ("cloudflare.com", None),
        ("*.example.com", "cert123"),  # Wildcard test
        ("nonexistent.domain.invalid", None),  # NXDOMAIN test
        ("github.com", None)
    ]

    # Run async resolution
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    results = loop.run_until_complete(
        resolver.resolve_batch(test_domains)
    )

    # Display results
    for result in results:
        if result.ips:
            print(f"✅ {result.domain} -> {', '.join(result.ips)}")
        else:
            print(f"❌ {result.domain} -> Error: {result.error}")

    # Show statistics
    stats = resolver.get_stats()
    print(f"\nStatistics: {stats}")

    loop.close()


def test_threaded_resolution():
    """Test threaded DNS resolution with batching"""
    print("\n=== Testing Threaded Resolution with Batching ===")

    # Create resolver thread
    resolver_thread = DNSResolverThread(logger, batch_size=3, flush_interval=2)

    # Add domains
    domains = [
        "apple.com",
        "microsoft.com",
        "amazon.com",
        "facebook.com",
        "netflix.com"
    ]

    for domain in domains:
        resolver_thread.add_domain(domain, cert_sha1=f"cert_{domain}")
        print(f"Queued: {domain}")
        time.sleep(0.5)  # Simulate delay between discoveries

    # Wait for batch processing
    print("Waiting for batch processing...")
    time.sleep(3)

    # Cleanup
    resolver_thread.close()


def test_elasticsearch_storage():
    """Test DNS resolution with Elasticsearch storage"""
    print("\n=== Testing DNS Resolution with Elasticsearch Storage ===")

    try:
        # Initialize storage
        storage = DNSElasticsearchStorage(
            index_prefix="ct-dns-test"
        )

        # Create test results
        test_results = [
            DNSResult(
                domain="test1.example.com",
                ips=["192.168.1.1", "192.168.1.2"],
                cert_sha1="abc123",
                record_type="A"
            ),
            DNSResult(
                domain="test2.example.com",
                ips=["10.0.0.1"],
                cert_sha1="def456",
                record_type="A"
            ),
            DNSResult(
                domain="failed.example.com",
                ips=[],
                cert_sha1="ghi789",
                error="nxdomain"
            )
        ]

        # Store results
        for result in test_results:
            storage.add_result(result)
            print(f"Added to batch: {result.domain}")

        # Flush to Elasticsearch
        storage.flush()
        print("✅ Flushed to Elasticsearch")

        # Test lookups
        time.sleep(2)  # Wait for ES to index

        # Lookup by domain
        print("\n--- Domain Lookup ---")
        results = storage.lookup_domain("test1.example.com")
        for r in results:
            print(f"Found: {r.get('d')} -> {r.get('i')}")

        # Lookup by IP
        print("\n--- IP Lookup ---")
        results = storage.lookup_ip("192.168.1.1")
        for r in results:
            print(f"IP {r.get('i')} -> Domain: {r.get('d')}")

        # Get statistics
        print("\n--- Storage Statistics ---")
        stats = storage.get_stats()
        print(f"Stats: {stats}")

        # Cleanup
        storage.close()

    except Exception as e:
        print(f"❌ Elasticsearch test failed: {e}")
        print("Make sure Elasticsearch is running and accessible")


def test_full_integration():
    """Test full integration with resolver and storage"""
    print("\n=== Testing Full Integration ===")

    try:
        # Initialize components
        storage = DNSElasticsearchStorage(index_prefix="ct-dns-integration")
        resolver_thread = DNSResolverThread(
            logger=logger,
            batch_size=5,
            flush_interval=3,
            storage=storage
        )

        # Add real domains
        test_domains = [
            ("google.com", "cert1"),
            ("github.com", "cert2"),
            ("stackoverflow.com", "cert3"),
            ("reddit.com", "cert4"),
            ("twitter.com", "cert5")
        ]

        for domain, cert_sha1 in test_domains:
            resolver_thread.add_domain(domain, cert_sha1)
            print(f"Queued for resolution: {domain}")

        # Wait for processing
        print("\nWaiting for DNS resolution and storage...")
        time.sleep(10)

        # Check storage
        print("\n--- Checking Stored Results ---")
        for domain, _ in test_domains:
            results = storage.lookup_domain(domain)
            if results:
                print(f"✅ {domain} stored successfully")
            else:
                print(f"❌ {domain} not found in storage")

        # Cleanup
        resolver_thread.close()
        storage.close()

    except Exception as e:
        print(f"❌ Integration test failed: {e}")


if __name__ == "__main__":
    print("DNS Resolver Test Suite")
    print("=" * 50)

    # Run tests
    test_basic_resolution()
    test_threaded_resolution()

    # Only run Elasticsearch tests if ES is available
    try:
        import requests
        response = requests.get("http://localhost:9200", timeout=2)
        if response.status_code == 200:
            test_elasticsearch_storage()
            test_full_integration()
        else:
            print("\n⚠️ Elasticsearch not available - skipping storage tests")
    except:
        print("\n⚠️ Elasticsearch not available - skipping storage tests")

    print("\n✅ Test suite completed!")