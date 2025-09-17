#!/usr/bin/env python3
"""
Test public DNS resolver round-robin functionality
"""

import asyncio
import logging
from dns_resolver import DNSResolver

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def test_round_robin():
    """Test round-robin DNS resolution with public resolvers"""
    print("\n=== Testing Round-Robin Public DNS Resolvers ===\n")

    # Create resolver with public DNS servers
    resolver = DNSResolver(
        logger=logger,
        use_public_resolvers=True,
        cache_size=0  # Disable cache to see all requests
    )

    # Test domains
    test_domains = [
        "google.com",
        "cloudflare.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "facebook.com"
    ]

    print("Resolving domains with round-robin public DNS servers:\n")

    # Resolve each domain
    for domain in test_domains:
        result = await resolver.resolve_domain_async(domain)
        if result.ips:
            print(f"✅ {domain} -> {', '.join(result.ips[:2])}")  # Show first 2 IPs

    # Show resolver usage statistics
    print("\n=== Resolver Usage Statistics ===")
    stats = resolver.get_stats()
    if 'resolver_usage' in stats:
        for dns_server, count in stats['resolver_usage'].items():
            print(f"  {dns_server}: {count} queries")

    print(f"\nTotal queries: {stats['total_queries']}")
    print(f"Successful: {stats['successful']}")
    print(f"Failed: {stats['failed']}")


async def test_parallel_resolution():
    """Test parallel resolution to see round-robin in action"""
    print("\n=== Testing Parallel Resolution with Round-Robin ===\n")

    resolver = DNSResolver(
        logger=logger,
        use_public_resolvers=True,
        max_concurrent=6,
        cache_size=0
    )

    # Create multiple domains for parallel resolution
    domains = [f"test{i}.example.com" for i in range(12)]
    domains.extend(["google.com", "github.com", "cloudflare.com"])

    # Resolve in batch
    batch = [(d, None) for d in domains]
    results = await resolver.resolve_batch(batch)

    success_count = sum(1 for r in results if r.ips)
    fail_count = sum(1 for r in results if not r.ips)

    print(f"Resolved {len(results)} domains")
    print(f"  Success: {success_count}")
    print(f"  Failed: {fail_count}")

    print("\n=== Resolver Distribution ===")
    stats = resolver.get_stats()
    if 'resolver_usage' in stats:
        total_queries = sum(stats['resolver_usage'].values())
        for dns_server, count in stats['resolver_usage'].items():
            percentage = (count / total_queries * 100) if total_queries > 0 else 0
            bar = '█' * int(percentage / 5)
            print(f"  {dns_server:16} [{bar:20}] {count:3} queries ({percentage:.1f}%)")


async def test_comparison():
    """Compare system resolver vs public resolvers"""
    print("\n=== Comparing System vs Public Resolvers ===\n")

    # Test with system resolver
    print("Using system resolver:")
    system_resolver = DNSResolver(logger=logger, use_public_resolvers=False)

    start = asyncio.get_event_loop().time()
    result1 = await system_resolver.resolve_domain_async("google.com")
    system_time = asyncio.get_event_loop().time() - start
    print(f"  google.com -> {result1.ips[0] if result1.ips else 'Failed'}")
    print(f"  Time: {system_time:.3f}s")

    # Test with public resolver
    print("\nUsing public resolvers (round-robin):")
    public_resolver = DNSResolver(logger=logger, use_public_resolvers=True)

    start = asyncio.get_event_loop().time()
    result2 = await public_resolver.resolve_domain_async("google.com")
    public_time = asyncio.get_event_loop().time() - start
    print(f"  google.com -> {result2.ips[0] if result2.ips else 'Failed'}")
    print(f"  Time: {public_time:.3f}s")

    print(f"\nSpeed difference: {abs(system_time - public_time):.3f}s")


async def main():
    """Run all tests"""
    await test_round_robin()
    await test_parallel_resolution()
    await test_comparison()


if __name__ == "__main__":
    print("Public DNS Resolver Round-Robin Test")
    print("=" * 50)

    # Run tests
    asyncio.run(main())

    print("\n✅ All tests completed!")