#!/usr/bin/env python3
"""
Debug DNS resolution to verify which resolver is being used
"""

import sys
import socket
import asyncio
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_socket_resolution():
    """Test socket-based resolution"""
    print("\n=== Testing socket.getaddrinfo() ===")
    try:
        result = socket.getaddrinfo("google.com", None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set([addr[4][0] for addr in result]))
        print(f"Socket resolved google.com to: {ips}")
        return ips
    except Exception as e:
        print(f"Socket resolution failed: {e}")
        return []

def test_gethostbyname():
    """Test socket.gethostbyname()"""
    print("\n=== Testing socket.gethostbyname() ===")
    try:
        ip = socket.gethostbyname("google.com")
        print(f"gethostbyname resolved google.com to: {ip}")
        return [ip]
    except Exception as e:
        print(f"gethostbyname failed: {e}")
        return []

def test_dnspython_sync():
    """Test dnspython synchronous resolution"""
    print("\n=== Testing dnspython (sync) ===")
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()

        print(f"Nameservers: {resolver.nameservers}")
        print(f"Port: {resolver.port}")
        print(f"Timeout: {resolver.timeout}")

        answers = resolver.resolve("google.com", 'A')
        ips = [str(rdata) for rdata in answers]
        print(f"dnspython resolved google.com to: {ips}")
        print(f"TTL: {answers.rrset.ttl}")
        return ips
    except ImportError:
        print("dnspython not installed")
        return []
    except Exception as e:
        print(f"dnspython resolution failed: {e}")
        return []

async def test_dnspython_async():
    """Test dnspython async resolution"""
    print("\n=== Testing dnspython (async) ===")
    try:
        import dns.asyncresolver
        resolver = dns.asyncresolver.Resolver()

        print(f"Nameservers: {resolver.nameservers}")
        print(f"Port: {resolver.port}")
        print(f"Timeout: {resolver.timeout}")

        answers = await resolver.resolve("google.com", 'A')
        ips = [str(rdata) for rdata in answers]
        print(f"dnspython async resolved google.com to: {ips}")
        print(f"TTL: {answers.rrset.ttl}")
        return ips
    except ImportError:
        print("dnspython not installed")
        return []
    except Exception as e:
        print(f"dnspython async resolution failed: {e}")
        return []

def check_resolv_conf():
    """Check /etc/resolv.conf configuration"""
    print("\n=== Checking /etc/resolv.conf ===")
    try:
        with open('/etc/resolv.conf', 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    print(f"  {line}")
    except Exception as e:
        print(f"Could not read /etc/resolv.conf: {e}")

def check_nsswitch():
    """Check /etc/nsswitch.conf for hosts resolution order"""
    print("\n=== Checking /etc/nsswitch.conf (hosts line) ===")
    try:
        with open('/etc/nsswitch.conf', 'r') as f:
            for line in f:
                if line.strip().startswith('hosts:'):
                    print(f"  {line.strip()}")
                    break
    except:
        print("  /etc/nsswitch.conf not found (normal on some systems)")

def check_unbound_port():
    """Check if unbound is listening on localhost"""
    print("\n=== Checking for unbound on localhost ===")
    ports_to_check = [53, 5353]  # Standard DNS and possible alternate port

    for port in ports_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()

        if result == 0:
            print(f"  Port {port} is open on 127.0.0.1 (likely unbound)")
        else:
            print(f"  Port {port} is closed on 127.0.0.1")

def main():
    print("DNS Resolution Debug Tool")
    print("=" * 50)

    # Check system configuration
    check_resolv_conf()
    check_nsswitch()
    check_unbound_port()

    # Test different resolution methods
    socket_ips = test_socket_resolution()
    gethostbyname_ips = test_gethostbyname()
    dnspython_ips = test_dnspython_sync()

    # Test async
    loop = asyncio.get_event_loop()
    async_ips = loop.run_until_complete(test_dnspython_async())

    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY:")
    print(f"  Socket resolution: {bool(socket_ips)}")
    print(f"  gethostbyname: {bool(gethostbyname_ips)}")
    print(f"  dnspython sync: {bool(dnspython_ips)}")
    print(f"  dnspython async: {bool(async_ips)}")

    # Check if results match
    all_ips = set(socket_ips + gethostbyname_ips + dnspython_ips + async_ips)
    if len(all_ips) > 0:
        print(f"\nUnique IPs found: {all_ips}")
        if len(set(map(tuple, [socket_ips, dnspython_ips, async_ips]))) == 1:
            print("✅ All methods returned the same results")
        else:
            print("⚠️  Different methods returned different results")

if __name__ == "__main__":
    main()