#!/usr/bin/env python3
"""
Test suite for Certificate Transparency Log Monitor

Tests basic functionality and edge cases for the CT monitor.
"""

import pytest
import json
import re
from unittest.mock import Mock, patch, MagicMock
import base64
import time

# Import the module we're testing
# Note: Adjust import path based on your actual file structure
try:
    from ct_monitor import CTLogMonitor, CTResult, __version__
except ImportError:
    # Alternative import if running from same directory
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from ct_monitor import CTLogMonitor, CTResult, __version__


class TestCTResult:
    """Test CTResult class functionality"""
    
    def test_ct_result_creation(self):
        """Test basic CTResult creation and to_dict conversion"""
        result = CTResult(
            name="example.com",
            timestamp=1640995200000,
            cn="example.com",
            sha1="abc123def456",
            emails=["admin@example.com"],
            ips=["192.168.1.1"],
            dns=["example.com", "www.example.com"]
        )
        
        assert result.name == "example.com"
        assert result.timestamp == 1640995200000
        assert result.cn == "example.com"
        assert result.sha1 == "abc123def456"
        assert result.emails == ["admin@example.com"]
        assert result.ips == ["192.168.1.1"]
        assert result.dns == ["example.com", "www.example.com"]
    
    def test_ct_result_to_dict(self):
        """Test CTResult to_dict conversion"""
        result = CTResult(
            name="test.com",
            timestamp=1640995200000,
            cn="test.com",
            sha1="hash123"
        )
        
        data = result.to_dict()
        
        assert data["name"] == "test.com"
        assert data["ts"] == 1640995200000
        assert data["cn"] == "test.com"
        assert data["sha1"] == "hash123"
        assert data["email"] is None
        assert data["ip"] is None
        assert data["dns"] is None
    
    def test_ct_result_with_optional_fields(self):
        """Test CTResult with optional email, IP, and DNS fields"""
        result = CTResult(
            name="secure.example.com",
            timestamp=1640995200000,
            cn="secure.example.com",
            sha1="secureHash123",
            emails=["security@example.com", "admin@example.com"],
            ips=["10.0.0.1", "2001:db8::1"],
            dns=["secure.example.com", "*.secure.example.com"]
        )
        
        data = result.to_dict()
        
        assert len(data["email"]) == 2
        assert "security@example.com" in data["email"]
        assert len(data["ip"]) == 2
        assert "10.0.0.1" in data["ip"]
        assert len(data["dns"]) == 2


class TestCTLogMonitor:
    """Test CTLogMonitor class functionality"""
    
    def test_monitor_initialization(self):
        """Test CTLogMonitor initialization with default parameters"""
        monitor = CTLogMonitor()
        
        assert monitor.log_url is None
        assert monitor.tail_count == 100
        assert monitor.poll_time == 10
        assert monitor.follow is False
        assert monitor.pattern is None
        assert monitor.verbose is False
        assert monitor.quiet is False
        
        # Check statistics initialization
        assert monitor.stat_input == 0
        assert monitor.stat_output == 0
        assert monitor.stat_errors == 0
        assert monitor.stat_processed == 0
    
    def test_monitor_initialization_with_parameters(self):
        """Test CTLogMonitor initialization with custom parameters"""
        monitor = CTLogMonitor(
            log_url="https://ct.example.com/log/",
            tail_count=500,
            poll_time=30,
            follow=True,
            pattern=".*\\.example\\.com$",
            verbose=True,
            quiet=False
        )
        
        assert monitor.log_url == "https://ct.example.com/log/"
        assert monitor.tail_count == 500
        assert monitor.poll_time == 30
        assert monitor.follow is True
        assert monitor.pattern.pattern == ".*\\.example\\.com$"
        assert monitor.verbose is True
        assert monitor.quiet is False
    
    def test_conflicting_verbose_quiet(self):
        """Test that verbose and quiet can be set (validation happens at CLI level)"""
        # Note: The actual validation happens in main(), not in the class
        monitor = CTLogMonitor(verbose=True, quiet=True)
        assert monitor.verbose is True
        assert monitor.quiet is True
    
    def test_scrub_x509_value(self):
        """Test X509 value scrubbing functionality"""
        monitor = CTLogMonitor()
        
        # Test normal string
        assert monitor.scrub_x509_value("example.com") == "example.com"
        
        # Test string with null bytes
        assert monitor.scrub_x509_value("test\x00value") == "testvalue"
        
        # Test empty string
        assert monitor.scrub_x509_value("") == ""
        
        # Test None input
        assert monitor.scrub_x509_value(None) == ""
    
    def test_is_valid_hostname_or_ip(self):
        """Test hostname and IP validation"""
        monitor = CTLogMonitor()
        
        # Valid hostnames
        assert monitor.is_valid_hostname_or_ip("example.com") is True
        assert monitor.is_valid_hostname_or_ip("sub.example.com") is True
        assert monitor.is_valid_hostname_or_ip("test-site.co.uk") is True
        
        # Valid IPv4 addresses
        assert monitor.is_valid_hostname_or_ip("192.168.1.1") is True
        assert monitor.is_valid_hostname_or_ip("10.0.0.1") is True
        assert monitor.is_valid_hostname_or_ip("255.255.255.255") is True
        
        # Valid IPv6 addresses
        assert monitor.is_valid_hostname_or_ip("2001:db8::1") is True
        assert monitor.is_valid_hostname_or_ip("::1") is True
        
        # Invalid inputs
        assert monitor.is_valid_hostname_or_ip("") is False
        assert monitor.is_valid_hostname_or_ip("example with spaces") is False
        assert monitor.is_valid_hostname_or_ip("example:with:colons") is False
        assert monitor.is_valid_hostname_or_ip(None) is False
    
    def test_extract_timestamp_from_entry(self):
        """Test timestamp extraction from CT log entry"""
        monitor = CTLogMonitor()
        
        # Create a mock entry with valid leaf_input
        timestamp_ms = 1640995200000  # 2022-01-01 00:00:00 UTC
        timestamp_bytes = timestamp_ms.to_bytes(8, 'big')
        
        # Create a minimal leaf input with timestamp at bytes 2-9
        leaf_input = b'\x00\x00' + timestamp_bytes + b'\x00\x00' + b'dummy_cert_data'
        entry = {
            'leaf_input': base64.b64encode(leaf_input).decode('ascii')
        }
        
        extracted_ts = monitor.extract_timestamp_from_entry(entry)
        assert extracted_ts == timestamp_ms
    
    def test_extract_timestamp_fallback(self):
        """Test timestamp extraction fallback to current time"""
        monitor = CTLogMonitor()
        
        # Test with invalid entry
        entry = {'leaf_input': 'invalid_base64'}
        
        current_time = int(time.time() * 1000)
        extracted_ts = monitor.extract_timestamp_from_entry(entry)
        
        # Should be close to current time (within 1 second)
        assert abs(extracted_ts - current_time) < 1000
    
    @patch('requests.Session.get')
    def test_download_json_success(self, mock_get):
        """Test successful JSON download"""
        monitor = CTLogMonitor()
        
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"tree_size": 1000, "timestamp": 1640995200}
        mock_get.return_value = mock_response
        
        result = monitor.download_json("https://ct.example.com/get-sth")
        
        assert result["tree_size"] == 1000
        assert result["timestamp"] == 1640995200
        mock_get.assert_called_once()
    
    @patch('requests.Session.get')
    def test_download_json_rate_limited(self, mock_get):
        """Test JSON download with rate limiting"""
        monitor = CTLogMonitor(quiet=True)  # Quiet mode to suppress output
        
        # Mock rate-limited response followed by success
        rate_limited_response = Mock()
        rate_limited_response.status_code = 429
        
        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {"tree_size": 500}
        
        mock_get.side_effect = [rate_limited_response, success_response]
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            result = monitor.download_json("https://ct.example.com/get-sth")
        
        assert result["tree_size"] == 500
        assert mock_get.call_count == 2
    
    def test_pattern_compilation(self):
        """Test regex pattern compilation"""
        # Valid pattern
        monitor = CTLogMonitor(pattern=".*\\.example\\.com$")
        assert monitor.pattern is not None
        assert monitor.pattern.search("sub.example.com") is not None
        assert monitor.pattern.search("different.com") is None
        
        # No pattern
        monitor_no_pattern = CTLogMonitor()
        assert monitor_no_pattern.pattern is None


class TestVersionInfo:
    """Test version and metadata"""
    
    def test_version_format(self):
        """Test that version follows semantic versioning"""
        version_pattern = re.compile(r'^\d+\.\d+\.\d+$')
        assert version_pattern.match(__version__)
    
    def test_version_is_string(self):
        """Test that version is a string"""
        assert isinstance(__version__, str)
        assert len(__version__) > 0


class TestHelperFunctions:
    """Test standalone helper functions and utilities"""
    
    def test_ipv4_pattern(self):
        """Test IPv4 regex pattern"""
        from ct_monitor import IPV4_PATTERN
        
        # Valid IPv4 addresses
        assert IPV4_PATTERN.match("192.168.1.1") is not None
        assert IPV4_PATTERN.match("10.0.0.1") is not None
        assert IPV4_PATTERN.match("255.255.255.255") is not None
        assert IPV4_PATTERN.match("0.0.0.0") is not None
        
        # Invalid IPv4 addresses
        assert IPV4_PATTERN.match("256.1.1.1") is None
        assert IPV4_PATTERN.match("192.168.1") is None
        assert IPV4_PATTERN.match("not.an.ip.address") is None
        assert IPV4_PATTERN.match("") is None
    
    def test_ipv6_pattern(self):
        """Test IPv6 regex pattern"""
        from ct_monitor import IPV6_PATTERN
        
        # Valid IPv6 addresses
        assert IPV6_PATTERN.match("2001:db8::1") is not None
        assert IPV6_PATTERN.match("::1") is not None
        assert IPV6_PATTERN.match("fe80::1%lo0") is not None
        
        # Invalid IPv6 addresses
        assert IPV6_PATTERN.match("not:an:ipv6:address:g") is None
        assert IPV6_PATTERN.match("192.168.1.1") is None
        assert IPV6_PATTERN.match("") is None


class TestIntegration:
    """Integration tests that test multiple components working together"""
    
    def test_ct_result_json_serialization(self):
        """Test that CTResult can be properly JSON serialized"""
        result = CTResult(
            name="integration.test.com",
            timestamp=1640995200000,
            cn="integration.test.com",
            sha1="integration_hash_123",
            emails=["test@integration.com"],
            ips=["203.0.113.1"],
            dns=["integration.test.com", "www.integration.test.com"]
        )
        
        # Convert to dict and serialize to JSON
        data = result.to_dict()
        json_str = json.dumps(data)
        
        # Parse back and verify
        parsed = json.loads(json_str)
        assert parsed["name"] == "integration.test.com"
        assert parsed["email"][0] == "test@integration.com"
        assert len(parsed["dns"]) == 2
    
    @patch('requests.Session.get')
    def test_monitor_basic_workflow(self, mock_get):
        """Test basic monitor workflow without actually hitting CT logs"""
        monitor = CTLogMonitor(quiet=True, tail_count=1)
        
        # Mock the log list response
        log_list_response = Mock()
        log_list_response.status_code = 200
        log_list_response.json.return_value = {
            "operators": [
                {
                    "name": "Test Operator",
                    "logs": [
                        {"url": "https://test.ct.example.com/"}
                    ]
                }
            ]
        }
        
        mock_get.return_value = log_list_response
        
        logs = monitor.get_all_logs()
        assert len(logs) == 1
        assert logs[0] == "https://test.ct.example.com/"


if __name__ == "__main__":
    pytest.main([__file__])
