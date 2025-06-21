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
import sys
import os

# Import the module we're testing
# Handle the hyphenated filename by importing as a module
try:
    # Try direct import first (if file is renamed to ct_monitor.py)
    from ct_monitor import CTLogMonitor, CTResult, __version__
except ImportError:
    try:
        # Import the hyphenated filename using importlib
        import importlib.util
        spec = importlib.util.spec_from_file_location("ct_monitor", "ct-monitor.py")
        if spec is None:
            raise ImportError("Could not load ct-monitor.py")
        ct_monitor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ct_monitor)
        
        # Import the classes and variables we need
        CTLogMonitor = ct_monitor.CTLogMonitor
        CTResult = ct_monitor.CTResult
        __version__ = ct_monitor.__version__
        
    except (ImportError, FileNotFoundError):
        # Fallback: add current directory to path and try importing
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("ct_monitor", "ct-monitor.py")
            ct_monitor = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ct_monitor)
            
            CTLogMonitor = ct_monitor.CTLogMonitor
            CTResult = ct_monitor.CTResult
            __version__ = ct_monitor.__version__
        except Exception as e:
            raise ImportError(f"Could not import ct-monitor.py: {e}")


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
        
        # Valid IPv4 addresses
        assert monitor.is_valid_hostname_or_ip("192.168.1.1") is True
        assert monitor.is_valid_hostname_or_ip("10.0.0.1") is True
        
        # Invalid inputs
        assert monitor.is_valid_hostname_or_ip("") is False
        assert monitor.is_valid_hostname_or_ip("example with spaces") is False
        assert monitor.is_valid_hostname_or_ip(None) is False


class TestVersionInfo:
    """Test version and metadata"""
    
    def test_version_format(self):
        """Test that version follows semantic versioning"""
        version_pattern = re.compile(r"^\d+\.\d+\.\d+$")
        assert version_pattern.match(__version__)
    
    def test_version_is_string(self):
        """Test that version is a string"""
        assert isinstance(__version__, str)
        assert len(__version__) > 0


class TestBasicFunctionality:
    """Test basic functionality without external dependencies"""
    
    def test_ct_result_json_serialization(self):
        """Test that CTResult can be properly JSON serialized"""
        result = CTResult(
            name="test.example.com",
            timestamp=1640995200000,
            cn="test.example.com",
            sha1="test_hash_123"
        )
        
        # Convert to dict and serialize to JSON
        data = result.to_dict()
        json_str = json.dumps(data)
        
        # Parse back and verify
        parsed = json.loads(json_str)
        assert parsed["name"] == "test.example.com"
        assert parsed["ts"] == 1640995200000


if __name__ == "__main__":
    pytest.main([__file__])
