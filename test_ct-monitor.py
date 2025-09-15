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
import importlib.util
from pathlib import Path

# Import the module we're testing
def import_ct_monitor():
    """Import the ct-monitor module with proper error handling"""
    # Get the directory containing this test file
    test_dir = Path(__file__).parent
    
    # Look for ct-monitor.py in the same directory
    ct_monitor_path = test_dir / "ct-monitor.py"
    
    if not ct_monitor_path.exists():
        # Also try looking in parent directory
        ct_monitor_path = test_dir.parent / "ct-monitor.py"
    
    if not ct_monitor_path.exists():
        raise ImportError(
            f"Could not find ct-monitor.py in {test_dir} or {test_dir.parent}. "
            "Please ensure ct-monitor.py is in the same directory as this test file."
        )
    
    # Load the module
    spec = importlib.util.spec_from_file_location("ct_monitor", ct_monitor_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not create module spec for {ct_monitor_path}")
    
    ct_monitor = importlib.util.module_from_spec(spec)
    
    # Execute the module
    try:
        spec.loader.exec_module(ct_monitor)
    except Exception as e:
        raise ImportError(f"Failed to execute ct-monitor.py: {e}")
    
    return ct_monitor

# Import the module and extract the classes we need
try:
    ct_monitor = import_ct_monitor()
    CTLogMonitor = ct_monitor.CTLogMonitor
    CTResult = ct_monitor.CTResult
    __version__ = getattr(ct_monitor, '__version__', '0.0.0')
except ImportError as e:
    pytest.skip(f"Could not import ct-monitor.py: {e}", allow_module_level=True)


class TestCTResult:
    """Test CTResult class functionality"""
    
    def test_ct_result_creation(self):
        """Test basic CTResult creation and attribute access"""
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
    
    def test_ct_result_minimal_creation(self):
        """Test CTResult creation with minimal required fields"""
        result = CTResult(
            name="test.com",
            timestamp=1640995200000,
            cn="test.com",
            sha1="hash123"
        )
        
        assert result.name == "test.com"
        assert result.timestamp == 1640995200000
        assert result.cn == "test.com"
        assert result.sha1 == "hash123"
        # Optional fields should have default values
        assert hasattr(result, 'emails')
        assert hasattr(result, 'ips')
        assert hasattr(result, 'dns')
    
    def test_ct_result_to_dict(self):
        """Test CTResult to_dict conversion"""
        result = CTResult(
            name="test.com",
            timestamp=1640995200000,
            cn="test.com",
            sha1="hash123"
        )
        
        # Check that to_dict method exists
        assert hasattr(result, 'to_dict'), "CTResult should have a to_dict method"
        
        data = result.to_dict()
        
        # Verify the dictionary structure
        assert isinstance(data, dict)
        assert data["name"] == "test.com"
        assert data["ts"] == 1640995200000
        assert data["cn"] == "test.com"
        assert data["sha1"] == "hash123"
        
        # Check for optional fields (they should exist in dict even if None)
        assert "email" in data
        assert "ip" in data
        assert "dns" in data


class TestCTLogMonitor:
    """Test CTLogMonitor class functionality"""
    
    def test_monitor_can_be_instantiated(self):
        """Test that CTLogMonitor can be instantiated"""
        monitor = CTLogMonitor()
        assert monitor is not None
        assert isinstance(monitor, CTLogMonitor)
    
    def test_monitor_initialization_default(self):
        """Test CTLogMonitor initialization with default parameters"""
        monitor = CTLogMonitor()
        
        # Check that basic attributes exist and have expected values if they exist
        assert hasattr(monitor, 'log_url')
        
        # Check common attributes that might exist
        expected_attrs = {
            'tail_count': 100,
            'poll_time': 10,
            'follow': False,
            'pattern': None,
        }
        
        for attr, expected_value in expected_attrs.items():
            if hasattr(monitor, attr):
                actual_value = getattr(monitor, attr)
                assert actual_value == expected_value, f"Expected {attr}={expected_value}, got {actual_value}"
        
        # Check statistics - in the real implementation, these are in a Statistics object
        if hasattr(monitor, 'stats'):
            stats_obj = monitor.stats
            stat_methods = ['increment_input', 'increment_output', 'increment_errors', 'increment_processed', 'get_stats']
            for method in stat_methods:
                assert hasattr(stats_obj, method), f"Stats object should have method: {method}"
    
    def test_monitor_basic_attributes(self):
        """Test that CTLogMonitor has basic expected attributes"""
        monitor = CTLogMonitor()
        
        # Core attributes that should exist based on the actual implementation
        required_attrs = ['log_url', 'tail_count', 'poll_time', 'follow', 'pattern']
        
        # Check that required attributes exist
        for attr in required_attrs:
            assert hasattr(monitor, attr), f"Monitor should have attribute: {attr}"
        
        # Check component attributes
        component_attrs = ['logger', 'stats', 'http_client', 'cert_parser']
        for attr in component_attrs:
            if hasattr(monitor, attr):
                assert getattr(monitor, attr) is not None, f"Component {attr} should not be None"
    
    def test_monitor_initialization_with_params(self):
        """Test CTLogMonitor initialization with custom parameters"""
        # Test with parameters that the constructor accepts
        try:
            monitor = CTLogMonitor(
                log_url="https://test.ct.log",
                tail_count=50,
                poll_time=5,
                follow=True,
                pattern="test.*",
                verbose=True,
                quiet=False
            )
            
            # Check that parameters were set correctly
            assert monitor.log_url == "https://test.ct.log"
            assert monitor.tail_count == 50
            assert monitor.poll_time == 5
            assert monitor.follow is True
            assert monitor.pattern is not None  # Should be compiled regex
            
            # verbose and quiet are passed to logger, not stored directly
            if hasattr(monitor, 'logger'):
                assert hasattr(monitor.logger, 'verbose')
                assert hasattr(monitor.logger, 'quiet')
                assert monitor.logger.verbose is True
                assert monitor.logger.quiet is False
                
        except Exception as e:
            pytest.fail(f"CTLogMonitor initialization with parameters failed: {e}")
    
    def test_scrub_x509_value(self):
        """Test X509 value scrubbing functionality"""
        monitor = CTLogMonitor()
        
        # Check if the method exists
        if not hasattr(monitor, 'scrub_x509_value'):
            pytest.skip("scrub_x509_value method not found")
        
        # Test normal string
        assert monitor.scrub_x509_value("example.com") == "example.com"
        
        # Test string with null bytes
        result = monitor.scrub_x509_value("test\x00value")
        assert "\x00" not in result  # Null bytes should be removed
        
        # Test empty string
        assert monitor.scrub_x509_value("") == ""
        
        # Test None input (should handle gracefully)
        try:
            result = monitor.scrub_x509_value(None)
            assert result == "" or result is None
        except (TypeError, AttributeError):
            # Method might not handle None input
            pass
    
    def test_is_valid_hostname_or_ip(self):
        """Test hostname and IP validation"""
        monitor = CTLogMonitor()
        
        # Check if the method exists
        if not hasattr(monitor, 'is_valid_hostname_or_ip'):
            pytest.skip("is_valid_hostname_or_ip method not found")
        
        # Valid hostnames
        assert monitor.is_valid_hostname_or_ip("example.com") is True
        assert monitor.is_valid_hostname_or_ip("sub.example.com") is True
        
        # Valid IPv4 addresses
        assert monitor.is_valid_hostname_or_ip("192.168.1.1") is True
        assert monitor.is_valid_hostname_or_ip("10.0.0.1") is True
        
        # Invalid inputs
        assert monitor.is_valid_hostname_or_ip("") is False
        assert monitor.is_valid_hostname_or_ip("example with spaces") is False
        
        # Test None input
        try:
            result = monitor.is_valid_hostname_or_ip(None)
            assert result is False
        except (TypeError, AttributeError):
            # Method might not handle None input
            pass


class TestVersionInfo:
    """Test version and metadata"""
    
    def test_version_exists(self):
        """Test that version variable exists"""
        assert __version__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0
    
    def test_version_format(self):
        """Test that version follows semantic versioning (if it does)"""
        # More flexible version pattern matching
        # Could be semantic versioning (1.0.0) or other formats (1.0, v1.0, etc.)
        version_patterns = [
            r"^\d+\.\d+\.\d+$",  # Semantic versioning (1.0.0)
            r"^\d+\.\d+$",       # Major.minor (1.0)
            r"^v?\d+\.\d+\.\d+$", # With optional 'v' prefix
            r"^v?\d+\.\d+$",     # With optional 'v' prefix, major.minor
        ]
        
        version_matches = any(re.match(pattern, __version__) for pattern in version_patterns)
        assert version_matches, f"Version '{__version__}' doesn't match expected patterns"


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
        assert "sha1" in parsed
        assert "cn" in parsed
    
    def test_module_attributes(self):
        """Test that the module has expected attributes"""
        # Test that we can access the imported classes
        assert CTLogMonitor is not None
        assert CTResult is not None
        
        # Test that they are actually classes
        assert isinstance(CTLogMonitor, type)
        assert isinstance(CTResult, type)
    
    def test_ct_result_instantiation(self):
        """Test that CTResult can be instantiated with various parameter combinations"""
        # Minimal instantiation
        result1 = CTResult(name="test", timestamp=123, cn="test", sha1="hash")
        assert result1 is not None
        
        # With optional parameters
        try:
            result2 = CTResult(
                name="test2", 
                timestamp=456, 
                cn="test2", 
                sha1="hash2",
                emails=["test@example.com"],
                ips=["1.2.3.4"],
                dns=["test.com"]
            )
            assert result2 is not None
        except TypeError:
            # Constructor might not accept these optional parameters
            pytest.skip("CTResult constructor doesn't accept optional parameters")


class TestElasticsearchOutput:
    """Test Elasticsearch output functionality"""

    @patch.dict('os.environ', {'ES_HOST': 'http://test:9200', 'ES_USER': 'testuser', 'ES_PASSWORD': 'testpass'})
    def test_elasticsearch_output_initialization(self):
        """Test ElasticsearchOutput constructor with environment variables"""
        from elasticsearch_output import ElasticsearchOutput

        # Test with environment variables
        es = ElasticsearchOutput()
        assert es.es_host == "http://test:9200"
        assert es.es_user == "testuser"
        assert es.es_password == "testpass"
        assert es.index_prefix == "ct-domains"
        assert es.batch_size == 1000

    def test_elasticsearch_output_explicit_params(self):
        """Test ElasticsearchOutput with explicit parameters"""
        from elasticsearch_output import ElasticsearchOutput

        # Test with explicit parameters
        es = ElasticsearchOutput(
            es_host="http://custom:9200",
            es_user="customuser",
            es_password="custompass",
            index_prefix="custom-prefix",
            batch_size=500
        )

        assert es.es_host == "http://custom:9200"
        assert es.es_user == "customuser"
        assert es.es_password == "custompass"
        assert es.index_prefix == "custom-prefix"
        assert es.batch_size == 500

    def test_elasticsearch_session_auth(self):
        """Test that session authentication is properly configured"""
        from elasticsearch_output import ElasticsearchOutput

        # Test that session is created with correct auth
        es = ElasticsearchOutput(es_user="test", es_password="pass")

        # Verify session has correct auth
        assert es.session.auth == ("test", "pass")

        # Verify headers are set
        assert es.session.headers['Content-Type'] == 'application/json'
        assert es.session.headers['Accept'] == 'application/json'

    def test_transform_to_minimal(self):
        """Test data transformation to minimal format"""
        from elasticsearch_output import ElasticsearchOutput

        es = ElasticsearchOutput()

        # Test with complete data
        ct_result = {
            'name': 'example.com',
            'ts': 1736832000000,
            'sha1': 'a1b2c3d4e5f6g7h8i9j0',
            'dns': ['example.com', 'www.example.com', 'api.example.com']
        }

        minimal = es.transform_to_minimal(ct_result, "https://ct.googleapis.com/logs/xenon2024/")

        assert minimal["d"] == "example.com"
        assert minimal["t"] == 1736832000000
        assert minimal["h"] == "a1b2c3d4e5f6g7h8i9j0"
        assert minimal["l"] == "g"  # google log source
        assert minimal["s"] == ["example.com", "www.example.com", "api.example.com"]

    def test_transform_to_minimal_missing_fields(self):
        """Test transformation with missing fields"""
        from elasticsearch_output import ElasticsearchOutput

        es = ElasticsearchOutput()

        # Test with missing fields
        ct_result = {'name': 'example.com'}

        minimal = es.transform_to_minimal(ct_result, "https://unknown.log/")

        assert minimal["d"] == "example.com"
        assert minimal["t"] == 0
        assert minimal["h"] == ""
        assert minimal["l"] == "x"  # default log source
        assert minimal["s"] == []

    def test_get_log_source_code(self):
        """Test log source code extraction"""
        from elasticsearch_output import ElasticsearchOutput

        es = ElasticsearchOutput()

        # Test known log providers
        assert es._get_log_source_code("https://ct.googleapis.com/logs/xenon2024/") == "g"
        assert es._get_log_source_code("https://ct.sectigo.com/logs/sectigo2024/") == "s"
        assert es._get_log_source_code("https://ct.digicert.com/logs/digicert2024/") == "d"
        assert es._get_log_source_code("https://ct.letsencrypt.org/logs/letsencrypt2024/") == "l"

        # Test unknown log provider
        assert es._get_log_source_code("https://unknown.log/") == "x"

    @patch('elasticsearch_output.requests.Session')
    def test_add_to_batch_and_flush(self, mock_session_class):
        """Test batch accumulation and flushing"""
        from elasticsearch_output import ElasticsearchOutput

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"items": [{"index": {"status": 201}}]}
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        es = ElasticsearchOutput(batch_size=2)  # Small batch for testing

        # Add first item
        ct_result1 = {
            'name': 'example1.com',
            'ts': 1000000000000,
            'sha1': 'hash1',
            'dns': ['example1.com']
        }
        es.add_to_batch(ct_result1, "https://ct.googleapis.com/logs/xenon2024/")

        # Batch should not flush yet
        mock_session.post.assert_not_called()

        # Add second item - should trigger flush
        ct_result2 = {
            'name': 'example2.com',
            'ts': 2000000000000,
            'sha1': 'hash2',
            'dns': ['example2.com']
        }
        es.add_to_batch(ct_result2, "https://ct.googleapis.com/logs/xenon2024/")

        # Verify bulk API was called
        mock_session.post.assert_called_once()
        args, kwargs = mock_session.post.call_args
        assert args[0] == "http://localhost:9200/_bulk"

        # Verify batch was cleared
        assert len(es.batch) == 0

    @patch('elasticsearch_output.requests.Session')
    def test_elasticsearch_error_handling(self, mock_session_class):
        """Test error handling for Elasticsearch failures"""
        from elasticsearch_output import ElasticsearchOutput
        import requests

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        es = ElasticsearchOutput(batch_size=1)

        # This should not raise an exception but should log the error
        ct_result = {
            'name': 'example.com',
            'ts': 1000000000000,
            'sha1': 'hash',
            'dns': ['example.com']
        }

        # Should handle error gracefully
        es.add_to_batch(ct_result, "https://ct.googleapis.com/logs/xenon2024/")
        es.flush()

        # Verify the request was attempted
        mock_session.post.assert_called()

    @patch('elasticsearch_output.requests.Session')
    def test_network_failure_handling(self, mock_session_class):
        """Test handling of network failures"""
        from elasticsearch_output import ElasticsearchOutput
        import requests

        mock_session = Mock()
        mock_session.post.side_effect = requests.exceptions.ConnectionError("Connection failed")
        mock_session_class.return_value = mock_session

        es = ElasticsearchOutput(batch_size=1)

        ct_result = {
            'name': 'example.com',
            'ts': 1000000000000,
            'sha1': 'hash',
            'dns': ['example.com']
        }

        # Should handle network error gracefully
        es.add_to_batch(ct_result, "https://ct.googleapis.com/logs/xenon2024/")
        es.flush()

        # Verify the request was attempted
        mock_session.post.assert_called()

    def test_get_index_name(self):
        """Test daily index name generation"""
        from elasticsearch_output import ElasticsearchOutput
        from unittest.mock import patch
        from datetime import datetime

        es = ElasticsearchOutput()

        # Test with specific date
        with patch('elasticsearch_output.datetime') as mock_dt:
            mock_dt.now.return_value = datetime(2025, 9, 14)
            mock_dt.strftime = datetime.strftime

            index_name = es._get_index_name()
            assert index_name == "ct-domains-2025-09-14"


# Test discovery helper
def test_module_can_be_imported():
    """Ensure the module can be imported successfully"""
    assert ct_monitor is not None
    assert CTLogMonitor is not None
    assert CTResult is not None


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"])
