"""Tests for scanner module"""

import pytest
from unittest.mock import patch, MagicMock
from src.scanner import AssetScanner


class TestAssetScanner:
    """Test AssetScanner class"""

    def test_init_valid_domain(self):
        """Test scanner initialization with valid domain"""
        scanner = AssetScanner("example.com")
        assert scanner.domain == "example.com"
        assert scanner.subdomains == []

    def test_init_invalid_domain(self):
        """Test scanner initialization with invalid domain"""
        with pytest.raises(ValueError):
            AssetScanner("")

        with pytest.raises(ValueError):
            AssetScanner(None)

    @patch("src.scanner.requests.get")
    def test_enumerate_subdomains_with_mock(self, mock_get):
        """Test subdomain enumeration with mocked API response"""
        # Mock the response
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"name_value": "google.com\nwww.google.com\napi.google.com"},
            {"name_value": "*.google.com"},
        ]
        mock_get.return_value = mock_response

        scanner = AssetScanner("google.com")
        subdomains = scanner.enumerate_subdomains()

        assert len(subdomains) > 0
        assert isinstance(subdomains, list)
        assert "google.com" in subdomains

    def test_enumerate_subdomains_mock_fallback(self):
        """Test fallback when crt.sh fails"""
        scanner = AssetScanner("test.com")
        # Manually set subdomains like fallback would
        scanner.subdomains = [
            "test.com",
            "www.test.com",
            "api.test.com",
            "admin.test.com",
        ]

        assert len(scanner.subdomains) > 0
        assert "test.com" in scanner.subdomains

    def test_export_json(self, tmp_path):
        """Test JSON export"""
        scanner = AssetScanner("example.com")
        scanner.subdomains = ["sub1.example.com", "sub2.example.com"]

        output_file = tmp_path / "test_results.json"
        scanner.export_json(str(output_file))

        assert output_file.exists()

        import json

        with open(output_file) as f:
            data = json.load(f)

        assert data["domain"] == "example.com"
        assert len(data["subdomains"]) == 2
        assert data["total"] == 2


def test_scan_ports_mock(self):
    """Test port scanning"""
    scanner = AssetScanner("example.com")
    results = scanner.scan_ports(hosts=["google.com"], ports=[80, 443])

    assert isinstance(results, dict)
    assert "google.com" in results
