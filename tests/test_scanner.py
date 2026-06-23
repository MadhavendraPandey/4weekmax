"""Tests for scanner module"""

import pytest
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

    def test_enumerate_subdomains_real(self):
        """Test subdomain enumeration on real domain"""
        scanner = AssetScanner("google.com")
        subdomains = scanner.enumerate_subdomains()

        assert len(subdomains) > 0
        assert isinstance(subdomains, list)
        # Check results contain google.com variants
        assert any("google.com" in sub for sub in subdomains)

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
