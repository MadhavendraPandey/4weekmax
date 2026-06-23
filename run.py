#!/usr/bin/env python
"""Entry point for asset enumeration tool"""

from src.scanner import main

if __name__ == "__main__":
    from src.scanner import AssetScanner

    scanner = AssetScanner("google.com")
    subdomains = scanner.enumerate_subdomains()
    print(f"\n[*] Found {len(subdomains)} subdomains")

    ports = scanner.scan_ports(hosts=["google.com"])
    print(f"\n[*] Port scan results: {ports}")

    scanner.export_json("results.json")
    print("\n[+] Results exported to results.json")
