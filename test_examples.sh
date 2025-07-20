#!/bin/bash

# RedGem Bruter Test Examples
# This script demonstrates various usage scenarios for the RedGem Bruter tool

echo "=== RedGem Bruter Test Examples ==="
echo

# Check if the binary exists
if [ ! -f "./redgem_bruter" ]; then
    echo "Error: redgem_bruter binary not found. Please build the project first."
    exit 1
fi

echo "1. Basic scan of localhost (all default services):"
echo "./redgem_bruter -target localhost"
echo
./redgem_bruter -target localhost
echo

echo "2. Scan specific ports:"
echo "./redgem_bruter -target localhost -port 22,80,443,3306"
echo
./redgem_bruter -target localhost -port 22,80,443,3306
echo

echo "3. Scan with JSON output:"
echo "./redgem_bruter -target localhost -f json"
echo
./redgem_bruter -target localhost -f json
echo

echo "4. Scan with custom timeout:"
echo "./redgem_bruter -target localhost -timeout 10s"
echo
./redgem_bruter -target localhost -timeout 10s
echo

echo "5. Save results to file:"
echo "./redgem_bruter -target localhost -o scan_results.txt"
echo
./redgem_bruter -target localhost -o scan_results.txt
echo

echo "6. CSV output:"
echo "./redgem_bruter -target localhost -f csv -o results.csv"
echo
./redgem_bruter -target localhost -f csv -o results.csv
echo

echo "7. Show help:"
echo "./redgem_bruter -help"
echo
./redgem_bruter -help
echo

echo "=== Test completed ==="
echo "Note: Attack mode (-a flag) is not demonstrated in this script for safety reasons."
echo "Use attack mode only on systems you own or have explicit permission to test." 