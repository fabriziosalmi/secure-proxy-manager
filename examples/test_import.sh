#!/bin/bash

# Test script for blacklist import functionality
# This script demonstrates that the API already supports plain text files

BASE_URL="http://localhost:8011"
AUTH_HEADER="Authorization: Basic $(echo -n admin:admin | base64)"

echo "=== Secure Proxy Manager - Blacklist Import Test ==="
echo ""

# Test 1: Domain blacklist import from content
echo "Test 1: Importing domain blacklist from direct content..."
RESPONSE=$(curl -s -X POST "${BASE_URL}/api/domain-blacklist/import" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d '{
    "content": "test-domain1.com\ntest-domain2.com\n*.malicious.example\n# This is a comment\ntest-domain3.com"
  }')

echo "Response: $RESPONSE"
echo ""

# Test 2: IP blacklist import from content  
echo "Test 2: Importing IP blacklist from direct content..."
RESPONSE=$(curl -s -X POST "${BASE_URL}/api/ip-blacklist/import" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d '{
    "content": "192.168.1.100\n10.0.0.5\n172.16.0.0/24\n# This is a comment\n203.0.113.42"
  }')

echo "Response: $RESPONSE"
echo ""

# Test 3: Generic endpoint with domain type
echo "Test 3: Using generic endpoint for domain import..."
RESPONSE=$(curl -s -X POST "${BASE_URL}/api/blacklists/import" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d '{
    "type": "domain",
    "content": "generic-test1.com\ngeneric-test2.com"
  }')

echo "Response: $RESPONSE"
echo ""

# Test 4: Generic endpoint with IP type
echo "Test 4: Using generic endpoint for IP import..."
RESPONSE=$(curl -s -X POST "${BASE_URL}/api/blacklists/import" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d '{
    "type": "ip", 
    "content": "198.51.100.1\n198.51.100.2"
  }')

echo "Response: $RESPONSE"
echo ""

echo "=== Test completed ==="
echo ""
echo "Usage examples for the GitHub user:"
echo ""
echo "For domain blacklists (like their example):"
echo 'curl -X POST http://localhost:8011/api/domain-blacklist/import \'
echo '  -H "Content-Type: application/json" \'
echo '  -H "Authorization: Basic $(echo -n admin:admin | base64)" \'
echo '  -d '"'"'{"url": "https://example.com/blacklist.txt"}'"'"''
echo ""
echo "For IP blacklists:"
echo 'curl -X POST http://localhost:8011/api/ip-blacklist/import \'
echo '  -H "Content-Type: application/json" \'
echo '  -H "Authorization: Basic $(echo -n admin:admin | base64)" \'
echo '  -d '"'"'{"url": "https://example.com/ip-blacklist.txt"}'"'"''
