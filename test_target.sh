#!/bin/bash

# Test script for the specific target mentioned by the user
# Target: 178.63.237.151

echo "=== Testing Improved Authentication Detection ==="
echo "Target: 178.63.237.151"
echo

# Check if the binary exists
if [ ! -f "./redgem_bruter" ]; then
    echo "Error: redgem_bruter binary not found. Please build the project first."
    exit 1
fi

echo "1. Testing Elasticsearch (port 9200) - Should now detect authentication:"
echo "./redgem_bruter -target 178.63.237.151 -port 9200"
echo
./redgem_bruter -target 178.63.237.151 -port 9200
echo

echo "2. Testing RabbitMQ/AMQP (port 5672) - Should now detect authentication:"
echo "./redgem_bruter -target 178.63.237.151 -port 5672"
echo
./redgem_bruter -target 178.63.237.151 -port 5672
echo

echo "3. Testing Kibana (port 5601) - Should now detect authentication:"
echo "./redgem_bruter -target 178.63.237.151 -port 5601"
echo
./redgem_bruter -target 178.63.237.151 -port 5601
echo

echo "4. Testing SSH (port 22) - Should continue to detect authentication correctly:"
echo "./redgem_bruter -target 178.63.237.151 -port 22"
echo
./redgem_bruter -target 178.63.237.151 -port 22
echo

echo "5. Full scan of all mentioned ports:"
echo "./redgem_bruter -target 178.63.237.151 -port 22,80,443,5601,5672,9200"
echo
./redgem_bruter -target 178.63.237.151 -port 22,80,443,5601,5672,9200
echo

echo "=== Test completed ==="
echo "The improved version should now correctly detect authentication requirements"
echo "for Elasticsearch, RabbitMQ, and Kibana services." 