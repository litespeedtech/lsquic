#!/bin/bash
# Test script for multi_dest_test program

cd /home/dmitri/devel/lsquic-gh-ssh

# Build
echo "Building multi_dest_test..."
make multi_dest_test 2>&1 | tail -2

# Run the test
echo "Running test..."
./bin/multi_dest_test > /tmp/multi_dest_test.log 2>&1 &
PID=$!

# Wait for test to complete
sleep 12

# Stop the test
kill -9 $PID 2>/dev/null
wait $PID 2>/dev/null

# Show results
echo "=== Test Results ==="
echo ""
echo "Summary:"
grep -E "Test completed|Successful responses|GOT RESPONSE" /tmp/multi_dest_test.log | tail -10
echo ""
echo "Sent requests:"
grep -E "Sent GET.*request" /tmp/multi_dest_test.log
echo ""
echo "Got responses from:"
grep -E "=== Response from" /tmp/multi_dest_test.log
echo ""
echo "Data received:"
grep -E "Received.*bytes \(headers" /tmp/multi_dest_test.log
echo ""
echo "=== Full log saved to /tmp/multi_dest_test.log ==="
