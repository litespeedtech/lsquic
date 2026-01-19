#!/bin/bash
# Test script for multi_dest_test program

cd /home/dmitri/devel/lsquic-gh-ssh

# Build
echo "Building multi_dest_test..."
make multi_dest_test 2>&1 | tail -2

# Run the test
echo "Running test..."
./bin/multi_dest_test 2>&1 > /tmp/multi_dest_test.log &
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
grep -E "Successful responses|GOT RESPONSE|no response" /tmp/multi_dest_test.log
echo ""
echo "Response data:"
grep -E "Read.*bytes from" /tmp/multi_dest_test.log | head -10
echo ""
echo "Requests sent:"
grep -E "Sent GET.*request" /tmp/multi_dest_test.log
echo ""
echo "Errors (if any):"
grep -E "CONNECTION_CLOSE.*error" /tmp/multi_dest_test.log | tail -3
echo ""
echo "=== Full log saved to /tmp/multi_dest_test.log ==="
