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
grep -E "sent.*packet.*received.*packet" /tmp/multi_dest_test.log | tail -5
echo ""
echo "Handshake status:"
grep -E "(Handshake successful|Handshake failed)" /tmp/multi_dest_test.log | head -10
echo ""
echo "Data exchange:"
grep -E "(Read.*bytes|Wrote.*bytes|Stream.*created)" /tmp/multi_dest_test.log | tail -10
echo ""
echo "Errors:"
grep -E "CONNECTION_CLOSE" /tmp/multi_dest_test.log | tail -5
echo ""
echo "=== Full log saved to /tmp/multi_dest_test.log ==="
