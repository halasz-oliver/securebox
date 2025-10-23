#!/bin/bash

# Benchmark script for SecureBox
# Tests performance with different file sizes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="/tmp/securebox_benchmark_$$"
VAULT_PATH="$TEST_DIR/benchmark_vault"
TEST_PASSWORD="benchmark_password"

echo "SecureBox Performance Benchmark"
echo "================================"
echo ""

cleanup() {
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Create vault
echo "Creating test vault..."
echo -e "$TEST_PASSWORD\n$TEST_PASSWORD" | ../build/securebox init "$VAULT_PATH" > /dev/null 2>&1

# Benchmark function
benchmark_file_size() {
    local size_kb=$1
    local size_name=$2
    
    echo "Testing $size_name ($size_kb KB)..."
    
    # Create test file
    dd if=/dev/urandom of=test_file.bin bs=1024 count=$size_kb 2>/dev/null
    
    # Measure add time
    start_time=$(date +%s.%N)
    echo "$TEST_PASSWORD" | ../build/securebox add "$VAULT_PATH" test_file.bin > /dev/null 2>&1
    end_time=$(date +%s.%N)
    add_time=$(echo "$end_time - $start_time" | bc)
    
    # Get file ID (simplified - assumes last added)
    # In reality, would parse the output
    
    echo "  Add time: ${add_time}s"
    
    # Calculate throughput
    throughput=$(echo "scale=2; $size_kb / $add_time / 1024" | bc)
    echo "  Throughput: ${throughput} MB/s"
    
    rm test_file.bin
    echo ""
}

# Run benchmarks
benchmark_file_size 10 "10 KB"
benchmark_file_size 100 "100 KB"
benchmark_file_size 1024 "1 MB"
benchmark_file_size 10240 "10 MB"
benchmark_file_size 102400 "100 MB"

echo "Benchmark complete!"
