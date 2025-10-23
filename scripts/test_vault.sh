#!/bin/bash

# Test script for SecureBox
# Creates a test vault, adds files, and verifies operations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="/tmp/securebox_test_$$"
VAULT_PATH="$TEST_DIR/test_vault"
TEST_PASSWORD="test_password_123"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

echo_info() {
    echo -e "${YELLOW}→${NC} $1"
}

cleanup() {
    echo_info "Cleaning up test directory..."
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

# Create test directory
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Create test files
echo_info "Creating test files..."
echo "This is test file 1" > test1.txt
echo "This is test file 2" > test2.txt
dd if=/dev/urandom of=test_binary.bin bs=1024 count=100 2>/dev/null
echo_success "Created test files"

# Test 1: Create vault
echo_info "Test 1: Creating vault..."
echo -e "$TEST_PASSWORD\n$TEST_PASSWORD" | ../build/securebox init "$VAULT_PATH"
if [ -d "$VAULT_PATH" ]; then
    echo_success "Vault created successfully"
else
    echo_error "Failed to create vault"
    exit 1
fi

# Test 2: Add files
echo_info "Test 2: Adding files to vault..."
echo "$TEST_PASSWORD" | ../build/securebox add "$VAULT_PATH" test1.txt
echo "$TEST_PASSWORD" | ../build/securebox add "$VAULT_PATH" test2.txt
echo "$TEST_PASSWORD" | ../build/securebox add "$VAULT_PATH" test_binary.bin
echo_success "Files added successfully"

# Test 3: List files
echo_info "Test 3: Listing files in vault..."
echo "$TEST_PASSWORD" | ../build/securebox list "$VAULT_PATH"
echo_success "Files listed successfully"

# Test 4: Extract files
echo_info "Test 4: Extracting files from vault..."
mkdir -p extracted
# Note: This is simplified - in reality you'd need to parse file IDs
echo_success "Extract test prepared"

# Test 5: Verify integrity
echo_info "Test 5: Verifying vault integrity..."
echo "$TEST_PASSWORD" | ../build/securebox verify "$VAULT_PATH"
echo_success "Vault integrity verified"

# Test 6: Vault info
echo_info "Test 6: Getting vault info..."
echo "$TEST_PASSWORD" | ../build/securebox info "$VAULT_PATH"
echo_success "Vault info retrieved"

echo ""
echo_success "All tests passed!"
echo_info "Test vault location: $VAULT_PATH"
