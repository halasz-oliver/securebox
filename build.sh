#!/bin/bash

# SecureBox Build Script

set -e

echo "================================"
echo "SecureBox Build Script"
echo "================================"
echo ""

# Check for libsodium
if ! pkg-config --exists libsodium; then
    echo "Error: libsodium not found"
    echo "Please install libsodium:"
    echo "  macOS: brew install libsodium"
    echo "  Linux: sudo apt-get install libsodium-dev"
    exit 1
fi

# Create build directory
if [ -d "build" ]; then
    echo "Cleaning existing build directory..."
    rm -rf build
fi

mkdir build
cd build

echo "Running CMake..."
cmake ..

echo ""
echo "Building..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)

echo ""
echo "================================"
echo "Build completed successfully!"
echo "================================"
echo ""
echo "Executable: build/securebox"
echo ""
echo "To install system-wide, run:"
echo "  sudo make install"
echo ""
