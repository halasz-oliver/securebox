# SecureBox – Encrypted File Vault

A cross-platform encrypted file storage system with end-to-end encryption, implementing modern cryptographic standards.

## Features

- **Strong Encryption**: ChaCha20-Poly1305 authenticated encryption
- **Secure Key Derivation**: Argon2id password-based key derivation
- **Cross-Platform**: Works on macOS and Linux
- **Metadata Protection**: Encrypted file metadata storage
- **CLI Interface**: Easy-to-use command-line interface

## Security Features

- Password-based encryption using Argon2id
- Authenticated encryption with ChaCha20-Poly1305
- Secure random salt generation
- Memory-safe operations
- No plaintext data written to disk

## Requirements

- C++17 compatible compiler (GCC 7+, Clang 5+)
- CMake 3.15+
- libsodium 1.0.18+

## Installation

### macOS

```bash
# Install dependencies
brew install libsodium cmake

# Build
mkdir build && cd build
cmake ..
make
sudo make install
```

### Linux

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install libsodium-dev cmake build-essential

# Build
mkdir build && cd build
cmake ..
make
sudo make install
```

## Usage

### Initialize a new vault

```bash
securebox init /path/to/vault
```

### Add a file to the vault

```bash
securebox add /path/to/vault /path/to/file
```

### List files in the vault

```bash
securebox list /path/to/vault
```

### Extract a file from the vault

```bash
securebox extract /path/to/vault <file_id> /output/path
```

### Remove a file from the vault

```bash
securebox remove /path/to/vault <file_id>
```

### Change vault password

```bash
securebox change-password /path/to/vault
```

## Architecture

```
SecureBox/
├── include/
│   ├── crypto.h          # Cryptographic operations
│   ├── vault.h           # Vault management
│   ├── metadata.h        # Metadata handling
│   └── file_operations.h # File I/O operations
├── src/
│   ├── crypto.cpp
│   ├── vault.cpp
│   ├── metadata.cpp
│   ├── file_operations.cpp
│   └── main.cpp          # CLI interface
└── tests/
    └── test_crypto.cpp   # Unit tests
```

## Cryptographic Details

### Key Derivation
- Algorithm: Argon2id
- Memory: 64 MB
- Iterations: 3
- Parallelism: 1
- Salt: 16 bytes (random)

### Encryption
- Algorithm: ChaCha20-Poly1305
- Nonce: 24 bytes (random, XChaCha20)
- Authentication tag: 16 bytes

### File Format

```
Vault Structure:
├── .vault_config        # Encrypted vault configuration
├── .vault_metadata      # Encrypted file metadata
└── files/
    ├── <hash1>          # Encrypted file data
    └── <hash2>          # Encrypted file data
```

## Security Considerations

- Always use strong, unique passwords
- Store vault backups securely
- The vault password cannot be recovered if lost
- Encrypted files are stored with random names
- All metadata is encrypted

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please ensure all security-critical code is reviewed.

## Roadmap

- [ ] GUI interface
- [ ] Cloud sync support
- [ ] File compression
- [ ] Multiple user support
- [ ] Hardware key support (YubiKey)
