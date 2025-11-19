# SecureBox

An encrypted file vault for macOS and Linux.

## What does it do?

SecureBox creates an encrypted container (a "vault") where you can store sensitive files. Files are encrypted using modern cryptography (ChaCha20-Poly1305) and your password is turned into an encryption key using Argon2id, which makes brute-force attacks impractical.

The encrypted files live in a directory on your filesystem, but they're unreadable without the vault password. Even the filenames and metadata are encrypted.

## Getting started

You'll need:
- A C++17 compiler (GCC 7 or newer, or Clang 5+)
- CMake 3.15 or newer
- libsodium 1.0.18 or newer

### On macOS

```bash
brew install libsodium cmake
mkdir build && cd build
cmake ..
make
sudo make install
```

### On Linux (Ubuntu/Debian)

```bash
sudo apt-get install libsodium-dev cmake build-essential
mkdir build && cd build
cmake ..
make
sudo make install
```

## How to use it

### Creating a vault

```bash
securebox init ~/my-vault
```

You'll be prompted for a password. Pick a good one—if you lose it, your files are gone.

### Adding files

```bash
securebox add ~/my-vault /path/to/secret-file.pdf
```

The file gets encrypted and stored in the vault. You'll get back a file ID (a hash) that you can use to extract it later.

### Viewing what's in your vault

```bash
securebox list ~/my-vault
```

This shows all files with their original names, sizes, and when they were added.

### Getting files out

```bash
securebox extract ~/my-vault <file-id> /where/to/save/it.pdf
```

The file is decrypted and saved to the location you specify.

### Removing files

```bash
securebox remove ~/my-vault <file-id>
```

This securely deletes the encrypted file from the vault (overwrites it with random data first).

### Other commands

```bash
# Get vault info (number of files, total size, etc)
securebox info ~/my-vault

# Verify all files are intact and uncorrupted
securebox verify ~/my-vault

# Change the vault password
securebox change-password ~/my-vault
```

## Command-line options

- `--verbose` or `-v`: Show what's happening under the hood
- `--dry-run`: Preview what would happen without actually doing it (works with `remove`)
- `--force` or `-f`: Skip confirmation prompts

## Technical details

If you're curious about the cryptography:

**Password → Key derivation**
- Argon2id with 64 MB memory, 3 iterations
- 16-byte random salt (stored unencrypted)
- Produces a 32-byte key

**Encryption**
- ChaCha20-Poly1305 (authenticated encryption)
- 24-byte random nonce per file
- 16-byte authentication tag

Each file gets its own random nonce, and the nonces are stored in the encrypted metadata. The original filename, path, MIME type, and timestamps are all encrypted too.

## Important notes

- **Your password cannot be recovered.** If you forget it, your files are permanently inaccessible. There's no backdoor or recovery mechanism.
- Use a strong, unique password. This isn't the place for "password123".
- The vault directory contains encrypted files with random names. Don't try to read them directly—use the extract command.
- Back up your vault directory regularly, but keep the backups secure (they're encrypted, but still contain your sensitive data).

## What's next

I'm planning to add:
- Progress indicators for large files (done!)
- File compression before encryption
- A simple GUI
- Better error messages
- File tagging and search
- Cloud sync support (maybe)

Check out TODO.md for the full roadmap.

## Contributing

Found a bug? Have an idea? Pull requests are welcome. This is a side project but I'm happy to review contributions.

## License

MIT License—do whatever you want with it. See LICENSE for the legal text.

## Questions?

The code is documented, but if something's unclear, feel free to open an issue.