#ifndef SECUREBOX_CRYPTO_H
#define SECUREBOX_CRYPTO_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace securebox {

// Cryptographic constants
constexpr size_t SALT_SIZE = 16;
constexpr size_t KEY_SIZE = 32;
constexpr size_t NONCE_SIZE = 24; // XChaCha20 nonce
constexpr size_t MAC_SIZE = 16;   // Poly1305 MAC

// Argon2id parameters
constexpr uint64_t ARGON2_MEMORY = 64 * 1024 * 1024; // 64 MB
constexpr uint32_t ARGON2_ITERATIONS = 3;
constexpr uint32_t ARGON2_PARALLELISM = 1;

/**
 * Secure memory buffer that zeros itself on destruction
 */
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size);
    ~SecureBuffer();
    
    // Disable copy
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    // Enable move
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    
    uint8_t* data() { return buffer_.data(); }
    const uint8_t* data() const { return buffer_.data(); }
    size_t size() const { return buffer_.size(); }
    
private:
    std::vector<uint8_t> buffer_;
};

/**
 * Cryptographic operations wrapper
 */
class Crypto {
public:
    /**
     * Initialize libsodium library
     * @return true if initialization successful
     */
    static bool initialize();
    
    /**
     * Derive encryption key from password using Argon2id
     * @param password User password
     * @param salt Salt for key derivation
     * @param key Output buffer for derived key (must be KEY_SIZE bytes)
     * @return true if successful
     */
    static bool deriveKey(const std::string& password, 
                         const std::vector<uint8_t>& salt,
                         SecureBuffer& key);
    
    /**
     * Generate cryptographically secure random bytes
     * @param buffer Output buffer
     * @param size Number of bytes to generate
     */
    static void randomBytes(uint8_t* buffer, size_t size);
    
    /**
     * Generate random salt
     * @return Vector containing random salt
     */
    static std::vector<uint8_t> generateSalt();
    
    /**
     * Encrypt data using ChaCha20-Poly1305
     * @param plaintext Data to encrypt
     * @param key Encryption key (KEY_SIZE bytes)
     * @param nonce Nonce (NONCE_SIZE bytes)
     * @param ciphertext Output buffer for encrypted data
     * @return true if successful
     */
    static bool encrypt(const std::vector<uint8_t>& plaintext,
                       const SecureBuffer& key,
                       const std::vector<uint8_t>& nonce,
                       std::vector<uint8_t>& ciphertext);
    
    /**
     * Decrypt data using ChaCha20-Poly1305
     * @param ciphertext Encrypted data
     * @param key Decryption key (KEY_SIZE bytes)
     * @param nonce Nonce (NONCE_SIZE bytes)
     * @param plaintext Output buffer for decrypted data
     * @return true if successful (authentication passes)
     */
    static bool decrypt(const std::vector<uint8_t>& ciphertext,
                       const SecureBuffer& key,
                       const std::vector<uint8_t>& nonce,
                       std::vector<uint8_t>& plaintext);
    
    /**
     * Compute SHA-256 hash
     * @param data Input data
     * @return Hash as hex string
     */
    static std::string sha256(const std::vector<uint8_t>& data);
    
    /**
     * Securely compare two byte arrays in constant time
     * @param a First array
     * @param b Second array
     * @return true if arrays are equal
     */
    static bool secureCompare(const std::vector<uint8_t>& a,
                             const std::vector<uint8_t>& b);
};

} // namespace securebox

#endif // SECUREBOX_CRYPTO_H
