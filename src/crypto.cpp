#include "crypto.h"
#include <sodium.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace securebox {

// SecureBuffer implementation
SecureBuffer::SecureBuffer(size_t size) : buffer_(size) {}

SecureBuffer::~SecureBuffer() {
    if (!buffer_.empty()) {
        sodium_memzero(buffer_.data(), buffer_.size());
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept 
    : buffer_(std::move(other.buffer_)) {}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (!buffer_.empty()) {
            sodium_memzero(buffer_.data(), buffer_.size());
        }
        buffer_ = std::move(other.buffer_);
    }
    return *this;
}

// Crypto implementation
bool Crypto::initialize() {
    return sodium_init() >= 0;
}

bool Crypto::deriveKey(const std::string& password, 
                      const std::vector<uint8_t>& salt,
                      SecureBuffer& key) {
    if (salt.size() != SALT_SIZE || key.size() != KEY_SIZE) {
        return false;
    }
    
    int result = crypto_pwhash(
        key.data(),
        KEY_SIZE,
        password.c_str(),
        password.length(),
        salt.data(),
        ARGON2_ITERATIONS,
        ARGON2_MEMORY,
        crypto_pwhash_ALG_ARGON2ID13
    );
    
    return result == 0;
}

void Crypto::randomBytes(uint8_t* buffer, size_t size) {
    randombytes_buf(buffer, size);
}

std::vector<uint8_t> Crypto::generateSalt() {
    std::vector<uint8_t> salt(SALT_SIZE);
    randomBytes(salt.data(), SALT_SIZE);
    return salt;
}

bool Crypto::encrypt(const std::vector<uint8_t>& plaintext,
                    const SecureBuffer& key,
                    const std::vector<uint8_t>& nonce,
                    std::vector<uint8_t>& ciphertext) {
    if (key.size() != KEY_SIZE || nonce.size() != NONCE_SIZE) {
        return false;
    }
    
    // Allocate space for ciphertext + MAC
    ciphertext.resize(plaintext.size() + MAC_SIZE);
    
    unsigned long long ciphertext_len;
    int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(),
        &ciphertext_len,
        plaintext.data(),
        plaintext.size(),
        nullptr,  // No additional data
        0,
        nullptr,  // No secret nonce
        nonce.data(),
        key.data()
    );
    
    if (result != 0) {
        ciphertext.clear();
        return false;
    }
    
    ciphertext.resize(ciphertext_len);
    return true;
}

bool Crypto::decrypt(const std::vector<uint8_t>& ciphertext,
                    const SecureBuffer& key,
                    const std::vector<uint8_t>& nonce,
                    std::vector<uint8_t>& plaintext) {
    if (key.size() != KEY_SIZE || nonce.size() != NONCE_SIZE) {
        return false;
    }
    
    if (ciphertext.size() < MAC_SIZE) {
        return false;
    }
    
    // Allocate space for plaintext
    plaintext.resize(ciphertext.size() - MAC_SIZE);
    
    unsigned long long plaintext_len;
    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(),
        &plaintext_len,
        nullptr,  // No secret nonce
        ciphertext.data(),
        ciphertext.size(),
        nullptr,  // No additional data
        0,
        nonce.data(),
        key.data()
    );
    
    if (result != 0) {
        sodium_memzero(plaintext.data(), plaintext.size());
        plaintext.clear();
        return false;
    }
    
    plaintext.resize(plaintext_len);
    return true;
}

std::string Crypto::sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : hash) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

bool Crypto::secureCompare(const std::vector<uint8_t>& a,
                          const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace securebox
