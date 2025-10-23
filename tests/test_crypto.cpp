#include "../include/crypto.h"
#include <iostream>
#include <cassert>
#include <string>
#include <cstring>

using namespace securebox;

void testInitialization() {
    std::cout << "Testing initialization... ";
    assert(Crypto::initialize());
    std::cout << "PASSED\n";
}

void testSaltGeneration() {
    std::cout << "Testing salt generation... ";
    auto salt1 = Crypto::generateSalt();
    auto salt2 = Crypto::generateSalt();
    
    assert(salt1.size() == SALT_SIZE);
    assert(salt2.size() == SALT_SIZE);
    assert(salt1 != salt2); // Should be different
    std::cout << "PASSED\n";
}

void testKeyDerivation() {
    std::cout << "Testing key derivation... ";
    std::string password = "test_password_123";
    auto salt = Crypto::generateSalt();
    
    SecureBuffer key1(KEY_SIZE);
    SecureBuffer key2(KEY_SIZE);
    
    assert(Crypto::deriveKey(password, salt, key1));
    assert(Crypto::deriveKey(password, salt, key2));
    
    // Same password and salt should produce same key
    assert(std::memcmp(key1.data(), key2.data(), KEY_SIZE) == 0);
    
    // Different password should produce different key
    SecureBuffer key3(KEY_SIZE);
    assert(Crypto::deriveKey("different_password", salt, key3));
    assert(std::memcmp(key1.data(), key3.data(), KEY_SIZE) != 0);
    
    std::cout << "PASSED\n";
}

void testEncryptionDecryption() {
    std::cout << "Testing encryption/decryption... ";
    
    std::string password = "secure_password";
    auto salt = Crypto::generateSalt();
    SecureBuffer key(KEY_SIZE);
    assert(Crypto::deriveKey(password, salt, key));
    
    std::vector<uint8_t> plaintext = {
        'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'
    };
    
    std::vector<uint8_t> nonce(NONCE_SIZE);
    Crypto::randomBytes(nonce.data(), NONCE_SIZE);
    
    std::vector<uint8_t> ciphertext;
    assert(Crypto::encrypt(plaintext, key, nonce, ciphertext));
    
    // Ciphertext should be larger (includes MAC)
    assert(ciphertext.size() == plaintext.size() + MAC_SIZE);
    
    // Ciphertext should be different from plaintext
    assert(ciphertext != plaintext);
    
    std::vector<uint8_t> decrypted;
    assert(Crypto::decrypt(ciphertext, key, nonce, decrypted));
    
    // Decrypted should match original
    assert(decrypted == plaintext);
    
    std::cout << "PASSED\n";
}

void testAuthenticationFailure() {
    std::cout << "Testing authentication failure... ";
    
    std::string password = "password";
    auto salt = Crypto::generateSalt();
    SecureBuffer key(KEY_SIZE);
    assert(Crypto::deriveKey(password, salt, key));
    
    std::vector<uint8_t> plaintext = {'T', 'e', 's', 't'};
    std::vector<uint8_t> nonce(NONCE_SIZE);
    Crypto::randomBytes(nonce.data(), NONCE_SIZE);
    
    std::vector<uint8_t> ciphertext;
    assert(Crypto::encrypt(plaintext, key, nonce, ciphertext));
    
    // Tamper with ciphertext
    ciphertext[0] ^= 1;
    
    std::vector<uint8_t> decrypted;
    // Decryption should fail due to authentication
    assert(!Crypto::decrypt(ciphertext, key, nonce, decrypted));
    
    std::cout << "PASSED\n";
}

void testSHA256() {
    std::cout << "Testing SHA-256... ";
    
    std::vector<uint8_t> data = {'t', 'e', 's', 't'};
    std::string hash = Crypto::sha256(data);
    
    // SHA-256 produces 64 hex characters
    assert(hash.length() == 64);
    
    // Same data should produce same hash
    std::string hash2 = Crypto::sha256(data);
    assert(hash == hash2);
    
    // Different data should produce different hash
    std::vector<uint8_t> data2 = {'t', 'e', 's', 't', '2'};
    std::string hash3 = Crypto::sha256(data2);
    assert(hash != hash3);
    
    std::cout << "PASSED\n";
}

void testSecureCompare() {
    std::cout << "Testing secure compare... ";
    
    std::vector<uint8_t> a = {1, 2, 3, 4, 5};
    std::vector<uint8_t> b = {1, 2, 3, 4, 5};
    std::vector<uint8_t> c = {1, 2, 3, 4, 6};
    std::vector<uint8_t> d = {1, 2, 3};
    
    assert(Crypto::secureCompare(a, b));
    assert(!Crypto::secureCompare(a, c));
    assert(!Crypto::secureCompare(a, d));
    
    std::cout << "PASSED\n";
}

void testLargeData() {
    std::cout << "Testing large data encryption... ";
    
    std::string password = "password";
    auto salt = Crypto::generateSalt();
    SecureBuffer key(KEY_SIZE);
    assert(Crypto::deriveKey(password, salt, key));
    
    // Create 1MB of data
    std::vector<uint8_t> plaintext(1024 * 1024);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(i % 256);
    }
    
    std::vector<uint8_t> nonce(NONCE_SIZE);
    Crypto::randomBytes(nonce.data(), NONCE_SIZE);
    
    std::vector<uint8_t> ciphertext;
    assert(Crypto::encrypt(plaintext, key, nonce, ciphertext));
    
    std::vector<uint8_t> decrypted;
    assert(Crypto::decrypt(ciphertext, key, nonce, decrypted));
    
    assert(decrypted == plaintext);
    
    std::cout << "PASSED\n";
}

int main() {
    std::cout << "Running SecureBox Crypto Tests\n";
    std::cout << "================================\n\n";
    
    try {
        testInitialization();
        testSaltGeneration();
        testKeyDerivation();
        testEncryptionDecryption();
        testAuthenticationFailure();
        testSHA256();
        testSecureCompare();
        testLargeData();
        
        std::cout << "\n================================\n";
        std::cout << "All tests PASSED!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTest FAILED: " << e.what() << "\n";
        return 1;
    }
}
