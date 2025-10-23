#include "vault.h"
#include "file_operations.h"
#include <iostream>
#include <random>
#include <sstream>

namespace securebox {

// Static helper to generate unique vault ID
static std::string generateVaultId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 32; ++i) {
        ss << dis(gen);
    }
    return ss.str();
}

bool Vault::create(const std::filesystem::path& vaultPath,
                  const std::string& password) {
    // Check if vault already exists
    if (FileOperations::directoryExists(vaultPath)) {
        std::cerr << "Error: Vault directory already exists\n";
        return false;
    }
    
    // Create vault directory
    if (!FileOperations::createDirectory(vaultPath)) {
        std::cerr << "Error: Failed to create vault directory\n";
        return false;
    }
    
    // Create files subdirectory
    auto filesPath = vaultPath / "files";
    if (!FileOperations::createDirectory(filesPath)) {
        std::cerr << "Error: Failed to create files directory\n";
        return false;
    }
    
    // Generate salt and derive key
    auto salt = Crypto::generateSalt();
    SecureBuffer key(KEY_SIZE);
    if (!Crypto::deriveKey(password, salt, key)) {
        std::cerr << "Error: Failed to derive key\n";
        return false;
    }
    
    // Create vault configuration
    VaultConfig config;
    config.vaultId = generateVaultId();
    config.salt = salt;
    config.createdTime = std::chrono::system_clock::now();
    config.lastModified = config.createdTime;
    config.version = 1;
    config.totalFiles = 0;
    config.totalSize = 0;
    
    // Serialize and encrypt config
    MetadataManager metadata;
    metadata.setConfig(config);
    
    auto configData = metadata.serialize();
    auto nonce = Crypto::generateSalt(); // Reuse for nonce generation
    nonce.resize(NONCE_SIZE);
    Crypto::randomBytes(nonce.data(), NONCE_SIZE);
    
    std::vector<uint8_t> encryptedConfig;
    if (!Crypto::encrypt(configData, key, nonce, encryptedConfig)) {
        std::cerr << "Error: Failed to encrypt config\n";
        return false;
    }
    
    // Write config file (salt + nonce + encrypted data)
    std::vector<uint8_t> configFile;
    configFile.insert(configFile.end(), salt.begin(), salt.end());
    configFile.insert(configFile.end(), nonce.begin(), nonce.end());
    configFile.insert(configFile.end(), encryptedConfig.begin(), encryptedConfig.end());
    
    auto configPath = vaultPath / ".vault_config";
    if (!FileOperations::writeFile(configPath, configFile)) {
        std::cerr << "Error: Failed to write config file\n";
        return false;
    }
    
    // Create empty metadata file
    std::vector<uint8_t> emptyMetadata;
    auto metadataNonce = Crypto::generateSalt();
    metadataNonce.resize(NONCE_SIZE);
    Crypto::randomBytes(metadataNonce.data(), NONCE_SIZE);
    
    std::vector<uint8_t> encryptedMetadata;
    if (!Crypto::encrypt(emptyMetadata, key, metadataNonce, encryptedMetadata)) {
        std::cerr << "Error: Failed to encrypt metadata\n";
        return false;
    }
    
    std::vector<uint8_t> metadataFile;
    metadataFile.insert(metadataFile.end(), metadataNonce.begin(), metadataNonce.end());
    metadataFile.insert(metadataFile.end(), encryptedMetadata.begin(), encryptedMetadata.end());
    
    auto metadataPath = vaultPath / ".vault_metadata";
    if (!FileOperations::writeFile(metadataPath, metadataFile)) {
        std::cerr << "Error: Failed to write metadata file\n";
        return false;
    }
    
    std::cout << "Vault created successfully at: " << vaultPath << "\n";
    std::cout << "Vault ID: " << config.vaultId << "\n";
    
    return true;
}

std::unique_ptr<Vault> Vault::open(const std::filesystem::path& vaultPath,
                                   const std::string& password) {
    // Check if vault exists
    if (!FileOperations::directoryExists(vaultPath)) {
        std::cerr << "Error: Vault directory does not exist\n";
        return nullptr;
    }
    
    // Read config file
    auto configPath = vaultPath / ".vault_config";
    std::vector<uint8_t> configFile;
    if (!FileOperations::readFile(configPath, configFile)) {
        std::cerr << "Error: Failed to read config file\n";
        return nullptr;
    }
    
    if (configFile.size() < NONCE_SIZE) {
        std::cerr << "Error: Invalid config file\n";
        return nullptr;
    }
    
    // Extract nonce and encrypted data
    std::vector<uint8_t> nonce(configFile.begin(), configFile.begin() + NONCE_SIZE);
    std::vector<uint8_t> encryptedConfig(configFile.begin() + NONCE_SIZE, configFile.end());
    
    // Derive key from password
    MetadataManager tempMetadata;
    std::vector<uint8_t> configData;
    
    // We need the salt from config, but config is encrypted...
    // So we try to decrypt with a temporary key derived from a dummy salt
    // This won't work - we need to store salt separately or in plaintext
    
    // Better approach: Store salt in plaintext at start of config file
    // For now, let's assume we can read it
    
    // Actually, let's fix this properly: salt should be stored unencrypted
    // Modifying the approach: config file format is: salt + nonce + encrypted_data
    
    if (configFile.size() < SALT_SIZE + NONCE_SIZE) {
        std::cerr << "Error: Invalid config file format\n";
        return nullptr;
    }
    
    std::vector<uint8_t> salt(configFile.begin(), configFile.begin() + SALT_SIZE);
    nonce.assign(configFile.begin() + SALT_SIZE, configFile.begin() + SALT_SIZE + NONCE_SIZE);
    encryptedConfig.assign(configFile.begin() + SALT_SIZE + NONCE_SIZE, configFile.end());
    
    // Derive key
    SecureBuffer key(KEY_SIZE);
    if (!Crypto::deriveKey(password, salt, key)) {
        std::cerr << "Error: Failed to derive key\n";
        return nullptr;
    }
    
    // Decrypt config
    if (!Crypto::decrypt(encryptedConfig, key, nonce, configData)) {
        std::cerr << "Error: Failed to decrypt config (wrong password?)\n";
        return nullptr;
    }
    
    // Create vault object
    auto vault = std::unique_ptr<Vault>(new Vault(vaultPath, std::move(key)));
    
    // Load metadata
    if (!vault->loadMetadata()) {
        std::cerr << "Error: Failed to load metadata\n";
        return nullptr;
    }
    
    vault->isOpen_ = true;
    return vault;
}

Vault::Vault(const std::filesystem::path& vaultPath, SecureBuffer&& key)
    : vaultPath_(vaultPath), key_(std::move(key)), isOpen_(false) {}

bool Vault::close() {
    if (!isOpen_) {
        return false;
    }
    
    bool success = saveMetadata();
    isOpen_ = false;
    return success;
}

std::string Vault::addFile(const std::filesystem::path& filePath) {
    if (!isOpen_) {
        std::cerr << "Error: Vault is not open\n";
        return "";
    }
    
    // Read file
    std::vector<uint8_t> fileData;
    if (!FileOperations::readFile(filePath, fileData)) {
        std::cerr << "Error: Failed to read file\n";
        return "";
    }
    
    // Generate nonce
    std::vector<uint8_t> nonce(NONCE_SIZE);
    Crypto::randomBytes(nonce.data(), NONCE_SIZE);
    
    // Encrypt file
    std::vector<uint8_t> encryptedData;
    if (!Crypto::encrypt(fileData, key_, nonce, encryptedData)) {
        std::cerr << "Error: Failed to encrypt file\n";
        return "";
    }
    
    // Generate file ID (hash of encrypted data)
    std::string fileId = Crypto::sha256(encryptedData);
    
    // Save encrypted file
    auto encryptedPath = getEncryptedFilePath(fileId);
    if (!FileOperations::writeFile(encryptedPath, encryptedData)) {
        std::cerr << "Error: Failed to write encrypted file\n";
        return "";
    }
    
    // Create metadata
    FileMetadata metadata;
    metadata.fileId = fileId;
    metadata.originalName = filePath.filename().string();
    metadata.originalPath = filePath.string();
    metadata.originalSize = fileData.size();
    metadata.encryptedSize = encryptedData.size();
    metadata.mimeType = FileOperations::getMimeType(filePath);
    metadata.addedTime = std::chrono::system_clock::now();
    metadata.modifiedTime = metadata.addedTime;
    metadata.nonce = nonce;
    metadata.checksum = Crypto::sha256(fileData);
    
    metadata_.addFile(metadata);
    
    std::cout << "File added successfully\n";
    std::cout << "File ID: " << fileId << "\n";
    std::cout << "Original size: " << metadata.originalSize << " bytes\n";
    std::cout << "Encrypted size: " << metadata.encryptedSize << " bytes\n";
    
    return fileId;
}

bool Vault::extractFile(const std::string& fileId,
                       const std::filesystem::path& outputPath) {
    if (!isOpen_) {
        std::cerr << "Error: Vault is not open\n";
        return false;
    }
    
    // Get metadata
    const FileMetadata* metadata = metadata_.getFile(fileId);
    if (!metadata) {
        std::cerr << "Error: File not found in vault\n";
        return false;
    }
    
    // Read encrypted file
    auto encryptedPath = getEncryptedFilePath(fileId);
    std::vector<uint8_t> encryptedData;
    if (!FileOperations::readFile(encryptedPath, encryptedData)) {
        std::cerr << "Error: Failed to read encrypted file\n";
        return false;
    }
    
    // Decrypt file
    std::vector<uint8_t> fileData;
    if (!Crypto::decrypt(encryptedData, key_, metadata->nonce, fileData)) {
        std::cerr << "Error: Failed to decrypt file\n";
        return false;
    }
    
    // Verify checksum
    std::string checksum = Crypto::sha256(fileData);
    if (checksum != metadata->checksum) {
        std::cerr << "Error: Checksum mismatch (file may be corrupted)\n";
        return false;
    }
    
    // Write decrypted file
    if (!FileOperations::writeFile(outputPath, fileData)) {
        std::cerr << "Error: Failed to write output file\n";
        return false;
    }
    
    std::cout << "File extracted successfully to: " << outputPath << "\n";
    return true;
}

bool Vault::removeFile(const std::string& fileId) {
    if (!isOpen_) {
        std::cerr << "Error: Vault is not open\n";
        return false;
    }
    
    // Check if file exists
    if (!metadata_.getFile(fileId)) {
        std::cerr << "Error: File not found in vault\n";
        return false;
    }
    
    // Delete encrypted file
    auto encryptedPath = getEncryptedFilePath(fileId);
    if (!FileOperations::secureDelete(encryptedPath)) {
        std::cerr << "Warning: Failed to securely delete file\n";
    }
    
    // Remove metadata
    metadata_.removeFile(fileId);
    
    std::cout << "File removed successfully\n";
    return true;
}

const std::map<std::string, FileMetadata>& Vault::listFiles() const {
    return metadata_.getAllFiles();
}

const VaultConfig& Vault::getConfig() const {
    return metadata_.getConfig();
}

bool Vault::changePassword(const std::string& oldPassword,
                          const std::string& newPassword) {
    if (!isOpen_) {
        std::cerr << "Error: Vault is not open\n";
        return false;
    }
    
    // Verify old password by trying to derive the same key
    auto config = metadata_.getConfig();
    SecureBuffer oldKey(KEY_SIZE);
    if (!Crypto::deriveKey(oldPassword, config.salt, oldKey)) {
        std::cerr << "Error: Failed to derive old key\n";
        return false;
    }
    
    if (!Crypto::secureCompare(
        std::vector<uint8_t>(oldKey.data(), oldKey.data() + oldKey.size()),
        std::vector<uint8_t>(key_.data(), key_.data() + key_.size()))) {
        std::cerr << "Error: Old password is incorrect\n";
        return false;
    }
    
    // Generate new salt and derive new key
    auto newSalt = Crypto::generateSalt();
    SecureBuffer newKey(KEY_SIZE);
    if (!Crypto::deriveKey(newPassword, newSalt, newKey)) {
        std::cerr << "Error: Failed to derive new key\n";
        return false;
    }
    
    // Update config with new salt
    VaultConfig newConfig = config;
    newConfig.salt = newSalt;
    newConfig.lastModified = std::chrono::system_clock::now();
    metadata_.setConfig(newConfig);
    
    // Update key
    key_ = std::move(newKey);
    
    // Save everything with new key
    if (!saveMetadata() || !saveConfig()) {
        std::cerr << "Error: Failed to save with new password\n";
        return false;
    }
    
    std::cout << "Password changed successfully\n";
    return true;
}

bool Vault::verifyIntegrity() {
    if (!isOpen_) {
        std::cerr << "Error: Vault is not open\n";
        return false;
    }
    
    bool allValid = true;
    const auto& files = metadata_.getAllFiles();
    
    std::cout << "Verifying " << files.size() << " files...\n";
    
    for (const auto& [fileId, metadata] : files) {
        // Read encrypted file
        auto encryptedPath = getEncryptedFilePath(fileId);
        std::vector<uint8_t> encryptedData;
        if (!FileOperations::readFile(encryptedPath, encryptedData)) {
            std::cerr << "Error: Failed to read file " << fileId << "\n";
            allValid = false;
            continue;
        }
        
        // Decrypt file
        std::vector<uint8_t> fileData;
        if (!Crypto::decrypt(encryptedData, key_, metadata.nonce, fileData)) {
            std::cerr << "Error: Failed to decrypt file " << fileId << "\n";
            allValid = false;
            continue;
        }
        
        // Verify checksum
        std::string checksum = Crypto::sha256(fileData);
        if (checksum != metadata.checksum) {
            std::cerr << "Error: Checksum mismatch for file " << fileId << "\n";
            allValid = false;
            continue;
        }
        
        std::cout << "✓ " << metadata.originalName << "\n";
    }
    
    if (allValid) {
        std::cout << "All files verified successfully\n";
    } else {
        std::cout << "Some files failed verification\n";
    }
    
    return allValid;
}

bool Vault::loadMetadata() {
    auto metadataPath = getMetadataPath();
    std::vector<uint8_t> metadataFile;
    
    if (!FileOperations::readFile(metadataPath, metadataFile)) {
        return false;
    }
    
    if (metadataFile.size() < NONCE_SIZE) {
        return false;
    }
    
    // Extract nonce and encrypted data
    std::vector<uint8_t> nonce(metadataFile.begin(), metadataFile.begin() + NONCE_SIZE);
    std::vector<uint8_t> encryptedMetadata(metadataFile.begin() + NONCE_SIZE, metadataFile.end());
    
    // Decrypt metadata
    std::vector<uint8_t> metadataData;
    if (!Crypto::decrypt(encryptedMetadata, key_, nonce, metadataData)) {
        return false;
    }
    
    // Deserialize metadata (if not empty)
    if (!metadataData.empty()) {
        if (!metadata_.deserialize(metadataData)) {
            return false;
        }
    }
    
    return true;
}

bool Vault::saveMetadata() {
    // Serialize metadata
    auto metadataData = metadata_.serialize();
    
    // Generate nonce
    std::vector<uint8_t> nonce(NONCE_SIZE);
    Crypto::randomBytes(nonce.data(), NONCE_SIZE);
    
    // Encrypt metadata
    std::vector<uint8_t> encryptedMetadata;
    if (!Crypto::encrypt(metadataData, key_, nonce, encryptedMetadata)) {
        return false;
    }
    
    // Write metadata file
    std::vector<uint8_t> metadataFile;
    metadataFile.insert(metadataFile.end(), nonce.begin(), nonce.end());
    metadataFile.insert(metadataFile.end(), encryptedMetadata.begin(), encryptedMetadata.end());
    
    return FileOperations::writeFile(getMetadataPath(), metadataFile);
}

bool Vault::loadConfig() {
    // Config is loaded during open(), so this is a no-op
    return true;
}

bool Vault::saveConfig() {
    // Serialize config
    auto configData = metadata_.serialize();
    
    // Generate nonce
    std::vector<uint8_t> nonce(NONCE_SIZE);
    Crypto::randomBytes(nonce.data(), NONCE_SIZE);
    
    // Encrypt config
    std::vector<uint8_t> encryptedConfig;
    if (!Crypto::encrypt(configData, key_, nonce, encryptedConfig)) {
        return false;
    }
    
    // Write config file (salt + nonce + encrypted data)
    auto config = metadata_.getConfig();
    std::vector<uint8_t> configFile;
    configFile.insert(configFile.end(), config.salt.begin(), config.salt.end());
    configFile.insert(configFile.end(), nonce.begin(), nonce.end());
    configFile.insert(configFile.end(), encryptedConfig.begin(), encryptedConfig.end());
    
    return FileOperations::writeFile(getConfigPath(), configFile);
}

std::filesystem::path Vault::getConfigPath() const {
    return vaultPath_ / ".vault_config";
}

std::filesystem::path Vault::getMetadataPath() const {
    return vaultPath_ / ".vault_metadata";
}

std::filesystem::path Vault::getFilesPath() const {
    return vaultPath_ / "files";
}

std::filesystem::path Vault::getEncryptedFilePath(const std::string& fileId) const {
    return getFilesPath() / fileId;
}

} // namespace securebox
