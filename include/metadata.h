#ifndef SECUREBOX_METADATA_H
#define SECUREBOX_METADATA_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <chrono>

namespace securebox {

/**
 * Metadata for a single file in the vault
 */
struct FileMetadata {
    std::string fileId;           // Unique identifier (hash of encrypted file)
    std::string originalName;     // Original filename
    std::string originalPath;     // Original file path
    uint64_t originalSize;        // Original file size in bytes
    uint64_t encryptedSize;       // Encrypted file size in bytes
    std::string mimeType;         // MIME type
    std::chrono::system_clock::time_point addedTime;
    std::chrono::system_clock::time_point modifiedTime;
    std::vector<uint8_t> nonce;   // Encryption nonce for this file
    std::string checksum;         // SHA-256 of original file
};

/**
 * Vault configuration and metadata
 */
struct VaultConfig {
    std::string vaultId;          // Unique vault identifier
    std::vector<uint8_t> salt;    // Salt for key derivation
    std::chrono::system_clock::time_point createdTime;
    std::chrono::system_clock::time_point lastModified;
    uint32_t version;             // Vault format version
    uint64_t totalFiles;          // Number of files in vault
    uint64_t totalSize;           // Total size of encrypted files
};

/**
 * Metadata manager for vault
 */
class MetadataManager {
public:
    MetadataManager();
    
    /**
     * Add file metadata
     * @param metadata File metadata to add
     */
    void addFile(const FileMetadata& metadata);
    
    /**
     * Remove file metadata
     * @param fileId File ID to remove
     * @return true if file was found and removed
     */
    bool removeFile(const std::string& fileId);
    
    /**
     * Get file metadata by ID
     * @param fileId File ID
     * @return Pointer to metadata or nullptr if not found
     */
    const FileMetadata* getFile(const std::string& fileId) const;
    
    /**
     * Get all file metadata
     * @return Map of file ID to metadata
     */
    const std::map<std::string, FileMetadata>& getAllFiles() const;
    
    /**
     * Get vault configuration
     * @return Vault configuration
     */
    const VaultConfig& getConfig() const;
    
    /**
     * Set vault configuration
     * @param config Vault configuration
     */
    void setConfig(const VaultConfig& config);
    
    /**
     * Serialize metadata to binary format
     * @return Serialized metadata
     */
    std::vector<uint8_t> serialize() const;
    
    /**
     * Deserialize metadata from binary format
     * @param data Serialized metadata
     * @return true if successful
     */
    bool deserialize(const std::vector<uint8_t>& data);
    
    /**
     * Update vault statistics
     */
    void updateStatistics();
    
private:
    VaultConfig config_;
    std::map<std::string, FileMetadata> files_;
    
    // Serialization helpers
    void serializeString(std::vector<uint8_t>& buffer, const std::string& str) const;
    void serializeUint64(std::vector<uint8_t>& buffer, uint64_t value) const;
    void serializeUint32(std::vector<uint8_t>& buffer, uint32_t value) const;
    void serializeBytes(std::vector<uint8_t>& buffer, const std::vector<uint8_t>& bytes) const;
    void serializeTime(std::vector<uint8_t>& buffer, const std::chrono::system_clock::time_point& time) const;
    
    bool deserializeString(const uint8_t*& ptr, const uint8_t* end, std::string& str);
    bool deserializeUint64(const uint8_t*& ptr, const uint8_t* end, uint64_t& value);
    bool deserializeUint32(const uint8_t*& ptr, const uint8_t* end, uint32_t& value);
    bool deserializeBytes(const uint8_t*& ptr, const uint8_t* end, std::vector<uint8_t>& bytes);
    bool deserializeTime(const uint8_t*& ptr, const uint8_t* end, std::chrono::system_clock::time_point& time);
};

} // namespace securebox

#endif // SECUREBOX_METADATA_H
