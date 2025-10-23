#include "metadata.h"
#include <cstring>
#include <algorithm>

namespace securebox {

MetadataManager::MetadataManager() {
    config_.version = 1;
    config_.totalFiles = 0;
    config_.totalSize = 0;
    config_.createdTime = std::chrono::system_clock::now();
    config_.lastModified = config_.createdTime;
}

void MetadataManager::addFile(const FileMetadata& metadata) {
    files_[metadata.fileId] = metadata;
    updateStatistics();
}

bool MetadataManager::removeFile(const std::string& fileId) {
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        return false;
    }
    files_.erase(it);
    updateStatistics();
    return true;
}

const FileMetadata* MetadataManager::getFile(const std::string& fileId) const {
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        return nullptr;
    }
    return &it->second;
}

const std::map<std::string, FileMetadata>& MetadataManager::getAllFiles() const {
    return files_;
}

const VaultConfig& MetadataManager::getConfig() const {
    return config_;
}

void MetadataManager::setConfig(const VaultConfig& config) {
    config_ = config;
}

void MetadataManager::updateStatistics() {
    config_.totalFiles = files_.size();
    config_.totalSize = 0;
    for (const auto& [id, metadata] : files_) {
        config_.totalSize += metadata.encryptedSize;
    }
    config_.lastModified = std::chrono::system_clock::now();
}

// Serialization helpers
void MetadataManager::serializeString(std::vector<uint8_t>& buffer, const std::string& str) const {
    uint32_t len = static_cast<uint32_t>(str.length());
    serializeUint32(buffer, len);
    buffer.insert(buffer.end(), str.begin(), str.end());
}

void MetadataManager::serializeUint64(std::vector<uint8_t>& buffer, uint64_t value) const {
    for (int i = 0; i < 8; ++i) {
        buffer.push_back(static_cast<uint8_t>(value >> (i * 8)));
    }
}

void MetadataManager::serializeUint32(std::vector<uint8_t>& buffer, uint32_t value) const {
    for (int i = 0; i < 4; ++i) {
        buffer.push_back(static_cast<uint8_t>(value >> (i * 8)));
    }
}

void MetadataManager::serializeBytes(std::vector<uint8_t>& buffer, const std::vector<uint8_t>& bytes) const {
    uint32_t len = static_cast<uint32_t>(bytes.size());
    serializeUint32(buffer, len);
    buffer.insert(buffer.end(), bytes.begin(), bytes.end());
}

void MetadataManager::serializeTime(std::vector<uint8_t>& buffer, 
                                   const std::chrono::system_clock::time_point& time) const {
    auto duration = time.time_since_epoch();
    uint64_t millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    serializeUint64(buffer, millis);
}

bool MetadataManager::deserializeString(const uint8_t*& ptr, const uint8_t* end, std::string& str) {
    uint32_t len;
    if (!deserializeUint32(ptr, end, len)) {
        return false;
    }
    if (ptr + len > end) {
        return false;
    }
    str.assign(reinterpret_cast<const char*>(ptr), len);
    ptr += len;
    return true;
}

bool MetadataManager::deserializeUint64(const uint8_t*& ptr, const uint8_t* end, uint64_t& value) {
    if (ptr + 8 > end) {
        return false;
    }
    value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(ptr[i]) << (i * 8);
    }
    ptr += 8;
    return true;
}

bool MetadataManager::deserializeUint32(const uint8_t*& ptr, const uint8_t* end, uint32_t& value) {
    if (ptr + 4 > end) {
        return false;
    }
    value = 0;
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<uint32_t>(ptr[i]) << (i * 8);
    }
    ptr += 4;
    return true;
}

bool MetadataManager::deserializeBytes(const uint8_t*& ptr, const uint8_t* end, 
                                      std::vector<uint8_t>& bytes) {
    uint32_t len;
    if (!deserializeUint32(ptr, end, len)) {
        return false;
    }
    if (ptr + len > end) {
        return false;
    }
    bytes.assign(ptr, ptr + len);
    ptr += len;
    return true;
}

bool MetadataManager::deserializeTime(const uint8_t*& ptr, const uint8_t* end, 
                                     std::chrono::system_clock::time_point& time) {
    uint64_t millis;
    if (!deserializeUint64(ptr, end, millis)) {
        return false;
    }
    time = std::chrono::system_clock::time_point(std::chrono::milliseconds(millis));
    return true;
}

std::vector<uint8_t> MetadataManager::serialize() const {
    std::vector<uint8_t> buffer;
    
    // Magic number
    buffer.push_back('S');
    buffer.push_back('B');
    buffer.push_back('M');
    buffer.push_back('D');
    
    // Serialize config
    serializeString(buffer, config_.vaultId);
    serializeBytes(buffer, config_.salt);
    serializeTime(buffer, config_.createdTime);
    serializeTime(buffer, config_.lastModified);
    serializeUint32(buffer, config_.version);
    serializeUint64(buffer, config_.totalFiles);
    serializeUint64(buffer, config_.totalSize);
    
    // Serialize files
    serializeUint32(buffer, static_cast<uint32_t>(files_.size()));
    for (const auto& [id, metadata] : files_) {
        serializeString(buffer, metadata.fileId);
        serializeString(buffer, metadata.originalName);
        serializeString(buffer, metadata.originalPath);
        serializeUint64(buffer, metadata.originalSize);
        serializeUint64(buffer, metadata.encryptedSize);
        serializeString(buffer, metadata.mimeType);
        serializeTime(buffer, metadata.addedTime);
        serializeTime(buffer, metadata.modifiedTime);
        serializeBytes(buffer, metadata.nonce);
        serializeString(buffer, metadata.checksum);
    }
    
    return buffer;
}

bool MetadataManager::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return false;
    }
    
    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();
    
    // Check magic number
    if (ptr[0] != 'S' || ptr[1] != 'B' || ptr[2] != 'M' || ptr[3] != 'D') {
        return false;
    }
    ptr += 4;
    
    // Deserialize config
    if (!deserializeString(ptr, end, config_.vaultId)) return false;
    if (!deserializeBytes(ptr, end, config_.salt)) return false;
    if (!deserializeTime(ptr, end, config_.createdTime)) return false;
    if (!deserializeTime(ptr, end, config_.lastModified)) return false;
    if (!deserializeUint32(ptr, end, config_.version)) return false;
    if (!deserializeUint64(ptr, end, config_.totalFiles)) return false;
    if (!deserializeUint64(ptr, end, config_.totalSize)) return false;
    
    // Deserialize files
    uint32_t fileCount;
    if (!deserializeUint32(ptr, end, fileCount)) return false;
    
    files_.clear();
    for (uint32_t i = 0; i < fileCount; ++i) {
        FileMetadata metadata;
        if (!deserializeString(ptr, end, metadata.fileId)) return false;
        if (!deserializeString(ptr, end, metadata.originalName)) return false;
        if (!deserializeString(ptr, end, metadata.originalPath)) return false;
        if (!deserializeUint64(ptr, end, metadata.originalSize)) return false;
        if (!deserializeUint64(ptr, end, metadata.encryptedSize)) return false;
        if (!deserializeString(ptr, end, metadata.mimeType)) return false;
        if (!deserializeTime(ptr, end, metadata.addedTime)) return false;
        if (!deserializeTime(ptr, end, metadata.modifiedTime)) return false;
        if (!deserializeBytes(ptr, end, metadata.nonce)) return false;
        if (!deserializeString(ptr, end, metadata.checksum)) return false;
        
        files_[metadata.fileId] = metadata;
    }
    
    return true;
}

} // namespace securebox
