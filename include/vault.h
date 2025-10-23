#ifndef SECUREBOX_VAULT_H
#define SECUREBOX_VAULT_H

#include "crypto.h"
#include "metadata.h"
#include <string>
#include <filesystem>
#include <memory>

namespace securebox {

/**
 * Vault manager - main interface for vault operations
 */
class Vault {
public:
    /**
     * Create a new vault
     * @param vaultPath Path to vault directory
     * @param password Vault password
     * @return true if successful
     */
    static bool create(const std::filesystem::path& vaultPath,
                      const std::string& password);
    
    /**
     * Open an existing vault
     * @param vaultPath Path to vault directory
     * @param password Vault password
     * @return Unique pointer to Vault object, or nullptr on failure
     */
    static std::unique_ptr<Vault> open(const std::filesystem::path& vaultPath,
                                       const std::string& password);
    
    /**
     * Close the vault and save metadata
     * @return true if successful
     */
    bool close();
    
    /**
     * Add a file to the vault
     * @param filePath Path to file to add
     * @return File ID on success, empty string on failure
     */
    std::string addFile(const std::filesystem::path& filePath);
    
    /**
     * Extract a file from the vault
     * @param fileId File ID
     * @param outputPath Output file path
     * @return true if successful
     */
    bool extractFile(const std::string& fileId,
                    const std::filesystem::path& outputPath);
    
    /**
     * Remove a file from the vault
     * @param fileId File ID
     * @return true if successful
     */
    bool removeFile(const std::string& fileId);
    
    /**
     * List all files in the vault
     * @return Map of file ID to metadata
     */
    const std::map<std::string, FileMetadata>& listFiles() const;
    
    /**
     * Get vault configuration
     * @return Vault configuration
     */
    const VaultConfig& getConfig() const;
    
    /**
     * Change vault password
     * @param oldPassword Current password
     * @param newPassword New password
     * @return true if successful
     */
    bool changePassword(const std::string& oldPassword,
                       const std::string& newPassword);
    
    /**
     * Verify vault integrity
     * @return true if all files are intact
     */
    bool verifyIntegrity();
    
private:
    Vault(const std::filesystem::path& vaultPath, SecureBuffer&& key);
    
    bool loadMetadata();
    bool saveMetadata();
    bool loadConfig();
    bool saveConfig();
    
    std::filesystem::path getConfigPath() const;
    std::filesystem::path getMetadataPath() const;
    std::filesystem::path getFilesPath() const;
    std::filesystem::path getEncryptedFilePath(const std::string& fileId) const;
    
    std::filesystem::path vaultPath_;
    SecureBuffer key_;
    MetadataManager metadata_;
    bool isOpen_;
};

} // namespace securebox

#endif // SECUREBOX_VAULT_H
