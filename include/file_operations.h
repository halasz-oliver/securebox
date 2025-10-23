#ifndef SECUREBOX_FILE_OPERATIONS_H
#define SECUREBOX_FILE_OPERATIONS_H

#include <string>
#include <vector>
#include <filesystem>

namespace securebox {

/**
 * File I/O operations
 */
class FileOperations {
public:
    /**
     * Read entire file into memory
     * @param path File path
     * @param data Output buffer
     * @return true if successful
     */
    static bool readFile(const std::filesystem::path& path, 
                        std::vector<uint8_t>& data);
    
    /**
     * Write data to file
     * @param path File path
     * @param data Data to write
     * @return true if successful
     */
    static bool writeFile(const std::filesystem::path& path,
                         const std::vector<uint8_t>& data);
    
    /**
     * Check if file exists
     * @param path File path
     * @return true if file exists
     */
    static bool fileExists(const std::filesystem::path& path);
    
    /**
     * Check if directory exists
     * @param path Directory path
     * @return true if directory exists
     */
    static bool directoryExists(const std::filesystem::path& path);
    
    /**
     * Create directory (including parent directories)
     * @param path Directory path
     * @return true if successful
     */
    static bool createDirectory(const std::filesystem::path& path);
    
    /**
     * Delete file
     * @param path File path
     * @return true if successful
     */
    static bool deleteFile(const std::filesystem::path& path);
    
    /**
     * Get file size
     * @param path File path
     * @return File size in bytes, or 0 on error
     */
    static uint64_t getFileSize(const std::filesystem::path& path);
    
    /**
     * Get MIME type from file extension
     * @param path File path
     * @return MIME type string
     */
    static std::string getMimeType(const std::filesystem::path& path);
    
    /**
     * Securely delete file (overwrite before deletion)
     * @param path File path
     * @return true if successful
     */
    static bool secureDelete(const std::filesystem::path& path);
};

} // namespace securebox

#endif // SECUREBOX_FILE_OPERATIONS_H
