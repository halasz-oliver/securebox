#include "file_operations.h"
#include <fstream>
#include <random>
#include <map>

namespace securebox {

bool FileOperations::readFile(const std::filesystem::path& path, 
                             std::vector<uint8_t>& data) {
    try {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return false;
        }
        
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        data.resize(size);
        if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
            return false;
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

bool FileOperations::writeFile(const std::filesystem::path& path,
                              const std::vector<uint8_t>& data) {
    try {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return file.good();
    } catch (...) {
        return false;
    }
}

bool FileOperations::fileExists(const std::filesystem::path& path) {
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

bool FileOperations::directoryExists(const std::filesystem::path& path) {
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

bool FileOperations::createDirectory(const std::filesystem::path& path) {
    try {
        return std::filesystem::create_directories(path);
    } catch (...) {
        return false;
    }
}

bool FileOperations::deleteFile(const std::filesystem::path& path) {
    try {
        return std::filesystem::remove(path);
    } catch (...) {
        return false;
    }
}

uint64_t FileOperations::getFileSize(const std::filesystem::path& path) {
    try {
        if (!fileExists(path)) {
            return 0;
        }
        return std::filesystem::file_size(path);
    } catch (...) {
        return 0;
    }
}

std::string FileOperations::getMimeType(const std::filesystem::path& path) {
    static const std::map<std::string, std::string> mimeTypes = {
        {".txt", "text/plain"},
        {".pdf", "application/pdf"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".png", "image/png"},
        {".gif", "image/gif"},
        {".mp4", "video/mp4"},
        {".mp3", "audio/mpeg"},
        {".zip", "application/zip"},
        {".json", "application/json"},
        {".xml", "application/xml"},
        {".html", "text/html"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".cpp", "text/x-c++src"},
        {".h", "text/x-c++hdr"},
        {".py", "text/x-python"},
        {".doc", "application/msword"},
        {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {".xls", "application/vnd.ms-excel"},
        {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
    };
    
    std::string ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    auto it = mimeTypes.find(ext);
    if (it != mimeTypes.end()) {
        return it->second;
    }
    return "application/octet-stream";
}

bool FileOperations::secureDelete(const std::filesystem::path& path) {
    try {
        if (!fileExists(path)) {
            return false;
        }
        
        uint64_t size = getFileSize(path);
        if (size == 0) {
            return deleteFile(path);
        }
        
        // Overwrite file with random data
        std::ofstream file(path, std::ios::binary | std::ios::in | std::ios::out);
        if (!file.is_open()) {
            return false;
        }
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        const size_t bufferSize = 4096;
        std::vector<uint8_t> buffer(bufferSize);
        
        for (uint64_t written = 0; written < size; written += bufferSize) {
            size_t toWrite = std::min(bufferSize, static_cast<size_t>(size - written));
            for (size_t i = 0; i < toWrite; ++i) {
                buffer[i] = static_cast<uint8_t>(dis(gen));
            }
            file.write(reinterpret_cast<const char*>(buffer.data()), toWrite);
        }
        
        file.close();
        
        // Now delete the file
        return deleteFile(path);
    } catch (...) {
        return false;
    }
}

} // namespace securebox
