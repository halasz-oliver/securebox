#include "vault.h"
#include "crypto.h"
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <termios.h>
#include <unistd.h>

using namespace securebox;

// Helper function to read password without echoing
std::string readPassword(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    
    // Disable echo
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::string password;
    std::getline(std::cin, password);
    
    // Re-enable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    
    return password;
}

// Format file size for display
std::string formatSize(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return ss.str();
}

// Format time for display
std::string formatTime(const std::chrono::system_clock::time_point& time) {
    std::time_t tt = std::chrono::system_clock::to_time_t(time);
    std::tm tm = *std::localtime(&tt);
    
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void printUsage(const char* programName) {
    std::cout << "SecureBox - Encrypted File Vault\n\n";
    std::cout << "Usage:\n";
    std::cout << "  " << programName << " init <vault_path>\n";
    std::cout << "      Initialize a new vault\n\n";
    std::cout << "  " << programName << " add <vault_path> <file_path>\n";
    std::cout << "      Add a file to the vault\n\n";
    std::cout << "  " << programName << " list <vault_path>\n";
    std::cout << "      List all files in the vault\n\n";
    std::cout << "  " << programName << " extract <vault_path> <file_id> <output_path>\n";
    std::cout << "      Extract a file from the vault\n\n";
    std::cout << "  " << programName << " remove <vault_path> <file_id>\n";
    std::cout << "      Remove a file from the vault\n\n";
    std::cout << "  " << programName << " info <vault_path>\n";
    std::cout << "      Show vault information\n\n";
    std::cout << "  " << programName << " verify <vault_path>\n";
    std::cout << "      Verify vault integrity\n\n";
    std::cout << "  " << programName << " change-password <vault_path>\n";
    std::cout << "      Change vault password\n\n";
}

int cmdInit(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Error: Missing vault path\n";
        return 1;
    }
    
    std::string vaultPath = argv[2];
    
    std::string password = readPassword("Enter vault password: ");
    if (password.empty()) {
        std::cerr << "Error: Password cannot be empty\n";
        return 1;
    }
    
    std::string confirmPassword = readPassword("Confirm password: ");
    if (password != confirmPassword) {
        std::cerr << "Error: Passwords do not match\n";
        return 1;
    }
    
    if (!Vault::create(vaultPath, password)) {
        return 1;
    }
    
    return 0;
}

int cmdAdd(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Error: Missing vault path or file path\n";
        return 1;
    }
    
    std::string vaultPath = argv[2];
    std::string filePath = argv[3];
    
    std::string password = readPassword("Enter vault password: ");
    
    auto vault = Vault::open(vaultPath, password);
    if (!vault) {
        return 1;
    }
    
    std::string fileId = vault->addFile(filePath);
    if (fileId.empty()) {
        return 1;
    }
    
    vault->close();
    return 0;
}

int cmdList(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Error: Missing vault path\n";
        return 1;
    }
    
    std::string vaultPath = argv[2];
    std::string password = readPassword("Enter vault password: ");
    
    auto vault = Vault::open(vaultPath, password);
    if (!vault) {
        return 1;
    }
    
    const auto& files = vault->listFiles();
    
    if (files.empty()) {
        std::cout << "Vault is empty\n";
    } else {
        std::cout << "\nFiles in vault (" << files.size() << " total):\n";
        std::cout << std::string(80, '-') << "\n";
        
        for (const auto& [fileId, metadata] : files) {
            std::cout << "File ID: " << fileId.substr(0, 16) << "...\n";
            std::cout << "  Name: " << metadata.originalName << "\n";
            std::cout << "  Size: " << formatSize(metadata.originalSize) 
                     << " (encrypted: " << formatSize(metadata.encryptedSize) << ")\n";
            std::cout << "  Type: " << metadata.mimeType << "\n";
            std::cout << "  Added: " << formatTime(metadata.addedTime) << "\n";
            std::cout << "\n";
        }
    }
    
    vault->close();
    return 0;
}

int cmdExtract(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Error: Missing vault path, file ID, or output path\n";
        return 1;
    }
    
    std::string vaultPath = argv[2];
    std::string fileId = argv[3];
    std::string outputPath = argv[4];
    
    std::string password = readPassword("Enter vault password: ");
    
    auto vault = Vault::open(vaultPath, password);
    if (!vault) {
        return 1;
    }
    
    if (!vault->extractFile(fileId, outputPath)) {
        return 1;
    }
    
    vault->close();
    return 0;
}

int cmdRemove(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Error: Missing vault path or file ID\n";
        return 1;
    }
    
    std::string vaultPath = argv[2];
    std::string fileId = argv[3];
    
    std::string password = readPassword("Enter vault password: ");
    
    auto vault = Vault::open(vaultPath, password);
    if (!vault) {
        return 1;
    }
    
    std::cout << "Are you sure you want to remove this file? (yes/no): ";
    std::string confirm;
    std::getline(std::cin, confirm);
    
    if (confirm != "yes") {
        std::cout << "Operation cancelled\n";
        return 0;
    }
    
    if (!vault->removeFile(fileId)) {
        return 1;
    }
    
    vault->close();
    return 0;
}

int cmdInfo(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Error: Missing vault path\n";
        return 1;
    }
    
    std::string vaultPath = argv[2];
    std::string password = readPassword("Enter vault password: ");
    
    auto vault = Vault::open(vaultPath, password);
    if (!vault) {
        return 1;
    }
    
    const auto& config = vault->getConfig();
    
    std::cout << "\nVault Information:\n";
    std::cout << std::string(80, '=') << "\n";
    std::cout << "Vault ID: " << config.vaultId << "\n";
    std::cout << "Version: " << config.version << "\n";
    std::cout << "Created: " << formatTime(config.createdTime) << "\n";
    std::cout << "Last Modified: " << formatTime(config.lastModified) << "\n";
    std::cout << "Total Files: " << config.totalFiles << "\n";
    std::cout << "Total Size: " << formatSize(config.totalSize) << "\n";
    std::cout << std::string(80, '=') << "\n";
    
    vault->close();
    return 0;
}

int cmdVerify(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Error: Missing vault path\n";
        return 1;
    }
    
    std::string vaultPath = argv[2];
    std::string password = readPassword("Enter vault password: ");
    
    auto vault = Vault::open(vaultPath, password);
    if (!vault) {
        return 1;
    }
    
    bool valid = vault->verifyIntegrity();
    
    vault->close();
    return valid ? 0 : 1;
}

int cmdChangePassword(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Error: Missing vault path\n";
        return 1;
    }
    
    std::string vaultPath = argv[2];
    std::string oldPassword = readPassword("Enter current password: ");
    
    auto vault = Vault::open(vaultPath, oldPassword);
    if (!vault) {
        return 1;
    }
    
    std::string newPassword = readPassword("Enter new password: ");
    if (newPassword.empty()) {
        std::cerr << "Error: Password cannot be empty\n";
        return 1;
    }
    
    std::string confirmPassword = readPassword("Confirm new password: ");
    if (newPassword != confirmPassword) {
        std::cerr << "Error: Passwords do not match\n";
        return 1;
    }
    
    if (!vault->changePassword(oldPassword, newPassword)) {
        return 1;
    }
    
    vault->close();
    return 0;
}

int main(int argc, char* argv[]) {
    // Initialize libsodium
    if (!Crypto::initialize()) {
        std::cerr << "Error: Failed to initialize cryptographic library\n";
        return 1;
    }
    
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    try {
        if (command == "init") {
            return cmdInit(argc, argv);
        } else if (command == "add") {
            return cmdAdd(argc, argv);
        } else if (command == "list") {
            return cmdList(argc, argv);
        } else if (command == "extract") {
            return cmdExtract(argc, argv);
        } else if (command == "remove") {
            return cmdRemove(argc, argv);
        } else if (command == "info") {
            return cmdInfo(argc, argv);
        } else if (command == "verify") {
            return cmdVerify(argc, argv);
        } else if (command == "change-password") {
            return cmdChangePassword(argc, argv);
        } else {
            std::cerr << "Error: Unknown command '" << command << "'\n\n";
            printUsage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
