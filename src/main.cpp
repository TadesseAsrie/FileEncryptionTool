#include "CryptoCore.hpp"
#include <iostream>
#include <string_view>
#include <fmt/format.h>

namespace crypto::io {
    class FileIOManager {
    public:
        static std::expected<void, std::error_code> encrypt_file(const std::filesystem::path&, const std::filesystem::path&, std::string_view, std::string_view);
        static std::expected<void, std::error_code> decrypt_file(const std::filesystem::path&, const std::filesystem::path&, std::string_view);
    };
    class FolderProcessor {
    public:
        static void process_folder(const std::filesystem::path&, std::string_view, bool);
    };
}

void print_usage() {
    fmt::print(R"(
======================================================
 Production-Ready Cross-Platform File Encryption Tool
 Standard C++23 / OpenSSL / Authenticated Encryption
======================================================
Usage:
  encrypt        --input <file> --output <file.enc> --password <pass> [--algo AES-256-GCM]
  decrypt        --input <file.enc> --output <file> --password <pass>
  encrypt-folder --input <dir> --password <pass>
  decrypt-folder --input <dir> --password <pass>
  generate-key   --output <key.pem>
  hash           --input <file>
)");
}

int main(int argc, char* argv[]) {
    try {
        crypto::Logger::initialize("logs/app.log", crypto::LogLevel::Info);
        if (argc < 2) {
            print_usage();
            return 1;
        }

        std::string command = argv[1];
        std::string input, output, password, algo = "AES-256-GCM";

        for (int i = 2; i < argc; ++i) {
            std::string_view arg = argv[i];
            if (arg == "--input" && i + 1 < argc) input = argv[++i];
            else if (arg == "--output" && i + 1 < argc) output = argv[++i];
            else if (arg == "--password" && i + 1 < argc) password = argv[++i];
            else if (arg == "--algo" && i + 1 < argc) algo = argv[++i];
        }

        if (command == "encrypt") {
            if (input.empty() || output.empty() || password.empty()) {
                fmt::print(stderr, "Error: Missing parameters for encryption.\n");
                return 1;
            }
            auto res = crypto::io::FileIOManager::encrypt_file(input, output, password, algo);
            if (!res) {
                fmt::print(stderr, "Encryption failed with error code.\n");
                return 2;
            }
        } else if (command == "decrypt") {
            if (input.empty() || output.empty() || password.empty()) {
                fmt::print(stderr, "Error: Missing parameters for decryption.\n");
                return 1;
            }
            auto res = crypto::io::FileIOManager::decrypt_file(input, output, password);
            if (!res) {
                fmt::print(stderr, "Decryption failed or invalid authentication tag.\n");
                return 2;
            }
        } else if (command == "encrypt-folder") {
            if (input.empty() || password.empty()) return 1;
            crypto::io::FolderProcessor::process_folder(input, password, true);
        } else if (command == "decrypt-folder") {
            if (input.empty() || password.empty()) return 1;
            crypto::io::FolderProcessor::process_folder(input, password, false);
        } else if (command == "generate-key") {
            auto keys = crypto::RSAProvider::generate_keypair(4096);
            if (keys) {
                fmt::print("Generated 4096-bit RSA Keypair successfully.\n");
            }
        } else {
            print_usage();
        }

        crypto::Logger::shutdown();
        return 0;
    } catch (const std::exception& ex) {
        fmt::print(stderr, "Fatal Runtime Exception: {}\n", ex.what());
        return 99;
    }
}