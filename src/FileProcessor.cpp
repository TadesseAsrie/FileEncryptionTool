#include "CryptoCore.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <fmt/format.h>

namespace crypto::io {

class ProgressTracker {
public:
    explicit ProgressTracker(uint64_t total_bytes) : m_total_bytes(total_bytes) {}
    void update(uint64_t bytes_processed) {
        m_processed_bytes += bytes_processed;
        float percent = (static_cast<float>(m_processed_bytes) / m_total_bytes) * 100.0f;
        fmt::print("\r[PROGRESS] {:.2f}% ({}/{} bytes)", percent, m_processed_bytes.load(), m_total_bytes);
        std::cout.flush();
    }
    void finish() { fmt::print("\n[COMPLETE] Operation finished.\n"); }
private:
    uint64_t m_total_bytes;
    std::atomic<uint64_t> m_processed_bytes{0};
};

class FileIOManager {
public:
    static std::expected<void, std::error_code> encrypt_file(
        const std::filesystem::path& in_path,
        const std::filesystem::path& out_path,
        std::string_view password,
        std::string_view algorithm = "AES-256-GCM"
    ) {
        if (!std::filesystem::exists(in_path)) return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
        uint64_t file_size = std::filesystem::file_size(in_path);

        std::ifstream fin(in_path, std::ios::binary);
        std::ofstream fout(out_path, std::ios::binary);
        if (!fin || !fout) return std::unexpected(std::make_error_code(std::errc::io_error));

        SecureBuffer salt = KeyGenerator::generate_salt(16);
        SecureBuffer iv = KeyGenerator::generate_iv(12);
        SecureBuffer key = PasswordManager::derive_key_pbkdf2(password, salt.as_span(), 600000, 32);

        CryptoFileHeader header;
        header.algorithm_id = (algorithm == "AES-256-CBC") ? 2 : (algorithm == "ChaCha20-Poly1305" ? 3 : 1);
        header.pbkdf2_iterations = 600000;
        std::memcpy(header.salt, salt.data(), 16);
        std::memcpy(header.iv, iv.data(), 12);

        fout.write(reinterpret_cast<const char*>(&header), sizeof(CryptoFileHeader));

        auto provider = CryptoEngine::instance().create_provider(algorithm);
        ProgressTracker progress(file_size);
        std::size_t chunk_size = 4 * 1024 * 1024; // 4MB Chunk
        SecureBuffer buffer(chunk_size);

        while (fin) {
            fin.read(reinterpret_cast<char*>(buffer.data()), chunk_size);
            std::streamsize bytes_read = fin.gcount();
            if (bytes_read <= 0) break;

            SecureBuffer tag;
            auto cipher_res = provider->encrypt_chunk(std::span<const std::byte>(buffer.data(), bytes_read), key.as_span(), iv.as_span(), tag);
            if (!cipher_res) return std::unexpected(cipher_res.error());

            uint32_t chunk_len = static_cast<uint32_t>(cipher_res->size());
            fout.write(reinterpret_cast<const char*>(&chunk_len), sizeof(chunk_len));
            fout.write(reinterpret_cast<const char*>(tag.data()), tag.size());
            fout.write(reinterpret_cast<const char*>(cipher_res->data()), cipher_res->size());

            progress.update(bytes_read);
        }
        progress.finish();
        return {};
    }

    static std::expected<void, std::error_code> decrypt_file(
        const std::filesystem::path& in_path,
        const std::filesystem::path& out_path,
        std::string_view password
    ) {
        if (!std::filesystem::exists(in_path)) return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
        uint64_t file_size = std::filesystem::file_size(in_path);

        std::ifstream fin(in_path, std::ios::binary);
        std::ofstream fout(out_path, std::ios::binary);
        if (!fin || !fout) return std::unexpected(std::make_error_code(std::errc::io_error));

        CryptoFileHeader header;
        fin.read(reinterpret_cast<char*>(&header), sizeof(CryptoFileHeader));
        if (std::strncmp(header.magic, "FET1", 4) != 0) return std::unexpected(std::make_error_code(std::errc::executable_format_error));

        std::string algorithm = (header.algorithm_id == 2) ? "AES-256-CBC" : ((header.algorithm_id == 3) ? "ChaCha20-Poly1305" : "AES-256-GCM");
        SecureBuffer salt(reinterpret_cast<const std::byte*>(header.salt), 16);
        SecureBuffer iv(reinterpret_cast<const std::byte*>(header.iv), 12);
        SecureBuffer key = PasswordManager::derive_key_pbkdf2(password, salt.as_span(), header.pbkdf2_iterations, 32);

        auto provider = CryptoEngine::instance().create_provider(algorithm);
        ProgressTracker progress(file_size);

        while (fin.peek() != EOF) {
            uint32_t chunk_len = 0;
            if (!fin.read(reinterpret_cast<char*>(&chunk_len), sizeof(chunk_len))) break;

            SecureBuffer tag(16);
            fin.read(reinterpret_cast<char*>(tag.data()), 16);

            SecureBuffer ciphertext(chunk_len);
            fin.read(reinterpret_cast<char*>(ciphertext.data()), chunk_len);

            auto plain_res = provider->decrypt_chunk(ciphertext.as_span(), key.as_span(), iv.as_span(), tag.as_span());
            if (!plain_res) return std::unexpected(plain_res.error());

            fout.write(reinterpret_cast<const char*>(plain_res->data()), plain_res->size());
            progress.update(chunk_len);
        }
        progress.finish();
        return {};
    }

    static void secure_overwrite_and_delete(const std::filesystem::path& path) {
        if (!std::filesystem::exists(path)) return;
        uint64_t size = std::filesystem::file_size(path);
        std::ofstream fout(path, std::ios::binary | std::ios::in);
        std::vector<char> zeros(64 * 1024, 0);
        uint64_t written = 0;
        while (written < size) {
            uint64_t chunk = std::min(size - written, static_cast<uint64_t>(zeros.size()));
            fout.write(zeros.data(), chunk);
            written += chunk;
        }
        fout.close();
        std::filesystem::remove(path);
    }
};

class FolderProcessor {
public:
    static void process_folder(const std::filesystem::path& dir, std::string_view password, bool encrypt) {
        std::vector<std::filesystem::path> files;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
            if (entry.is_regular_file()) {
                files.push_back(entry.path());
            }
        }

        fmt::print("Found {} files for folder processing.\n", files.size());
        for (const auto& f : files) {
            if (encrypt && f.extension() != ".enc") {
                auto out = f; out += ".enc";
                fmt::print("Encrypting: {}\n", f.string());
                FileIOManager::encrypt_file(f, out, password);
            } else if (!encrypt && f.extension() == ".enc") {
                auto out = f; out.replace_extension("");
                fmt::print("Decrypting: {}\n", f.string());
                FileIOManager::decrypt_file(f, out, password);
            }
        }
    }
};

} // namespace crypto::io