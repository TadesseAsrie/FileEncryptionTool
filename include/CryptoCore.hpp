#ifndef CRYPTO_CORE_HPP
#define CRYPTO_CORE_HPP

#include <cstddef>
#include <vector>
#include <span >
#include <string>
#include <string_view>
#include <memory>
#include <expected>
#include <system_error>
#include <filesystem>
#include <functional>
#include <atomic>
#include <shared_mutex>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace crypto {

// ==========================================
// 1. Core Secure Memory
// ==========================================
template <typename T>
struct SecureAllocator {
    using value_type = T;
    SecureAllocator() noexcept = default;
    template <typename U> constexpr SecureAllocator(const SecureAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t n) {
        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) throw std::bad_alloc();
        T* p = static_cast<T*>(::operator new(n * sizeof(T)));
        if (!p) throw std::bad_alloc();
        return p;
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p) {
            OPENSSL_cleanse(static_cast<void*>(p), n * sizeof(T));
            ::operator delete(static_cast<void*>(p));
        }
    }
    template <typename U> bool operator==(const SecureAllocator<U>&) const noexcept { return true; }
    template <typename U> bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

class SecureBuffer {
public:
    using container_type = std::vector<std::byte, SecureAllocator<std::byte>>;
    using size_type = container_type::size_type;

    SecureBuffer() noexcept = default;
    explicit SecureBuffer(size_type size);
    SecureBuffer(const std::byte* data, size_type count);
    SecureBuffer(std::span<const std::byte> data);
    SecureBuffer(std::string_view str);
    ~SecureBuffer() noexcept;

    SecureBuffer(const SecureBuffer& other);
    SecureBuffer& operator=(const SecureBuffer& other);
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    [[nodiscard]] std::byte* data() noexcept;
    [[nodiscard]] const std::byte* data() const noexcept;
    [[nodiscard]] unsigned char* unsigned_data() noexcept;
    [[nodiscard]] const unsigned char* unsigned_data() const noexcept;
    [[nodiscard]] size_type size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

    void resize(size_type new_size);
    void wipe() noexcept;
    [[nodiscard]] std::span<std::byte> as_span() noexcept;
    [[nodiscard]] std::span<const std::byte> as_span() const noexcept;
    [[nodiscard]] std::string_view as_string_view() const noexcept;
    void append(std::span<const std::byte> data);
    [[nodiscard]] bool constant_time_equals(const SecureBuffer& other) const noexcept;

private:
    container_type m_buffer;
};

// ==========================================
// 2. Logging & Configuration
// ==========================================
enum class LogLevel { Trace, Debug, Info, Warn, Error, Critical };

class Logger {
public:
    static void initialize(const std::filesystem::path& log_file = "logs/app.log", LogLevel level = LogLevel::Info);
    static void set_level(LogLevel level) noexcept;
    static std::shared_ptr<spdlog::logger> get() noexcept;
    static void shutdown() noexcept;
private:
    static inline std::shared_ptr<spdlog::logger> s_logger{nullptr};
};

enum class OverwritePolicy { Overwrite, Skip, Fail };

struct Configuration {
    std::string default_algorithm{"AES-256-GCM"};
    bool enable_compression{false};
    OverwritePolicy overwrite_policy{OverwritePolicy::Fail};
    std::string log_level{"info"};
    std::filesystem::path output_folder{"./output"};
    std::size_t chunk_size_bytes{4 * 1024 * 1024}; // 4MB Chunks
    std::size_t pbkdf2_iterations{600000};
    bool secure_delete_source{false};
    std::size_t thread_pool_size{4};

    [[nodiscard]] bool validate() const noexcept;
};

void to_json(nlohmann::json& j, const Configuration& config);
void from_json(const nlohmann::json& j, Configuration& config);

class SettingsManager {
public:
    static SettingsManager& instance() noexcept;
    std::expected<void, std::error_code> load_from_file(const std::filesystem::path& path);
    std::expected<void, std::error_code> save_to_file(const std::filesystem::path& path) const;
    [[nodiscard]] Configuration get_config() const;
    void update_config(const Configuration& config);
private:
    SettingsManager() = default;
    mutable std::shared_mutex m_mutex;
    Configuration m_config;
};

// ==========================================
// 3. Cryptographic Primitives & Key Management
// ==========================================
class KeyGenerator {
public:
    static SecureBuffer generate_random_bytes(std::size_t length);
    static SecureBuffer generate_symmetric_key(std::size_t key_bits = 256);
    static SecureBuffer generate_iv(std::size_t iv_bytes = 12);
    static SecureBuffer generate_salt(std::size_t salt_bytes = 16);
};

class PasswordManager {
public:
    static std::expected<void, std::error_code> validate_password_strength(std::string_view password);
    static SecureBuffer derive_key_pbkdf2(
        std::string_view password,
        std::span<const std::byte> salt,
        std::size_t iterations,
        std::size_t key_length_bytes,
        bool use_sha512 = false
    );
};

class HashManager {
public:
    static SecureBuffer compute_sha256(std::span<const std::byte> data);
    static SecureBuffer compute_sha512(std::span<const std::byte> data);
    static SecureBuffer compute_hmac_sha256(std::span<const std::byte> key, std::span<const std::byte> data);
};

// Header struct written to encrypted files
#pragma pack(push, 1)
struct CryptoFileHeader {
    char magic[4] = {'F', 'E', 'T', '1'};
    uint8_t algorithm_id; // 1: AES-256-GCM, 2: AES-256-CBC, 3: ChaCha20-Poly1305
    uint8_t flags;        // bit 0: compressed, bit 1: hybrid encrypted
    uint32_t pbkdf2_iterations;
    uint8_t salt[16];
    uint8_t iv[12];
    uint8_t auth_tag[16]; // For AEAD modes
};
#pragma pack(pop)

class ICryptoProvider {
public:
    virtual ~ICryptoProvider() = default;
    [[nodiscard]] virtual std::string_view get_name() const noexcept = 0;
    virtual std::expected<SecureBuffer, std::error_code> encrypt_chunk(
        std::span<const std::byte> plaintext,
        std::span<const std::byte> key,
        std::span<const std::byte> iv,
        SecureBuffer& out_tag
    ) = 0;
    virtual std::expected<SecureBuffer, std::error_code> decrypt_chunk(
        std::span<const std::byte> ciphertext,
        std::span<const std::byte> key,
        std::span<const std::byte> iv,
        std::span<const std::byte> tag
    ) = 0;
};

class AESGCMProvider final : public ICryptoProvider {
public:
    std::string_view get_name() const noexcept override { return "AES-256-GCM"; }
    std::expected<SecureBuffer, std::error_code> encrypt_chunk(
        std::span<const std::byte> plaintext, std::span<const std::byte> key,
        std::span<const std::byte> iv, SecureBuffer& out_tag) override;
    std::expected<SecureBuffer, std::error_code> decrypt_chunk(
        std::span<const std::byte> ciphertext, std::span<const std::byte> key,
        std::span<const std::byte> iv, std::span<const std::byte> tag) override;
};

class AESCBCProvider final : public ICryptoProvider {
public:
    std::string_view get_name() const noexcept override { return "AES-256-CBC"; }
    std::expected<SecureBuffer, std::error_code> encrypt_chunk(
        std::span<const std::byte> plaintext, std::span<const std::byte> key,
        std::span<const std::byte> iv, SecureBuffer& out_tag) override;
    std::expected<SecureBuffer, std::error_code> decrypt_chunk(
        std::span<const std::byte> ciphertext, std::span<const std::byte> key,
        std::span<const std::byte> iv, std::span<const std::byte> tag) override;
};

class ChaCha20Poly1305Provider final : public ICryptoProvider {
public:
    std::string_view get_name() const noexcept override { return "ChaCha20-Poly1305"; }
    std::expected<SecureBuffer, std::error_code> encrypt_chunk(
        std::span<const std::byte> plaintext, std::span<const std::byte> key,
        std::span<const std::byte> iv, SecureBuffer& out_tag) override;
    std::expected<SecureBuffer, std::error_code> decrypt_chunk(
        std::span<const std::byte> ciphertext, std::span<const std::byte> key,
        std::span<const std::byte> iv, std::span<const std::byte> tag) override;
};

class RSAProvider {
public:
    static std::expected<std::pair<std::string, std::string>, std::error_code> generate_keypair(int bits = 4096);
    static std::expected<SecureBuffer, std::error_code> encrypt(std::span<const std::byte> plaintext, std::string_view public_key_pem);
    static std::expected<SecureBuffer, std::error_code> decrypt(std::span<const std::byte> ciphertext, std::string_view private_key_pem);
    static std::expected<SecureBuffer, std::error_code> sign(std::span<const std::byte> data, std::string_view private_key_pem);
    static bool verify(std::span<const std::byte> data, std::span<const std::byte> signature, std::string_view public_key_pem);
};

class CryptoEngine {
public:
    static CryptoEngine& instance() noexcept;
    std::unique_ptr<ICryptoProvider> create_provider(std::string_view algorithm_name);
private:
    CryptoEngine() = default;
};

} // namespace crypto

#endif // CRYPTO_CORE_HPP