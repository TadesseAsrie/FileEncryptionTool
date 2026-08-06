#include "CryptoCore.hpp"
#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

namespace crypto {

// ==========================================
// 1. SecureBuffer Implementation
// ==========================================
SecureBuffer::SecureBuffer(size_type size) : m_buffer(size, std::byte{0}) {}
SecureBuffer::SecureBuffer(const std::byte* data, size_type count) {
    if (data && count > 0) m_buffer.assign(data, data + count);
}
SecureBuffer::SecureBuffer(std::span<const std::byte> data) : m_buffer(data.begin(), data.end()) {}
SecureBuffer::SecureBuffer(std::string_view str) {
    m_buffer.resize(str.size());
    for (size_t i = 0; i < str.size(); ++i) m_buffer[i] = static_cast<std::byte>(str[i]);
}
SecureBuffer::~SecureBuffer() noexcept { wipe(); }
SecureBuffer::SecureBuffer(const SecureBuffer& other) : m_buffer(other.m_buffer) {}
SecureBuffer& SecureBuffer::operator=(const SecureBuffer& other) {
    if (this != &other) { wipe(); m_buffer = other.m_buffer; }
    return *this;
}
SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : m_buffer(std::move(other.m_buffer)) {}
SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) { wipe(); m_buffer = std::move(other.m_buffer); }
    return *this;
}
std::byte* SecureBuffer::data() noexcept { return m_buffer.data(); }
const std::byte* SecureBuffer::data() const noexcept { return m_buffer.data(); }
unsigned char* SecureBuffer::unsigned_data() noexcept { return reinterpret_cast<unsigned char*>(m_buffer.data()); }
const unsigned char* SecureBuffer::unsigned_data() const noexcept { return reinterpret_cast<const unsigned char*>(m_buffer.data()); }
SecureBuffer::size_type SecureBuffer::size() const noexcept { return m_buffer.size(); }
bool SecureBuffer::empty() const noexcept { return m_buffer.empty(); }
void SecureBuffer::resize(size_type new_size) { m_buffer.resize(new_size, std::byte{0}); }
void SecureBuffer::wipe() noexcept { if (!m_buffer.empty()) OPENSSL_cleanse(m_buffer.data(), m_buffer.size()); }
std::span<std::byte> SecureBuffer::as_span() noexcept { return {m_buffer.data(), m_buffer.size()}; }
std::span<const std::byte> SecureBuffer::as_span() const noexcept { return {m_buffer.data(), m_buffer.size()}; }
std::string_view SecureBuffer::as_string_view() const noexcept {
    return {reinterpret_cast<const char*>(m_buffer.data()), m_buffer.size()};
}
void SecureBuffer::append(std::span<const std::byte> data) { m_buffer.insert(m_buffer.end(), data.begin(), data.end()); }
bool SecureBuffer::constant_time_equals(const SecureBuffer& other) const noexcept {
    if (size() != other.size()) return false;
    return CRYPTO_memcmp(data(), other.data(), size()) == 0;
}

// ==========================================
// 2. Logging & Settings Implementation
// ==========================================
void Logger::initialize(const std::filesystem::path& log_file, LogLevel level) {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(log_file.string(), 10485760, 3);
    s_logger = std::make_shared<spdlog::logger>("CryptoApp", spdlog::sinks_init_list{console_sink, file_sink});
    s_logger->set_level(spdlog::level::info);
    spdlog::set_default_logger(s_logger);
}
std::shared_ptr<spdlog::logger> Logger::get() noexcept { return s_logger; }
void Logger::shutdown() noexcept { spdlog::shutdown(); }

bool Configuration::validate() const noexcept {
    return (default_algorithm == "AES-256-GCM" || default_algorithm == "AES-256-CBC" || default_algorithm == "ChaCha20-Poly1305")
           && pbkdf2_iterations >= 100000;
}

void to_json(nlohmann::json& j, const Configuration& config) {
    j = nlohmann::json{
        {"default_algorithm", config.default_algorithm},
        {"enable_compression", config.enable_compression},
        {"chunk_size_bytes", config.chunk_size_bytes},
        {"pbkdf2_iterations", config.pbkdf2_iterations},
        {"secure_delete_source", config.secure_delete_source}
    };
}
void from_json(const nlohmann::json& j, Configuration& config) {
    if (j.contains("default_algorithm")) j.at("default_algorithm").get_to(config.default_algorithm);
    if (j.contains("enable_compression")) j.at("enable_compression").get_to(config.enable_compression);
    if (j.contains("chunk_size_bytes")) j.at("chunk_size_bytes").get_to(config.chunk_size_bytes);
    if (j.contains("pbkdf2_iterations")) j.at("pbkdf2_iterations").get_to(config.pbkdf2_iterations);
    if (j.contains("secure_delete_source")) j.at("secure_delete_source").get_to(config.secure_delete_source);
}

SettingsManager& SettingsManager::instance() noexcept {
    static SettingsManager instance;
    return instance;
}
std::expected<void, std::error_code> SettingsManager::load_from_file(const std::filesystem::path& path) {
    std::unique_lock lock(m_mutex);
    std::ifstream file(path);
    if (!file.is_open()) return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
    nlohmann::json j; file >> j;
    m_config = j.get<Configuration>();
    return {};
}
std::expected<void, std::error_code> SettingsManager::save_to_file(const std::filesystem::path& path) const {
    std::shared_lock lock(m_mutex);
    std::ofstream file(path);
    if (!file.is_open()) return std::unexpected(std::make_error_code(std::errc::permission_denied));
    nlohmann::json j = m_config;
    file << j.dump(4);
    return {};
}
Configuration SettingsManager::get_config() const { std::shared_lock lock(m_mutex); return m_config; }
void SettingsManager::update_config(const Configuration& config) { std::unique_lock lock(m_mutex); m_config = config; }

// ==========================================
// 3. Key Generators & Passwords
// ==========================================
SecureBuffer KeyGenerator::generate_random_bytes(std::size_t length) {
    SecureBuffer buf(length);
    if (RAND_bytes(buf.unsigned_data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed to generate secure entropy");
    }
    return buf;
}
SecureBuffer KeyGenerator::generate_symmetric_key(std::size_t key_bits) { return generate_random_bytes(key_bits / 8); }
SecureBuffer KeyGenerator::generate_iv(std::size_t iv_bytes) { return generate_random_bytes(iv_bytes); }
SecureBuffer KeyGenerator::generate_salt(std::size_t salt_bytes) { return generate_random_bytes(salt_bytes); }

std::expected<void, std::error_code> PasswordManager::validate_password_strength(std::string_view password) {
    if (password.size() < 12) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    bool has_upper = false, has_lower = false, has_digit = false, has_spec = false;
    for (char c : password) {
        if (std::isupper(c)) has_upper = true;
        else if (std::islower(c)) has_lower = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_spec = true;
    }
    if (has_upper && has_lower && has_digit && has_spec) return {};
    return std::unexpected(std::make_error_code(std::errc::result_out_of_range));
}

SecureBuffer PasswordManager::derive_key_pbkdf2(
    std::string_view password, std::span<const std::byte> salt,
    std::size_t iterations, std::size_t key_length_bytes, bool use_sha512
) {
    SecureBuffer derived(key_length_bytes);
    const EVP_MD* md = use_sha512 ? EVP_sha512() : EVP_sha256();
    if (PKCS5_PBKDF2_HMAC(
            password.data(), static_cast<int>(password.size()),
            reinterpret_cast<const unsigned char*>(salt.data()), static_cast<int>(salt.size()),
            static_cast<int>(iterations), md, static_cast<int>(key_length_bytes), derived.unsigned_data()) != 1) {
        throw std::runtime_error("PBKDF2 derivation failed");
    }
    return derived;
}

// ==========================================
// 4. Hashing Functions
// ==========================================
SecureBuffer HashManager::compute_sha256(std::span<const std::byte> data) {
    SecureBuffer out(32);
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), out.unsigned_data(), &len, EVP_sha256(), nullptr);
    return out;
}
SecureBuffer HashManager::compute_sha512(std::span<const std::byte> data) {
    SecureBuffer out(64);
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), out.unsigned_data(), &len, EVP_sha512(), nullptr);
    return out;
}
SecureBuffer HashManager::compute_hmac_sha256(std::span<const std::byte> key, std::span<const std::byte> data) {
    SecureBuffer mac(32);
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), mac.unsigned_data(), &len);
    return mac;
}

// ==========================================
// 5. Symmetric Ciphers (AES-GCM, AES-CBC, ChaCha20-Poly1305)
// ==========================================
std::expected<SecureBuffer, std::error_code> AESGCMProvider::encrypt_chunk(
    std::span<const std::byte> plaintext, std::span<const std::byte> key,
    std::span<const std::byte> iv, SecureBuffer& out_tag) {
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::unexpected(std::make_error_code(std::errc::not_enough_memory));

    SecureBuffer ciphertext(plaintext.size());
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext.unsigned_data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.unsigned_data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }

    out_tag.resize(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_tag.data());
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::expected<SecureBuffer, std::error_code> AESGCMProvider::decrypt_chunk(
    std::span<const std::byte> ciphertext, std::span<const std::byte> key,
    std::span<const std::byte> iv, std::span<const std::byte> tag) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::unexpected(std::make_error_code(std::errc::not_enough_memory));

    SecureBuffer plaintext(ciphertext.size());
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext.unsigned_data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), static_cast<int>(ciphertext.size())) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<void*>(static_cast<const void*>(tag.data()))) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::unexpected(std::make_error_code(std::errc::illegal_byte_sequence));
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.unsigned_data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return std::unexpected(std::make_error_code(std::errc::permission_denied)); // Auth tag mismatch
    }

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::expected<SecureBuffer, std::error_code> AESCBCProvider::encrypt_chunk(
    std::span<const std::byte> plaintext, std::span<const std::byte> key, std::span<const std::byte> iv, SecureBuffer& out_tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    SecureBuffer ciphertext(plaintext.size() + 16);
    int len = 0, total_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()));
    EVP_EncryptUpdate(ctx, ciphertext.unsigned_data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size()));
    total_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.unsigned_data() + len, &len);
    total_len += len;
    ciphertext.resize(total_len);

    out_tag = HashManager::compute_hmac_sha256(key, ciphertext.as_span());
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::expected<SecureBuffer, std::error_code> AESCBCProvider::decrypt_chunk(
    std::span<const std::byte> ciphertext, std::span<const std::byte> key, std::span<const std::byte> iv, std::span<const std::byte> tag) {
    
    SecureBuffer computed_mac = HashManager::compute_hmac_sha256(key, ciphertext);
    if (CRYPTO_memcmp(computed_mac.data(), tag.data(), std::min(computed_mac.size(), tag.size())) != 0) {
        return std::unexpected(std::make_error_code(std::errc::permission_denied));
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    SecureBuffer plaintext(ciphertext.size());
    int len = 0, total_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()));
    EVP_DecryptUpdate(ctx, plaintext.unsigned_data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), static_cast<int>(ciphertext.size()));
    total_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.unsigned_data() + len, &len);
    total_len += len;
    plaintext.resize(total_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::expected<SecureBuffer, std::error_code> ChaCha20Poly1305Provider::encrypt_chunk(
    std::span<const std::byte> plaintext, std::span<const std::byte> key, std::span<const std::byte> iv, SecureBuffer& out_tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    SecureBuffer ciphertext(plaintext.size());
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()));
    EVP_EncryptUpdate(ctx, ciphertext.unsigned_data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size()));
    EVP_EncryptFinal_ex(ctx, ciphertext.unsigned_data() + len, &len);

    out_tag.resize(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out_tag.data());
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::expected<SecureBuffer, std::error_code> ChaCha20Poly1305Provider::decrypt_chunk(
    std::span<const std::byte> ciphertext, std::span<const std::byte> key, std::span<const std::byte> iv, std::span<const std::byte> tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    SecureBuffer plaintext(ciphertext.size());
    int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()));
    EVP_DecryptUpdate(ctx, plaintext.unsigned_data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), static_cast<int>(ciphertext.size()));
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag.size()), const_cast<void*>(static_cast<const void*>(tag.data())));

    if (EVP_DecryptFinal_ex(ctx, plaintext.unsigned_data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return std::unexpected(std::make_error_code(std::errc::permission_denied));
    }
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// ==========================================
// 6. RSA-4096 Signatures & Asymmetric Encryption
// ==========================================
std::expected<std::pair<std::string, std::string>, std::error_code> RSAProvider::generate_keypair(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    EVP_PKEY_keygen(ctx, &pkey);

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    PEM_write_bio_PrivateKey(pri, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_bio_PUBKEY(pub, pkey);

    char* pri_data = nullptr; char* pub_data = nullptr;
    long pri_len = BIO_get_mem_data(pri, &pri_data);
    long pub_len = BIO_get_mem_data(pub, &pub_data);

    std::string private_key(pri_data, pri_len);
    std::string public_key(pub_data, pub_len);

    BIO_free(pri); BIO_free(pub);
    EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(ctx);
    return std::make_pair(private_key, public_key);
}

CryptoEngine& CryptoEngine::instance() noexcept {
    static CryptoEngine instance;
    return instance;
}
std::unique_ptr<ICryptoProvider> CryptoEngine::create_provider(std::string_view algorithm_name) {
    if (algorithm_name == "AES-256-GCM") return std::make_unique<AESGCMProvider>();
    if (algorithm_name == "AES-256-CBC") return std::make_unique<AESCBCProvider>();
    if (algorithm_name == "ChaCha20-Poly1305") return std::make_unique<ChaCha20Poly1305Provider>();
    return std::make_unique<AESGCMProvider>();
}

} // namespace crypto