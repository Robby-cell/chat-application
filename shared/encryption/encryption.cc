#include "encryption.hh"

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace encryption {

extern "C++" auto aes_encrypt(std::span<const unsigned char, 32UZ> key,
                              std::span<const unsigned char, 16UZ> iv,
                              std::string_view plaintext)
    -> std::vector<unsigned char> {
  std::vector<unsigned char> ciphertext(plaintext.length() + AES_BLOCK_SIZE);

  // Create AES context
  auto ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw encryption_exception("Failed to create AES context");
  }
  auto _evp_cipher_ctx_raii =
      std::unique_ptr<EVP_CIPHER_CTX, decltype([](auto ctx) {
                        EVP_CIPHER_CTX_free(ctx);
                      })>(ctx);

  // Initialize encryption
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(),
                              iv.data())) {
    throw encryption_exception("Failed to initialize encryption");
  }

  // Perform encryption
  int len = 0;
  if (1 != EVP_EncryptUpdate(
               ctx, ciphertext.data(), &len,
               reinterpret_cast<const unsigned char *>(plaintext.data()),
               plaintext.length())) {
    throw encryption_exception("Encryption failed");
  }

  // Finalize encryption
  int final_len = 0;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len)) {
    throw encryption_exception("Encryption finalization failed");
  }

  ciphertext.resize(len + final_len);
  return ciphertext;
}

extern "C++" auto aes_decrypt(std::span<const unsigned char, 32UZ> key,
                              std::span<const unsigned char, 16UZ> iv,
                              std::span<const unsigned char> ciphertext)
    -> std::string {
  std::vector<unsigned char> plaintext(ciphertext.size());

  // Create AES context
  auto ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw encryption_exception("Failed to create AES context");
  }
  auto _evp_cipher_ctx_raii =
      std::unique_ptr<EVP_CIPHER_CTX, decltype([](auto ctx) {
                        EVP_CIPHER_CTX_free(ctx);
                      })>(ctx);

  // Initialize decryption
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(),
                              iv.data())) {
    throw encryption_exception("Failed to initialize decryption");
  }

  // Perform decryption
  int len = 0;
  if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                             ciphertext.size())) {
    throw encryption_exception("Decryption failed");
  }

  // Finalize decryption
  int final_len = 0;
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len)) {
    throw encryption_exception("Decryption finalization failed");
  }

  // Resize the plaintext vector to remove padding bytes
  plaintext.resize(len + final_len);

  return std::string(reinterpret_cast<const char *>(plaintext.data()),
                     plaintext.size());
}

extern "C++" auto rsa_encrypt(std::string_view data,
                              std::span<const unsigned char> pub_key_view)
    -> std::vector<unsigned char> {
  BIO *bio = BIO_new_mem_buf(pub_key_view.data(), pub_key_view.size());
  EVP_PKEY *pub_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  if (!pub_key) {
    throw encryption_exception("Failed to read public key");
  }
  BIO_free(bio);

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
  if (!ctx) {
    throw encryption_exception("Failed to create EVP_PKEY_CTX for encryption");
  }

  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    throw encryption_exception("Failed to initialize encryption operation");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
    throw encryption_exception("Failed to set RSA_PKCS1_PADDING");
  }

  size_t required_len;
  if (EVP_PKEY_encrypt(ctx, nullptr, &required_len,
                       reinterpret_cast<const unsigned char *>(data.data()),
                       data.size()) <= 0) {
    throw encryption_exception(
        "Failed to determine required buffer size for encryption");
  }

  std::vector<unsigned char> encrypted_data(required_len);
  size_t outlen = required_len;

  if (EVP_PKEY_encrypt(ctx, encrypted_data.data(), &outlen,
                       reinterpret_cast<const unsigned char *>(data.data()),
                       data.size()) <= 0) {
    throw encryption_exception("RSA encryption failed");
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pub_key);

  return encrypted_data;
}

extern "C++" auto rsa_decrypt(std::span<unsigned char> encrypted_data,
                              std::span<const unsigned char> priv_key_view)
    -> std::string {
  BIO *bio = BIO_new_mem_buf(priv_key_view.data(), priv_key_view.size());
  EVP_PKEY *priv_key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  if (!priv_key) {
    throw encryption_exception("Failed to read private key");
  }
  BIO_free(bio);

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
  if (!ctx) {
    throw encryption_exception("Failed to create EVP_PKEY_CTX for decryption");
  }

  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    throw encryption_exception("Failed to initialize decryption operation");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
    throw encryption_exception("Failed to set RSA_PKCS1_PADDING");
  }

  size_t required_len;
  if (EVP_PKEY_decrypt(ctx, nullptr, &required_len, encrypted_data.data(),
                       encrypted_data.size()) <= 0) {
    throw encryption_exception(
        "Failed to determine required buffer size for decryption");
  }

  std::vector<unsigned char> decrypted_data(required_len);
  size_t outlen = required_len;

  if (EVP_PKEY_decrypt(ctx, decrypted_data.data(), &outlen,
                       encrypted_data.data(), encrypted_data.size()) <= 0) {
    throw encryption_exception("RSA decryption failed");
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(priv_key);

  return std::string(reinterpret_cast<const char *>(decrypted_data.data()),
                     outlen);
}

} // namespace encryption
