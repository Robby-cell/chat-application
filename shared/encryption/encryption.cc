#include "encryption.hh"

#include <openssl/aes.h>
#include <openssl/evp.h>

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
                              std::span<const unsigned char, 16UZ> &iv,
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

} // namespace encryption
