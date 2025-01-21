#include "encryption.hh"
#include <memory>
#include <openssl/evp.h>

namespace encryption {

extern "C++" auto aes_encrypt(const std::vector<unsigned char> &key,
                              const std::vector<unsigned char> &iv,
                              const std::string &plaintext)
    -> std::vector<unsigned char> {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw encryption_exception("Failed to create EVP_CIPHER_CTX");
  }
  auto _evp_cipher_ctx_raii =
      std::unique_ptr<EVP_CIPHER_CTX, decltype([](auto ctx) {
                        EVP_CIPHER_CTX_free(ctx);
                      })>(ctx);

  // Initialize encryption
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key.data(),
                         iv.data()) != 1) {
    throw encryption_exception("Failed to initialize AES encryption");
  }

  // Encrypt the plaintext
  std::vector<unsigned char> ciphertext(
      plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_cfb()));
  int len = 0, ciphertext_len = 0;

  if (EVP_EncryptUpdate(
          ctx, ciphertext.data(), &len,
          reinterpret_cast<const unsigned char *>(plaintext.data()),
          plaintext.size()) != 1) {
    throw encryption_exception("Failed to encrypt data");
  }
  ciphertext_len = len;

  // Finalize encryption (for CFB, this may not add additional data)
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
    throw encryption_exception("Failed to finalize encryption");
  }
  ciphertext_len += len;

  ciphertext.resize(ciphertext_len);
  return ciphertext;
}

extern "C++" auto aes_decrypt(const std::vector<unsigned char> &key,
                              const std::vector<unsigned char> &iv,
                              const std::vector<unsigned char> &ciphertext)
    -> std::string {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw encryption_exception("Failed to create EVP_CIPHER_CTX");
  }

  // Initialize decryption
  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key.data(),
                         iv.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw encryption_exception("Failed to initialize AES decryption");
  }

  // Decrypt the ciphertext
  std::vector<unsigned char> plaintext(ciphertext.size());
  int len = 0, plaintext_len = 0;

  if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                        ciphertext.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw encryption_exception("Failed to decrypt data");
  }
  plaintext_len = len;

  // Finalize decryption (for CFB, this may not add additional data)
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw encryption_exception("Failed to finalize decryption");
  }
  plaintext_len += len;

  plaintext.resize(plaintext_len);
  EVP_CIPHER_CTX_free(ctx);
  return std::string(plaintext.begin(), plaintext.end());
}

} // namespace encryption
