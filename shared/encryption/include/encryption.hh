#ifndef SHARED_ENCRYPTION_HH
#define SHARED_ENCRYPTION_HH

#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace encryption {

struct encryption_exception : std::runtime_error {
  using std::runtime_error::runtime_error;
};

extern "C++" auto aes_encrypt(std::span<const unsigned char, 32UZ> key,
                              std::span<const unsigned char, 16UZ> iv,
                              std::string_view plaintext)
    -> std::vector<unsigned char>;

extern "C++" auto aes_decrypt(std::span<const unsigned char, 32UZ> key,
                              std::span<const unsigned char, 16UZ> iv,
                              std::span<const unsigned char> ciphertext)
    -> std::string;

extern "C++" auto rsa_encrypt(std::string_view data,
                              std::span<const unsigned char> pub_key_view)
    -> std::vector<unsigned char>;

extern "C++" auto rsa_decrypt(std::span<unsigned char> encrypted_data,
                              std::span<const unsigned char> priv_key_view)
    -> std::string;

} // namespace encryption

#endif // SHARED_ENCRYPTION_HH
