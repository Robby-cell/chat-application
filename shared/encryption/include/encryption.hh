#ifndef SHARED_ENCRYPTION_HH
#define SHARED_ENCRYPTION_HH

#include <openssl/evp.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace encryption {

struct encryption_exception : std::runtime_error {
  using std::runtime_error::runtime_error;
};

extern "C++" auto aes_encrypt(const std::vector<unsigned char> &key,
                              const std::vector<unsigned char> &iv,
                              const std::string &plaintext)
    -> std::vector<unsigned char>;

extern "C++" auto aes_decrypt(const std::vector<unsigned char> &key,
                              const std::vector<unsigned char> &iv,
                              const std::vector<unsigned char> &ciphertext)
    -> std::string;

} // namespace encryption

#endif // SHARED_ENCRYPTION_HH
