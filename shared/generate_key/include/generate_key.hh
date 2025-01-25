#ifndef SHARED_GENERATE_KEY_HH
#define SHARED_GENERATE_KEY_HH

#include <array>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace key {

struct key_exception : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

struct key_iv {
  std::array<unsigned char, 32UZ> key;
  std::array<unsigned char, 16UZ> iv;
};

struct rsa_key_pair {
  std::string public_key;
  std::string private_key;
};

extern "C++" auto generate_key_iv() -> key_iv;

extern "C++" auto generate_dh_key() -> EVP_PKEY *;

extern "C++" auto derive_shared_secret(EVP_PKEY *local_key, EVP_PKEY *peer_key)
    -> std::vector<unsigned char>;

extern "C++" auto export_public_key(EVP_PKEY *key) -> std::string;

extern "C++" auto import_public_key(std::string_view pem_str) -> EVP_PKEY *;

extern "C++" auto generate_rsa_key_pair(int key_size_bits) -> rsa_key_pair;

} // namespace key

#endif // SHARED_GENERATE_KEY_HH
