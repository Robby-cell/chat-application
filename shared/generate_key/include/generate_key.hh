#ifndef SHARED_GENERATE_KEY_HH
#define SHARED_GENERATE_KEY_HH

#include <array>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace key {

struct key_exception : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

struct key_iv {
  std::array<unsigned char, 32UZ> key;
  std::array<unsigned char, 16UZ> iv;
};

extern "C++" auto generate_key_iv() -> key_iv;

extern "C++" auto generate_dh_key() -> EVP_PKEY *;

extern "C++" auto derive_shared_secret(EVP_PKEY *local_key, EVP_PKEY *peer_key)
    -> std::vector<unsigned char>;

extern "C++" auto export_public_key(EVP_PKEY *key) -> std::string;

extern "C++" auto import_public_key(std::string_view pem_str) -> EVP_PKEY *;

} // namespace key

#endif // SHARED_GENERATE_KEY_HH
