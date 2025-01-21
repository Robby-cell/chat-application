#ifndef SHARED_GENERATE_KEY_HH
#define SHARED_GENERATE_KEY_HH

#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace key {

struct key_exception : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

extern "C++" auto generate_dh_key() -> EVP_PKEY *;

extern "C++" auto derive_shared_secret(EVP_PKEY *local_key, EVP_PKEY *peer_key)
    -> std::vector<unsigned char>;

extern "C++" auto export_public_key(EVP_PKEY *key) -> std::string;

extern "C++" auto import_public_key(const std::string &pem_str) -> EVP_PKEY *;

} // namespace key

#endif // SHARED_GENERATE_KEY_HH
