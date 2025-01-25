#include "generate_key.hh"

#include <cstddef>
#include <cstdio>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <memory>
#include <openssl/rsa.h>
#include <string_view>

namespace std {
template <class T, class Deleter>
unique_ptr(T *, const Deleter &) -> unique_ptr<T, Deleter>;
}

namespace key {

extern "C++" auto generate_key_iv() -> key_iv {
  key_iv keys;

  if (1 != RAND_bytes(keys.key.data(), keys.key.size()) ||
      1 != RAND_bytes(keys.iv.data(), keys.iv.size())) {
    throw key_exception("Failed to generate random bytes");
  }

  return keys;
}

extern "C++" auto generate_dh_key() -> EVP_PKEY * {
  DH *dh_params = DH_new();
  if (!dh_params) {
    throw key_exception("Failed to create DH parameters");
  }

  // Generate standard DH parameters (2048-bit MODP group)
  if (DH_generate_parameters_ex(dh_params, 2048, DH_GENERATOR_2, nullptr) !=
      1) {
    DH_free(dh_params);
    throw key_exception("Failed to generate DH parameters");
  }

  EVP_PKEY *dh_key = EVP_PKEY_new();
  if (!dh_key) {
    DH_free(dh_params);
    throw key_exception("Failed to create EVP_PKEY structure");
  }

  if (EVP_PKEY_assign_DH(dh_key, dh_params) != 1) {
    EVP_PKEY_free(dh_key);
    DH_free(dh_params);
    throw key_exception("Failed to assign DH parameters to EVP_PKEY");
  }

  return dh_key;
}

extern "C++" auto derive_shared_secret(EVP_PKEY *local_key, EVP_PKEY *peer_key)
    -> std::vector<unsigned char> {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local_key, nullptr);
  if (!ctx) {
    throw key_exception("Failed to create context for key derivation");
  }

  if (EVP_PKEY_derive_init(ctx) <= 0) {
    throw key_exception("Failed to initialize key derivation");
  }

  if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
    throw key_exception("Failed to set peer key for derivation");
  }

  size_t secret_len = 0;
  if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
    throw key_exception("Failed to determine shared secret size");
  }

  std::vector<unsigned char> shared_secret(secret_len);
  if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
    throw key_exception("Failed to derive shared secret");
  }

  EVP_PKEY_CTX_free(ctx);
  return shared_secret;
}

extern "C++" auto export_public_key(EVP_PKEY *key) -> std::string {
  BIO *bio = BIO_new(BIO_s_mem());
  std::unique_ptr _bio_raii{bio, [](auto bio) { BIO_free(bio); }};

  PEM_write_bio_PUBKEY(bio, key);

  char *pem_data;
  size_t pem_len = BIO_get_mem_data(bio, &pem_data);
  std::string pem_str(pem_data, pem_len);

  return pem_str;
}

extern "C++" auto import_public_key(std::string_view pem_str) -> EVP_PKEY * {
  BIO *bio = BIO_new_mem_buf(pem_str.data(), pem_str.size());
  EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  return key;
}

extern "C++" auto generate_rsa_key_pair(int key_size_bits) -> rsa_key_pair {
  auto ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!ctx) {
    throw key_exception("Failed to create EVP_PKEY_CTX");
  }
  auto _evp_pkey_ctx_raii =
      std::unique_ptr<EVP_PKEY_CTX,
                      decltype([](auto ctx) { EVP_PKEY_CTX_free(ctx); })>(ctx);

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    throw key_exception("Failed to initialize key generation");
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size_bits) <= 0) {
    throw key_exception("Failed to set key size");
  }

  EVP_PKEY *key;
  if (EVP_PKEY_keygen(ctx, &key) <= 0) {
    throw key_exception("Failed to generate RSA key pair");
  }
  auto _evp_pkey_raii =
      std::unique_ptr<EVP_PKEY, decltype([](auto key) { EVP_PKEY_free(key); })>(
          key);

  rsa_key_pair keys;
  keys.private_key.resize(key_size_bits / 8);
  keys.public_key.resize(key_size_bits / 8);

  auto mem_to_mapping_for_write = [](void *mem, std::size_t length) {
    return fmemopen(mem, length, "w+");
  };

  auto pub_key =
      mem_to_mapping_for_write(keys.public_key.data(), keys.public_key.size());
  if (!pub_key) {
    throw key_exception("Failed to open mem mapping for public key write");
  }
  PEM_write_PUBKEY(pub_key, key);
  fclose(pub_key);

  auto priv_key = mem_to_mapping_for_write(keys.private_key.data(),
                                           keys.private_key.size());
  if (!priv_key) {
    throw key_exception("Failed to open mem mapping for private key write");
  }
  PEM_write_PrivateKey(priv_key, key, nullptr, nullptr, 0, nullptr, nullptr);
  fclose(priv_key);

  return keys;
}

} // namespace key
