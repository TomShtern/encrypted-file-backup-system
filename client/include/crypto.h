#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>

#ifdef HAVE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/aes.h>
#endif

/**
 * Cryptographic operations for RSA and AES encryption
 */
class Crypto {
public:
#ifdef HAVE_OPENSSL
    // RSA operations
    static bool generate_rsa_keypair(RSA** keypair, int key_length = 1024);
    static std::vector<unsigned char> rsa_encrypt(const std::vector<unsigned char>& data, RSA* public_key);
    static std::vector<unsigned char> rsa_decrypt(const std::vector<unsigned char>& encrypted_data, RSA* private_key);
    
    // AES operations
    static std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& data, 
                                                  const std::vector<unsigned char>& key,
                                                  const std::vector<unsigned char>& init_vector);
    static std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& encrypted_data,
                                                  const std::vector<unsigned char>& key,
                                                  const std::vector<unsigned char>& init_vector);
#else
    // Placeholder methods when OpenSSL is not available
    static bool generate_rsa_keypair(void** keypair, int key_length = 1024);
    static std::vector<unsigned char> rsa_encrypt(const std::vector<unsigned char>& data, void* public_key);
    static std::vector<unsigned char> rsa_decrypt(const std::vector<unsigned char>& encrypted_data, void* private_key);
    
    static std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& data, 
                                                  const std::vector<unsigned char>& key,
                                                  const std::vector<unsigned char>& init_vector);
    static std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& encrypted_data,
                                                  const std::vector<unsigned char>& key,
                                                  const std::vector<unsigned char>& init_vector);
#endif
    
    // Utility functions
    static std::vector<unsigned char> generate_random_bytes(int length);
    static std::string bytes_to_hex(const std::vector<unsigned char>& bytes);
    static std::vector<unsigned char> hex_to_bytes(const std::string& hex);
};

#endif // CRYPTO_H
