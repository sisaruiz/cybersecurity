#ifndef COMMON_SECURECHAN_H
#define COMMON_SECURECHAN_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#define GCM_KEY_LEN 32u
#define GCM_IV_LEN 12u
#define GCM_TAG_LEN 16u

typedef struct SecureChanKeys {
    uint8_t enc_key[GCM_KEY_LEN];
    uint8_t dec_key[GCM_KEY_LEN];
    uint8_t iv_salt[4];
} SecureChanKeys;

/*
 * Encrypt plaintext with AES-256-GCM.
 * Returns 0 on success and -1 on failure.
 */
int sc_aead_encrypt(const uint8_t key[32], const uint8_t iv[12],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *ct, uint8_t tag[16]);

/*
 * Decrypt ciphertext with AES-256-GCM and verify authentication tag.
 * Returns 0 on success and -1 on failure.
 */
int sc_aead_decrypt(const uint8_t key[32], const uint8_t iv[12],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    const uint8_t tag[16],
                    uint8_t *pt_out);

#endif /* COMMON_SECURECHAN_H */
