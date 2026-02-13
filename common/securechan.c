#include "securechan.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static int sc_check_lengths(size_t aad_len, size_t text_len)
{
    if (aad_len > (size_t)INT_MAX) {
        return -1;
    }
    if (text_len > (size_t)INT_MAX) {
        return -1;
    }
    return 0;
}

int sc_aead_encrypt(const uint8_t key[32], const uint8_t iv[12],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *ct, uint8_t tag[16])
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int out_len;

    if (key == NULL || iv == NULL || tag == NULL) {
        return -1;
    }
    if ((pt_len > 0 && (pt == NULL || ct == NULL)) || (aad_len > 0 && aad == NULL)) {
        return -1;
    }
    if (sc_check_lengths(aad_len, pt_len) != 0) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    out_len = 0;

    /* Configure AES-256-GCM with caller-provided key and IV. */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Process additional authenticated data when supplied. */
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    /* Encrypt plaintext into caller-managed ciphertext buffer. */
    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        out_len += len;
    }

    if (EVP_EncryptFinal_ex(ctx, ct + out_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int sc_aead_decrypt(const uint8_t key[32], const uint8_t iv[12],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    const uint8_t tag[16],
                    uint8_t *pt_out)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int out_len;

    if (key == NULL || iv == NULL || tag == NULL) {
        return -1;
    }
    if ((ct_len > 0 && (ct == NULL || pt_out == NULL)) || (aad_len > 0 && aad == NULL)) {
        return -1;
    }
    if (sc_check_lengths(aad_len, ct_len) != 0) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    out_len = 0;

    /* Configure AES-256-GCM with caller-provided key and IV. */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Process additional authenticated data when supplied. */
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    /* Decrypt ciphertext into caller-managed plaintext buffer. */
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int)ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        out_len += len;
    }

    /* Require tag verification before reporting success. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, pt_out + out_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
