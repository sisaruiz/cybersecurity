#include "handshake.h"

#include <stddef.h>

static EVP_PKEY *hs_new_x25519_private(const uint8_t priv[HS_ECDH_KEY_LEN])
{
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, HS_ECDH_KEY_LEN);
}

static EVP_PKEY *hs_new_x25519_public(const uint8_t pub[HS_ECDH_KEY_LEN])
{
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, HS_ECDH_KEY_LEN);
}

int hs_generate_ecdh_keypair(uint8_t priv_out[HS_ECDH_KEY_LEN],
                             uint8_t pub_out[HS_ECDH_KEY_LEN])
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey;
    size_t out_len;
    int ok;

    if (priv_out == NULL || pub_out == NULL) {
        return -1;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (ctx == NULL) {
        return -1;
    }

    pkey = NULL;
    ok = EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &pkey) == 1;
    if (!ok) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    out_len = HS_ECDH_KEY_LEN;
    if (EVP_PKEY_get_raw_private_key(pkey, priv_out, &out_len) != 1 || out_len != HS_ECDH_KEY_LEN) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    out_len = HS_ECDH_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub_out, &out_len) != 1 || out_len != HS_ECDH_KEY_LEN) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int hs_derive_shared_secret(const uint8_t local_priv[HS_ECDH_KEY_LEN],
                            const uint8_t peer_pub[HS_ECDH_KEY_LEN],
                            uint8_t shared_secret_out[HS_ECDH_KEY_LEN])
{
    EVP_PKEY *local_key;
    EVP_PKEY *peer_key;
    EVP_PKEY_CTX *ctx;
    size_t secret_len;

    if (local_priv == NULL || peer_pub == NULL || shared_secret_out == NULL) {
        return -1;
    }

    local_key = hs_new_x25519_private(local_priv);
    peer_key = hs_new_x25519_public(peer_pub);
    if (local_key == NULL || peer_key == NULL) {
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    ctx = EVP_PKEY_CTX_new(local_key, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) != 1 || EVP_PKEY_derive_set_peer(ctx, peer_key) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    secret_len = HS_ECDH_KEY_LEN;
    if (EVP_PKEY_derive(ctx, shared_secret_out, &secret_len) != 1 || secret_len != HS_ECDH_KEY_LEN) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(local_key);
    EVP_PKEY_free(peer_key);
    return 0;
}

int hs_sign_server_ephemeral(const uint8_t server_sign_priv[HS_SIGN_KEY_LEN],
                             const uint8_t server_eph_pub[HS_ECDH_KEY_LEN],
                             uint8_t signature_out[HS_SIG_LEN])
{
    EVP_MD_CTX *mdctx;
    EVP_PKEY *sign_key;
    size_t sig_len;

    if (server_sign_priv == NULL || server_eph_pub == NULL || signature_out == NULL) {
        return -1;
    }

    sign_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, server_sign_priv, HS_SIGN_KEY_LEN);
    if (sign_key == NULL) {
        return -1;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        EVP_PKEY_free(sign_key);
        return -1;
    }

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sign_key) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(sign_key);
        return -1;
    }

    sig_len = HS_SIG_LEN;
    if (EVP_DigestSign(mdctx, signature_out, &sig_len, server_eph_pub, HS_ECDH_KEY_LEN) != 1 ||
        sig_len != HS_SIG_LEN) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(sign_key);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(sign_key);
    return 0;
}

int hs_verify_server_ephemeral(const uint8_t server_sign_pub[HS_SIGN_KEY_LEN],
                               const uint8_t server_eph_pub[HS_ECDH_KEY_LEN],
                               const uint8_t signature[HS_SIG_LEN])
{
    EVP_MD_CTX *mdctx;
    EVP_PKEY *verify_key;

    if (server_sign_pub == NULL || server_eph_pub == NULL || signature == NULL) {
        return -1;
    }

    verify_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, server_sign_pub, HS_SIGN_KEY_LEN);
    if (verify_key == NULL) {
        return -1;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        EVP_PKEY_free(verify_key);
        return -1;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, verify_key) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(verify_key);
        return -1;
    }

    if (EVP_DigestVerify(mdctx, signature, HS_SIG_LEN, server_eph_pub, HS_ECDH_KEY_LEN) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(verify_key);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(verify_key);
    return 0;
}
