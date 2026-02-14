#include "handshake.h"

#include "net.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#else
#include <openssl/hmac.h>
#endif
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HS_FRAME_HEADER_LEN 5u
#define HS_LABEL_C2S "c2s"
#define HS_LABEL_S2C "s2c"

static int hs_send_frame(int fd, uint8_t type, const uint8_t *payload, size_t payload_len)
{
    uint8_t header[HS_FRAME_HEADER_LEN];
    uint32_t len_be;

    if (fd < 0 || (payload == NULL && payload_len > 0) || payload_len > UINT32_MAX) {
        return -1;
    }

    /* Frame format: type (1), length (4, big-endian), then payload bytes. */
    header[0] = type;
    len_be = htonl((uint32_t)payload_len);
    memcpy(header + 1, &len_be, sizeof(len_be));

    if (send_all(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    if (payload_len > 0 && send_all(fd, payload, payload_len) != 0) {
        return -1;
    }
    return 0;
}

static int hs_recv_frame(int fd, uint8_t expected_type, uint8_t **payload_out, size_t *payload_len_out)
{
    uint8_t header[HS_FRAME_HEADER_LEN];
    uint32_t len_be;
    uint32_t payload_len;
    uint8_t *payload;

    if (fd < 0 || payload_out == NULL || payload_len_out == NULL) {
        return -1;
    }

    *payload_out = NULL;
    *payload_len_out = 0;

    if (recv_all(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    if (header[0] != expected_type) {
        return -1;
    }

    memcpy(&len_be, header + 1, sizeof(len_be));
    payload_len = ntohl(len_be);

    if (payload_len == 0) {
        return 0;
    }

    payload = malloc(payload_len);
    if (payload == NULL) {
        return -1;
    }

    if (recv_all(fd, payload, payload_len) != 0) {
        free(payload);
        return -1;
    }

    *payload_out = payload;
    *payload_len_out = payload_len;
    return 0;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int hs_hkdf_extract_expand(const uint8_t *salt, size_t salt_len,
                                  const uint8_t *ikm, size_t ikm_len,
                                  const uint8_t *info, size_t info_len,
                                  uint8_t out[32])
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *ctx;
    OSSL_PARAM params[5];

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        return -1;
    }

    ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) {
        return -1;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, out, 32u, params) != 1) {
        EVP_KDF_CTX_free(ctx);
        return -1;
    }

    EVP_KDF_CTX_free(ctx);
    return 0;
}
#else
static int hs_hkdf_extract(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t prk_out[SHA256_DIGEST_LENGTH])
{
    unsigned int out_len;

    if (HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk_out, &out_len) == NULL) {
        return -1;
    }

    return out_len == SHA256_DIGEST_LENGTH ? 0 : -1;
}

static int hs_hkdf_expand(const uint8_t prk[SHA256_DIGEST_LENGTH],
                          const uint8_t *info, size_t info_len,
                          uint8_t out[32])
{
    uint8_t t[SHA256_DIGEST_LENGTH];
    unsigned int t_len;
    HMAC_CTX *hctx;
    uint8_t counter;

    hctx = HMAC_CTX_new();
    if (hctx == NULL) {
        return -1;
    }

    counter = 0x01;
    if (HMAC_Init_ex(hctx, prk, SHA256_DIGEST_LENGTH, EVP_sha256(), NULL) != 1 ||
        HMAC_Update(hctx, info, info_len) != 1 ||
        HMAC_Update(hctx, &counter, 1) != 1 ||
        HMAC_Final(hctx, t, &t_len) != 1) {
        HMAC_CTX_free(hctx);
        return -1;
    }

    HMAC_CTX_free(hctx);
    if (t_len < 32u) {
        return -1;
    }

    memcpy(out, t, 32u);
    return 0;
}
#endif

int hs_send_chlo(int fd, const uint8_t *client_pub, size_t client_pub_len)
{
    return hs_send_frame(fd, HS_CHLO, client_pub, client_pub_len);
}

int hs_recv_chlo(int fd, uint8_t **client_pub, size_t *client_pub_len)
{
    return hs_recv_frame(fd, HS_CHLO, client_pub, client_pub_len);
}

int hs_send_shlo(int fd, const uint8_t *server_pub, size_t server_pub_len,
                 const uint8_t *sig, size_t sig_len)
{
    uint8_t *payload;
    uint8_t *p;
    size_t payload_len;
    uint32_t pub_len_be;
    uint32_t sig_len_be;
    int rc;

    if ((server_pub == NULL && server_pub_len > 0) || (sig == NULL && sig_len > 0) ||
        server_pub_len > UINT32_MAX || sig_len > UINT32_MAX) {
        return -1;
    }
    if (server_pub_len > SIZE_MAX - sig_len - 8u) {
        return -1;
    }

    payload_len = 8u + server_pub_len + sig_len;
    payload = malloc(payload_len);
    if (payload == NULL) {
        return -1;
    }

    p = payload;
    pub_len_be = htonl((uint32_t)server_pub_len);
    sig_len_be = htonl((uint32_t)sig_len);
    memcpy(p, &pub_len_be, 4u);
    p += 4u;
    if (server_pub_len > 0) {
        memcpy(p, server_pub, server_pub_len);
    }
    p += server_pub_len;
    memcpy(p, &sig_len_be, 4u);
    p += 4u;
    if (sig_len > 0) {
        memcpy(p, sig, sig_len);
    }

    rc = hs_send_frame(fd, HS_SHLO, payload, payload_len);
    free(payload);
    return rc;
}

int hs_recv_shlo(int fd, uint8_t **server_pub, size_t *server_pub_len,
                 uint8_t **sig, size_t *sig_len)
{
    uint8_t *payload;
    size_t payload_len;
    const uint8_t *p;
    uint32_t pub_len_be;
    uint32_t sig_len_be;
    size_t pub_len;
    size_t sig_l;

    if (server_pub == NULL || server_pub_len == NULL || sig == NULL || sig_len == NULL) {
        return -1;
    }

    *server_pub = NULL;
    *server_pub_len = 0;
    *sig = NULL;
    *sig_len = 0;

    if (hs_recv_frame(fd, HS_SHLO, &payload, &payload_len) != 0) {
        return -1;
    }

    if (payload_len < 8u) {
        free(payload);
        return -1;
    }

    p = payload;
    memcpy(&pub_len_be, p, 4u);
    p += 4u;
    pub_len = ntohl(pub_len_be);
    if (pub_len > payload_len - 8u) {
        free(payload);
        return -1;
    }

    *server_pub = malloc(pub_len);
    if (*server_pub == NULL && pub_len > 0) {
        free(payload);
        return -1;
    }
    if (pub_len > 0) {
        memcpy(*server_pub, p, pub_len);
    }
    p += pub_len;

    memcpy(&sig_len_be, p, 4u);
    p += 4u;
    sig_l = ntohl(sig_len_be);
    if (sig_l != (size_t)(payload + payload_len - p)) {
        free(*server_pub);
        *server_pub = NULL;
        free(payload);
        return -1;
    }

    *sig = malloc(sig_l);
    if (*sig == NULL && sig_l > 0) {
        free(*server_pub);
        *server_pub = NULL;
        free(payload);
        return -1;
    }
    if (sig_l > 0) {
        memcpy(*sig, p, sig_l);
    }

    *server_pub_len = pub_len;
    *sig_len = sig_l;
    free(payload);
    return 0;
}

int hs_derive_keys(const uint8_t *shared_secret, size_t shared_secret_len,
                   const uint8_t *transcript, size_t transcript_len,
                   uint8_t c2s_key[32], uint8_t s2c_key[32])
{
    uint8_t salt[SHA256_DIGEST_LENGTH];

    if (shared_secret == NULL || transcript == NULL || c2s_key == NULL || s2c_key == NULL) {
        return -1;
    }

    if (EVP_Digest(transcript, transcript_len, salt, NULL, EVP_sha256(), NULL) != 1) {
        return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (hs_hkdf_extract_expand(salt, sizeof(salt),
                               shared_secret, shared_secret_len,
                               (const uint8_t *)HS_LABEL_C2S, strlen(HS_LABEL_C2S),
                               c2s_key) != 0) {
        return -1;
    }
    if (hs_hkdf_extract_expand(salt, sizeof(salt),
                               shared_secret, shared_secret_len,
                               (const uint8_t *)HS_LABEL_S2C, strlen(HS_LABEL_S2C),
                               s2c_key) != 0) {
        return -1;
    }
#else
    uint8_t prk[SHA256_DIGEST_LENGTH];
    if (hs_hkdf_extract(salt, sizeof(salt), shared_secret, shared_secret_len, prk) != 0) {
        return -1;
    }
    if (hs_hkdf_expand(prk, (const uint8_t *)HS_LABEL_C2S, strlen(HS_LABEL_C2S), c2s_key) != 0) {
        return -1;
    }
    if (hs_hkdf_expand(prk, (const uint8_t *)HS_LABEL_S2C, strlen(HS_LABEL_S2C), s2c_key) != 0) {
        return -1;
    }
#endif

    return 0;
}

int hs_gen_ecdh_keypair(uint8_t **pub_out, size_t *pub_len_out, EVP_PKEY **pkey_out)
{
    EVP_PKEY_CTX *kctx;
    EVP_PKEY *params;
    EVP_PKEY *pkey;
    unsigned char *der;
    int der_len;

    if (pub_out == NULL || pub_len_out == NULL || pkey_out == NULL) {
        return -1;
    }

    *pub_out = NULL;
    *pub_len_out = 0;
    *pkey_out = NULL;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (kctx == NULL) {
        return -1;
    }

    params = NULL;
    pkey = NULL;
    if (EVP_PKEY_paramgen_init(kctx) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, ECDH_CURVE_NID) != 1 ||
        EVP_PKEY_paramgen(kctx, &params) != 1) {
        EVP_PKEY_CTX_free(kctx);
        return -1;
    }

    EVP_PKEY_CTX_free(kctx);
    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (kctx == NULL) {
        EVP_PKEY_free(params);
        return -1;
    }

    if (EVP_PKEY_keygen_init(kctx) != 1 || EVP_PKEY_keygen(kctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(params);
        return -1;
    }

    /* Export public key as DER SubjectPublicKeyInfo for wire transport. */
    der = NULL;
    der_len = i2d_PUBKEY(pkey, &der);
    if (der_len <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(params);
        return -1;
    }

    *pub_out = malloc((size_t)der_len);
    if (*pub_out == NULL) {
        OPENSSL_free(der);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(params);
        return -1;
    }

    memcpy(*pub_out, der, (size_t)der_len);
    *pub_len_out = (size_t)der_len;
    *pkey_out = pkey;

    OPENSSL_free(der);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    return 0;
}

int hs_compute_shared(EVP_PKEY *own_priv, const uint8_t *peer_pub, size_t peer_pub_len,
                      uint8_t **secret_out, size_t *secret_len_out)
{
    const unsigned char *p;
    EVP_PKEY *peer_key;
    EVP_PKEY_CTX *ctx;
    size_t secret_len;
    uint8_t *secret;

    if (own_priv == NULL || peer_pub == NULL || peer_pub_len == 0 || secret_out == NULL ||
        secret_len_out == NULL) {
        return -1;
    }

    *secret_out = NULL;
    *secret_len_out = 0;

    /* Parse peer key from DER SubjectPublicKeyInfo. */
    p = peer_pub;
    peer_key = d2i_PUBKEY(NULL, &p, (long)peer_pub_len);
    if (peer_key == NULL) {
        return -1;
    }

    ctx = EVP_PKEY_CTX_new(own_priv, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(peer_key);
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) != 1 || EVP_PKEY_derive_set_peer(ctx, peer_key) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    if (EVP_PKEY_derive(ctx, NULL, &secret_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    secret = malloc(secret_len);
    if (secret == NULL) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    if (EVP_PKEY_derive(ctx, secret, &secret_len) != 1) {
        free(secret);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return -1;
    }

    *secret_out = secret;
    *secret_len_out = secret_len;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    return 0;
}

int hs_sign_transcript(const char *server_priv_pem_path,
                       const uint8_t *t, size_t tlen,
                       uint8_t **sig_out, size_t *sig_len_out)
{
    FILE *fp;
    EVP_PKEY *pkey;
    EVP_MD_CTX *mctx;
    size_t sig_len;
    uint8_t *sig;

    if (server_priv_pem_path == NULL || t == NULL || sig_out == NULL || sig_len_out == NULL) {
        return -1;
    }

    *sig_out = NULL;
    *sig_len_out = 0;

    fp = fopen(server_priv_pem_path, "r");
    if (fp == NULL) {
        return -1;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        return -1;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_DigestSign(mctx, NULL, &sig_len, t, tlen) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    sig = malloc(sig_len);
    if (sig == NULL) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_DigestSign(mctx, sig, &sig_len, t, tlen) != 1) {
        free(sig);
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    *sig_out = sig;
    *sig_len_out = sig_len;

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return 0;
}

int hs_verify_transcript(const char *server_pub_pem_path,
                         const uint8_t *t, size_t tlen,
                         const uint8_t *sig, size_t siglen)
{
    FILE *fp;
    EVP_PKEY *pkey;
    EVP_MD_CTX *mctx;
    int ok;

    if (server_pub_pem_path == NULL || t == NULL || sig == NULL) {
        return -1;
    }

    fp = fopen(server_pub_pem_path, "r");
    if (fp == NULL) {
        return -1;
    }

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        return -1;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    ok = EVP_DigestVerify(mctx, sig, siglen, t, tlen);

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ok == 1 ? 0 : -1;
}
