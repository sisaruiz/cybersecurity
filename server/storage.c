#include "storage.h"

#include "auth.h"

#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define KS_ROOT "server/res/keystore"
#define KS_MAGIC "DSS1"
#define KS_VERSION 1u
#define KS_PRIV_HDR_LEN 53u
#define KS_PBKDF2_ITERS 200000
#define KS_GCM_IV_LEN 12u
#define KS_GCM_TAG_LEN 16u

static int ks_join_path(char *out, size_t out_len, const char *a, const char *b)
{
    if (out == NULL || a == NULL || b == NULL) {
        return -1;
    }
    if (snprintf(out, out_len, "%s/%s", a, b) >= (int)out_len) {
        return -1;
    }
    return 0;
}

static int ks_build_user_paths(const char *username,
                               char user_dir[PATH_MAX],
                               char pub_path[PATH_MAX],
                               char enc_path[PATH_MAX])
{
    if (username == NULL || username[0] == '\0' || strchr(username, '/') != NULL) {
        return -1;
    }

    if (ks_join_path(user_dir, PATH_MAX, KS_ROOT, username) != 0) {
        return -1;
    }
    if (ks_join_path(pub_path, PATH_MAX, user_dir, "public.pem") != 0) {
        return -1;
    }
    if (ks_join_path(enc_path, PATH_MAX, user_dir, "private.enc") != 0) {
        return -1;
    }

    return 0;
}

static int ks_ensure_dir(const char *path)
{
    if (mkdir(path, 0700) != 0) {
        if (errno == EEXIST) {
            return 0;
        }
        return -1;
    }
    return 0;
}

static int ks_file_exists(const char *path)
{
    return (access(path, F_OK) == 0) ? 1 : 0;
}

static int ks_read_all(const char *path, uint8_t **buf_out, size_t *len_out)
{
    FILE *fp;
    long size;
    uint8_t *buf;
    size_t n;

    if (path == NULL || buf_out == NULL || len_out == NULL) {
        return -1;
    }

    *buf_out = NULL;
    *len_out = 0;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    buf = (size > 0) ? malloc((size_t)size) : malloc(1u);
    if (buf == NULL) {
        fclose(fp);
        return -1;
    }

    n = fread(buf, 1u, (size_t)size, fp);
    if (n != (size_t)size) {
        free(buf);
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        free(buf);
        return -1;
    }

    *buf_out = buf;
    *len_out = (size_t)size;
    return 0;
}

static int ks_write_all(const char *path, const uint8_t *buf, size_t len)
{
    FILE *fp;

    if (path == NULL || (len > 0 && buf == NULL)) {
        return -1;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        return -1;
    }

    if (len > 0 && fwrite(buf, 1u, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        return -1;
    }

    return 0;
}

static int ks_pbkdf2_key(const char *password,
                         const uint8_t salt[16],
                         uint8_t key_out[32])
{
    if (password == NULL || salt == NULL || key_out == NULL) {
        return -1;
    }

    if (PKCS5_PBKDF2_HMAC(password,
                          (int)strlen(password),
                          salt,
                          16,
                          KS_PBKDF2_ITERS,
                          EVP_sha256(),
                          32,
                          key_out) != 1) {
        return -1;
    }

    return 0;
}

static int ks_generate_rsa_key(EVP_PKEY **pkey_out)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey;

    if (pkey_out == NULL) {
        return -1;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    *pkey_out = pkey;
    return 0;
}

static int ks_derive_login_session_key(const char *username,
                                       const char *password,
                                       uint8_t key_out[32])
{
    char salt[256];

    if (username == NULL || password == NULL || key_out == NULL) {
        return -1;
    }
    if (snprintf(salt, sizeof(salt), "dss-session:%s", username) >= (int)sizeof(salt)) {
        return -1;
    }

    if (PKCS5_PBKDF2_HMAC(password,
                          (int)strlen(password),
                          (const uint8_t *)salt,
                          (int)strlen(salt),
                          KS_PBKDF2_ITERS,
                          EVP_sha256(),
                          32,
                          key_out) != 1) {
        return -1;
    }

    return 0;
}

static int ks_decrypt_private_blob_with_key(const uint8_t *blob,
                                            size_t blob_len,
                                            const uint8_t key[32],
                                            uint8_t **plain_out,
                                            size_t *plain_len_out)
{
    uint8_t iv[KS_GCM_IV_LEN];
    uint8_t tag[KS_GCM_TAG_LEN];
    uint32_t ct_len_u32;
    const uint8_t *ct;
    EVP_CIPHER_CTX *ctx;
    uint8_t *plain;
    int len1;
    int len2;

    if (blob == NULL || key == NULL || plain_out == NULL || plain_len_out == NULL) {
        return -1;
    }
    if (blob_len < KS_PRIV_HDR_LEN) {
        return -1;
    }
    if (memcmp(blob, KS_MAGIC, 4u) != 0) {
        return -1;
    }

    memcpy(iv, blob + 21u, sizeof(iv));
    memcpy(tag, blob + 33u, sizeof(tag));

    ct_len_u32 = ((uint32_t)blob[49u] << 24) |
                 ((uint32_t)blob[50u] << 16) |
                 ((uint32_t)blob[51u] << 8) |
                 (uint32_t)blob[52u];

    if (blob_len != KS_PRIV_HDR_LEN + (size_t)ct_len_u32) {
        return -1;
    }

    ct = blob + KS_PRIV_HDR_LEN;

    plain = malloc((size_t)ct_len_u32 + 1u);
    if (plain == NULL) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(plain);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, KS_GCM_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plain, &len1, ct, (int)ct_len_u32) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, KS_GCM_TAG_LEN, tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plain + len1, &len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plain);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    plain[len1 + len2] = '\0';

    *plain_out = plain;
    *plain_len_out = (size_t)(len1 + len2);
    return 0;
}

static int ks_encrypt_private_pem_with_key(const uint8_t *plain,
                                           size_t plain_len,
                                           const uint8_t key[32],
                                           uint8_t **blob_out,
                                           size_t *blob_len_out)
{
    uint8_t salt[16];
    uint8_t iv[KS_GCM_IV_LEN];
    uint8_t tag[KS_GCM_TAG_LEN];
    EVP_CIPHER_CTX *ctx;
    uint8_t *out;
    uint32_t ct_len_u32;
    int len1;
    int len2;

    if (plain == NULL || key == NULL || blob_out == NULL || blob_len_out == NULL) {
        return -1;
    }
    if (plain_len > UINT32_MAX) {
        return -1;
    }

    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        return -1;
    }

    out = malloc(KS_PRIV_HDR_LEN + plain_len);
    if (out == NULL) {
        return -1;
    }

    memcpy(out, KS_MAGIC, 4u);
    out[4] = 2u;
    memcpy(out + 5u, salt, sizeof(salt));
    memcpy(out + 21u, iv, sizeof(iv));
    memset(out + 33u, 0, KS_GCM_TAG_LEN);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(out);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, KS_GCM_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, out + KS_PRIV_HDR_LEN, &len1, plain, (int)plain_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, out + KS_PRIV_HDR_LEN + len1, &len2) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, KS_GCM_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(out);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    ct_len_u32 = (uint32_t)(len1 + len2);
    memcpy(out + 33u, tag, KS_GCM_TAG_LEN);
    out[49u] = (uint8_t)((ct_len_u32 >> 24) & 0xffu);
    out[50u] = (uint8_t)((ct_len_u32 >> 16) & 0xffu);
    out[51u] = (uint8_t)((ct_len_u32 >> 8) & 0xffu);
    out[52u] = (uint8_t)(ct_len_u32 & 0xffu);

    *blob_out = out;
    *blob_len_out = KS_PRIV_HDR_LEN + (size_t)ct_len_u32;
    return 0;
}

int ks_derive_session_key(const char *username,
                          const char *password,
                          uint8_t key_out[32])
{
    char user_dir[PATH_MAX];
    char pub_path[PATH_MAX];
    char enc_path[PATH_MAX];
    uint8_t *blob;
    size_t blob_len;

    blob = NULL;
    if (ks_derive_login_session_key(username, password, key_out) != 0) {
        return -1;
    }

    if (ks_build_user_paths(username, user_dir, pub_path, enc_path) != 0) {
        return -1;
    }
    (void)user_dir;
    (void)pub_path;

    if (ks_read_all(enc_path, &blob, &blob_len) != 0) {
        return 0;
    }

    if (blob_len >= KS_PRIV_HDR_LEN && memcmp(blob, KS_MAGIC, 4u) == 0 && blob[4] == KS_VERSION) {
        if (ks_pbkdf2_key(password, blob + 5u, key_out) != 0) {
            free(blob);
            return -1;
        }
    }

    free(blob);
    return 0;
}

int ks_create_keys_session(const char *username, const uint8_t user_wrap_key[32])
{
    char user_dir[PATH_MAX];
    char pub_path[PATH_MAX];
    char enc_path[PATH_MAX];
    EVP_PKEY *pkey;
    BIO *priv_bio;
    FILE *pub_fp;
    uint8_t *priv_pem;
    size_t priv_len;
    uint8_t *enc_blob;
    size_t enc_blob_len;
    BUF_MEM *bptr;

    pkey = NULL;
    priv_bio = NULL;
    pub_fp = NULL;
    priv_pem = NULL;
    enc_blob = NULL;

    if (username == NULL || user_wrap_key == NULL) {
        return -1;
    }

    {
        int deleted;
        if (auth_get_deleted(username, &deleted) != 0) {
            return -1;
        }
        if (deleted != 0) {
            return -1;
        }
    }

    if (ks_build_user_paths(username, user_dir, pub_path, enc_path) != 0) {
        return -1;
    }

    if (ks_file_exists(pub_path) && ks_file_exists(enc_path)) {
        return 0;
    }

    if (ks_ensure_dir("server/res") != 0 ||
        ks_ensure_dir(KS_ROOT) != 0 ||
        ks_ensure_dir(user_dir) != 0) {
        return -1;
    }

    if (ks_generate_rsa_key(&pkey) != 0) {
        goto cleanup;
    }

    pub_fp = fopen(pub_path, "w");
    if (pub_fp == NULL) {
        goto cleanup;
    }
    if (PEM_write_PUBKEY(pub_fp, pkey) != 1) {
        goto cleanup;
    }
    if (fclose(pub_fp) != 0) {
        pub_fp = NULL;
        goto cleanup;
    }
    pub_fp = NULL;

    priv_bio = BIO_new(BIO_s_mem());
    if (priv_bio == NULL) {
        goto cleanup;
    }
    if (PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        goto cleanup;
    }

    BIO_get_mem_ptr(priv_bio, &bptr);
    if (bptr == NULL || bptr->length == 0u) {
        goto cleanup;
    }

    priv_pem = malloc(bptr->length);
    if (priv_pem == NULL) {
        goto cleanup;
    }
    memcpy(priv_pem, bptr->data, bptr->length);
    priv_len = bptr->length;

    if (ks_encrypt_private_pem_with_key(priv_pem, priv_len, user_wrap_key, &enc_blob, &enc_blob_len) != 0) {
        goto cleanup;
    }

    if (ks_write_all(enc_path, enc_blob, enc_blob_len) != 0) {
        goto cleanup;
    }

    free(enc_blob);
    free(priv_pem);
    BIO_free(priv_bio);
    EVP_PKEY_free(pkey);
    return 0;

cleanup:
    if (pub_fp != NULL) {
        fclose(pub_fp);
    }
    unlink(pub_path);
    unlink(enc_path);
    free(enc_blob);
    free(priv_pem);
    BIO_free(priv_bio);
    EVP_PKEY_free(pkey);
    return -1;
}

int ks_get_public(const char *username, uint8_t **pem, size_t *pem_len)
{
    char user_dir[PATH_MAX];
    char pub_path[PATH_MAX];
    char enc_path[PATH_MAX];

    if (username == NULL || pem == NULL || pem_len == NULL) {
        return -1;
    }

    if (ks_build_user_paths(username, user_dir, pub_path, enc_path) != 0) {
        return -1;
    }

    (void)user_dir;
    (void)enc_path;
    return ks_read_all(pub_path, pem, pem_len);
}

int ks_sign_doc_session(const char *username,
                        const uint8_t user_wrap_key[32],
                        const uint8_t *doc, size_t doc_len,
                        uint8_t **sig, size_t *sig_len)
{
    char user_dir[PATH_MAX];
    char pub_path[PATH_MAX];
    char enc_path[PATH_MAX];
    uint8_t *enc_blob;
    size_t enc_blob_len;
    uint8_t *priv_pem;
    size_t priv_pem_len;
    BIO *priv_bio;
    EVP_PKEY *pkey;
    EVP_MD_CTX *mdctx;
    size_t out_len;
    uint8_t *out_sig;
    EVP_PKEY_CTX *pctx;

    enc_blob = NULL;
    priv_pem = NULL;
    priv_bio = NULL;
    pkey = NULL;
    mdctx = NULL;
    out_sig = NULL;

    if (username == NULL || user_wrap_key == NULL || doc == NULL || sig == NULL || sig_len == NULL) {
        return -1;
    }

    if (ks_build_user_paths(username, user_dir, pub_path, enc_path) != 0) {
        return -1;
    }

    (void)user_dir;
    (void)pub_path;

    if (ks_read_all(enc_path, &enc_blob, &enc_blob_len) != 0) {
        return -1;
    }

    if (ks_decrypt_private_blob_with_key(enc_blob, enc_blob_len, user_wrap_key, &priv_pem, &priv_pem_len) != 0) {
        free(enc_blob);
        return -1;
    }
    free(enc_blob);

    priv_bio = BIO_new_mem_buf(priv_pem, (int)priv_pem_len);
    if (priv_bio == NULL) {
        free(priv_pem);
        return -1;
    }

    pkey = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        BIO_free(priv_bio);
        free(priv_pem);
        return -1;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        EVP_PKEY_free(pkey);
        BIO_free(priv_bio);
        free(priv_pem);
        return -1;
    }

    /* Use RSA-PSS with SHA-256 consistently for document signing. */
    if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0 ||
        EVP_DigestSignUpdate(mdctx, doc, doc_len) != 1 ||
        EVP_DigestSignFinal(mdctx, NULL, &out_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(priv_bio);
        free(priv_pem);
        return -1;
    }

    out_sig = malloc(out_len);
    if (out_sig == NULL) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(priv_bio);
        free(priv_pem);
        return -1;
    }

    if (EVP_DigestSignFinal(mdctx, out_sig, &out_len) != 1) {
        free(out_sig);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        BIO_free(priv_bio);
        free(priv_pem);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(priv_bio);
    free(priv_pem);

    *sig = out_sig;
    *sig_len = out_len;
    return 0;
}

int ks_create_keys(const char *username, const char *password)
{
    uint8_t session_key[32];
    int deleted;
    int rc;

    if (auth_get_deleted(username, &deleted) != 0 || deleted != 0) {
        return -1;
    }

    if (ks_derive_session_key(username, password, session_key) != 0) {
        return -1;
    }
    rc = ks_create_keys_session(username, session_key);
    OPENSSL_cleanse(session_key, sizeof(session_key));
    return rc;
}

int ks_sign_doc(const char *username, const char *password,
                const uint8_t *doc, size_t doc_len,
                uint8_t **sig, size_t *sig_len)
{
    uint8_t session_key[32];
    int rc;

    if (ks_derive_session_key(username, password, session_key) != 0) {
        return -1;
    }
    rc = ks_sign_doc_session(username, session_key, doc, doc_len, sig, sig_len);
    OPENSSL_cleanse(session_key, sizeof(session_key));
    return rc;
}

int ks_delete_keys(const char *username)
{
    char user_dir[PATH_MAX];
    char pub_path[PATH_MAX];
    char enc_path[PATH_MAX];

    if (username == NULL) {
        return -1;
    }

    if (ks_build_user_paths(username, user_dir, pub_path, enc_path) != 0) {
        return -1;
    }

    /*
     * Project spec tombstone requirement: once key deletion is requested,
     * the account must be marked deleted in server/res/users.db so key
     * creation stays blocked even if key files are removed or already gone.
     */
    if (auth_set_deleted(username, 1) != 0) {
        return -1;
    }

    if (ks_file_exists(pub_path)) {
        if (unlink(pub_path) != 0) {
            return -1;
        }
    }
    if (ks_file_exists(enc_path)) {
        if (unlink(enc_path) != 0) {
            return -1;
        }
    }

    if (rmdir(user_dir) != 0 && errno != ENOENT && errno != ENOTEMPTY) {
        return -1;
    }

    return 0;
}

int ks_reencrypt_private_for_new_session_key(const char *username,
                                             const uint8_t old_session_key[32],
                                             const uint8_t new_session_key[32])
{
    char user_dir[PATH_MAX];
    char pub_path[PATH_MAX];
    char enc_path[PATH_MAX];
    uint8_t *enc_blob;
    size_t enc_blob_len;
    uint8_t *priv_pem;
    size_t priv_pem_len;
    uint8_t *new_blob;
    size_t new_blob_len;

    enc_blob = NULL;
    priv_pem = NULL;
    new_blob = NULL;

    if (username == NULL || old_session_key == NULL || new_session_key == NULL) {
        return -1;
    }

    if (ks_build_user_paths(username, user_dir, pub_path, enc_path) != 0) {
        return -1;
    }
    (void)user_dir;
    (void)pub_path;

    if (ks_read_all(enc_path, &enc_blob, &enc_blob_len) != 0) {
        return 0;
    }

    if (ks_decrypt_private_blob_with_key(enc_blob, enc_blob_len, old_session_key, &priv_pem, &priv_pem_len) != 0) {
        free(enc_blob);
        return -1;
    }
    free(enc_blob);

    if (ks_encrypt_private_pem_with_key(priv_pem, priv_pem_len, new_session_key, &new_blob, &new_blob_len) != 0) {
        free(priv_pem);
        return -1;
    }
    free(priv_pem);

    if (ks_write_all(enc_path, new_blob, new_blob_len) != 0) {
        free(new_blob);
        return -1;
    }

    free(new_blob);
    return 0;
}
