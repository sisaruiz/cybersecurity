#include "auth.h"
#include "storage.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KS_TEST_DB_PATH "server/res/users.db"
#define KS_TEST_SEED_PATH "server/res/users.seed"
#define KS_TEST_DOC_PATH "server/res/testdoc.bin"
#define KS_TEST_SIG_PATH "server/res/sig.bin"
#define KS_TEST_USER "alice"
#define KS_TEST_PASSWORD "TempPass123!"
#define KS_TEST_PEM_PREVIEW 80u

static int read_file(const char *path, uint8_t **buf_out, size_t *len_out)
{
    FILE *fp;
    long size;
    uint8_t *buf;
    size_t n;

    if (path == NULL || buf_out == NULL || len_out == NULL) {
        return -1;
    }

    *buf_out = NULL;
    *len_out = 0u;

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

static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *fp;

    if (path == NULL || (len > 0u && buf == NULL)) {
        return -1;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        return -1;
    }

    if (len > 0u && fwrite(buf, 1u, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        return -1;
    }

    return 0;
}

static int file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

int main(void)
{
    uint8_t *pub = NULL;
    size_t pub_len = 0u;
    uint8_t *doc = NULL;
    size_t doc_len = 0u;
    uint8_t *sig = NULL;
    size_t sig_len = 0u;
    int must_change = 0;
    int deleted = 0;
    char preview[KS_TEST_PEM_PREVIEW + 1u];
    const char *user_dir = "server/res/keystore/alice";
    const char *pub_path = "server/res/keystore/alice/public.pem";
    const char *enc_path = "server/res/keystore/alice/private.enc";

    /* Ensure the user database exists, including bootstrap from seed when needed. */
    if (auth_bootstrap_from_seed_if_needed(KS_TEST_DB_PATH, KS_TEST_SEED_PATH) != 0) {
        fprintf(stderr, "failed to bootstrap auth DB\n");
        return 1;
    }
    if (auth_load_db(KS_TEST_DB_PATH) != 0) {
        fprintf(stderr, "failed to load auth DB\n");
        return 1;
    }

    /* Confirm alice exists by checking her password can be verified. */
    if (auth_verify_password(KS_TEST_USER, KS_TEST_PASSWORD, &must_change, &deleted) != 0) {
        fprintf(stderr, "alice is missing or password mismatch\n");
        return 1;
    }
    printf("loaded user '%s' (must_change=%d, deleted=%d)\n", KS_TEST_USER, must_change, deleted);

    if (deleted != 0) {
        fprintf(stderr, "alice is already marked deleted, cannot proceed\n");
        return 1;
    }

    /* Create keys for alice. */
    if (ks_create_keys(KS_TEST_USER, KS_TEST_PASSWORD) != 0) {
        fprintf(stderr, "ks_create_keys failed\n");
        return 1;
    }

    /* Fetch and print a short preview of the public key PEM. */
    if (ks_get_public(KS_TEST_USER, &pub, &pub_len) != 0 || pub_len == 0u) {
        fprintf(stderr, "ks_get_public failed\n");
        return 1;
    }
    memset(preview, 0, sizeof(preview));
    memcpy(preview, pub, (pub_len < KS_TEST_PEM_PREVIEW) ? pub_len : KS_TEST_PEM_PREVIEW);
    printf("public PEM first %u chars: %s\n", KS_TEST_PEM_PREVIEW, preview);
    free(pub);
    pub = NULL;

    /* Load the test document and sign it with RSA-PSS via ks_sign_doc(). */
    if (read_file(KS_TEST_DOC_PATH, &doc, &doc_len) != 0) {
        fprintf(stderr, "failed to read %s\n", KS_TEST_DOC_PATH);
        return 1;
    }
    if (ks_sign_doc(KS_TEST_USER, KS_TEST_PASSWORD, doc, doc_len, &sig, &sig_len) != 0) {
        fprintf(stderr, "ks_sign_doc failed\n");
        free(doc);
        return 1;
    }
    free(doc);
    doc = NULL;

    printf("signature length: %zu bytes\n", sig_len);
    if (write_file(KS_TEST_SIG_PATH, sig, sig_len) != 0) {
        fprintf(stderr, "failed to write %s\n", KS_TEST_SIG_PATH);
        free(sig);
        return 1;
    }
    free(sig);
    sig = NULL;

    /* Delete keys and confirm key files are gone plus tombstone is set. */
    if (ks_delete_keys(KS_TEST_USER) != 0) {
        fprintf(stderr, "ks_delete_keys failed\n");
        return 1;
    }

    if (file_exists(pub_path) || file_exists(enc_path) || file_exists(user_dir)) {
        fprintf(stderr, "key material still present after deletion\n");
        return 1;
    }

    if (auth_verify_password(KS_TEST_USER, KS_TEST_PASSWORD, &must_change, &deleted) != 0 || deleted != 1) {
        fprintf(stderr, "alice not marked deleted in auth DB\n");
        return 1;
    }
    printf("alice deletion status confirmed (deleted=%d)\n", deleted);

    /* Attempt to recreate keys: this must fail for a deleted/tombstoned account. */
    if (ks_create_keys(KS_TEST_USER, KS_TEST_PASSWORD) == 0) {
        fprintf(stderr, "ks_create_keys unexpectedly succeeded for deleted alice\n");
        return 1;
    }

    printf("recreate attempt correctly failed for deleted user\n");
    printf("ks_test completed successfully\n");
    return 0;
}
