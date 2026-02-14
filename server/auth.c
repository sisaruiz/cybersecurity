#include "auth.h"

#include <errno.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AUTH_LINE_MAX 1024

typedef struct auth_user {
    char *username;
    int must_change;
    int deleted;
    uint8_t salt[AUTH_SALT_LEN];
    uint8_t hash[AUTH_HASH_LEN];
} auth_user_t;

static auth_user_t *g_users;
static size_t g_users_len;
static size_t g_users_cap;
static char *g_db_path;

static void auth_free_users(void)
{
    size_t i;

    for (i = 0; i < g_users_len; i++) {
        free(g_users[i].username);
    }
    free(g_users);
    g_users = NULL;
    g_users_len = 0;
    g_users_cap = 0;
}

static void auth_clear_state(void)
{
    auth_free_users();
    free(g_db_path);
    g_db_path = NULL;
}

static int auth_parse_bool(const char *s, int *out)
{
    char *end;
    long v;

    if (s == NULL || out == NULL) {
        return -1;
    }

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || *s == '\0' || *end != '\0') {
        return -1;
    }
    if (v != 0 && v != 1) {
        return -1;
    }

    *out = (int)v;
    return 0;
}

int auth_hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (in == NULL || out == NULL) {
        return -1;
    }
    if (out_len < (in_len * 2u + 1u)) {
        return -1;
    }

    for (i = 0; i < in_len; i++) {
        out[2u * i] = hex[(in[i] >> 4) & 0x0fu];
        out[2u * i + 1u] = hex[in[i] & 0x0fu];
    }
    out[in_len * 2u] = '\0';

    return 0;
}

static int auth_hex_nibble(char c, uint8_t *v)
{
    if (c >= '0' && c <= '9') {
        *v = (uint8_t)(c - '0');
        return 0;
    }
    if (c >= 'a' && c <= 'f') {
        *v = (uint8_t)(10 + (c - 'a'));
        return 0;
    }
    if (c >= 'A' && c <= 'F') {
        *v = (uint8_t)(10 + (c - 'A'));
        return 0;
    }
    return -1;
}

int auth_hex_decode(const char *in, uint8_t *out, size_t out_len)
{
    size_t in_len;
    size_t i;

    if (in == NULL || out == NULL) {
        return -1;
    }

    in_len = strlen(in);
    if (in_len != out_len * 2u) {
        return -1;
    }

    for (i = 0; i < out_len; i++) {
        uint8_t hi;
        uint8_t lo;
        if (auth_hex_nibble(in[2u * i], &hi) != 0 || auth_hex_nibble(in[2u * i + 1u], &lo) != 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static int auth_pbkdf2(const char *password,
                       const uint8_t salt[AUTH_SALT_LEN],
                       uint8_t out_hash[AUTH_HASH_LEN])
{
    if (password == NULL || salt == NULL || out_hash == NULL) {
        return -1;
    }

    if (PKCS5_PBKDF2_HMAC(password,
                          (int)strlen(password),
                          salt,
                          AUTH_SALT_LEN,
                          AUTH_PBKDF2_ITERS,
                          EVP_sha256(),
                          AUTH_HASH_LEN,
                          out_hash) != 1) {
        return -1;
    }

    return 0;
}

static auth_user_t *auth_find_user(const char *username)
{
    size_t i;

    if (username == NULL) {
        return NULL;
    }

    for (i = 0; i < g_users_len; i++) {
        if (strcmp(g_users[i].username, username) == 0) {
            return &g_users[i];
        }
    }

    return NULL;
}

static int auth_push_user(const auth_user_t *u)
{
    auth_user_t *next;

    if (u == NULL) {
        return -1;
    }

    if (g_users_len == g_users_cap) {
        size_t new_cap = (g_users_cap == 0u) ? 8u : g_users_cap * 2u;
        if (new_cap < g_users_cap) {
            return -1;
        }
        next = realloc(g_users, new_cap * sizeof(*next));
        if (next == NULL) {
            return -1;
        }
        g_users = next;
        g_users_cap = new_cap;
    }

    g_users[g_users_len] = *u;
    g_users_len++;
    return 0;
}

static int auth_parse_db_line(char *line, auth_user_t *out)
{
    char *fields[5];
    size_t i;

    if (line == NULL || out == NULL) {
        return -1;
    }

    for (i = 0; i < 5; i++) {
        fields[i] = (i == 0) ? strtok(line, ":") : strtok(NULL, ":");
        if (fields[i] == NULL) {
            return -1;
        }
        line = NULL;
    }

    if (strtok(NULL, ":") != NULL) {
        return -1;
    }

    if (fields[0][0] == '\0' || strchr(fields[0], ':') != NULL) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->username = strdup(fields[0]);
    if (out->username == NULL) {
        return -1;
    }

    if (auth_parse_bool(fields[1], &out->must_change) != 0 ||
        auth_parse_bool(fields[2], &out->deleted) != 0 ||
        auth_hex_decode(fields[3], out->salt, AUTH_SALT_LEN) != 0 ||
        auth_hex_decode(fields[4], out->hash, AUTH_HASH_LEN) != 0) {
        free(out->username);
        out->username = NULL;
        return -1;
    }

    return 0;
}

static int auth_write_db(const char *path)
{
    char *tmp_path;
    FILE *fp;
    size_t i;

    if (path == NULL) {
        return -1;
    }

    tmp_path = malloc(strlen(path) + 5u);
    if (tmp_path == NULL) {
        return -1;
    }
    sprintf(tmp_path, "%s.tmp", path);

    fp = fopen(tmp_path, "w");
    if (fp == NULL) {
        free(tmp_path);
        return -1;
    }

    for (i = 0; i < g_users_len; i++) {
        char salt_hex[AUTH_SALT_LEN * 2u + 1u];
        char hash_hex[AUTH_HASH_LEN * 2u + 1u];

        if (auth_hex_encode(g_users[i].salt, AUTH_SALT_LEN, salt_hex, sizeof(salt_hex)) != 0 ||
            auth_hex_encode(g_users[i].hash, AUTH_HASH_LEN, hash_hex, sizeof(hash_hex)) != 0) {
            fclose(fp);
            unlink(tmp_path);
            free(tmp_path);
            return -1;
        }

        if (fprintf(fp, "%s:%d:%d:%s:%s\n",
                    g_users[i].username,
                    g_users[i].must_change,
                    g_users[i].deleted,
                    salt_hex,
                    hash_hex) < 0) {
            fclose(fp);
            unlink(tmp_path);
            free(tmp_path);
            return -1;
        }
    }

    if (fclose(fp) != 0) {
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }

    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }

    free(tmp_path);
    return 0;
}

static int auth_make_seed_path(const char *db_path, const char *suffix, char **out)
{
    const char *dot;
    size_t base_len;

    if (db_path == NULL || suffix == NULL || out == NULL) {
        return -1;
    }

    dot = strrchr(db_path, '.');
    if (dot != NULL && strcmp(dot, ".db") == 0) {
        base_len = (size_t)(dot - db_path);
    } else {
        base_len = strlen(db_path);
    }

    *out = malloc(base_len + strlen(suffix) + 1u);
    if (*out == NULL) {
        return -1;
    }

    memcpy(*out, db_path, base_len);
    strcpy(*out + base_len, suffix);
    return 0;
}

int auth_bootstrap_from_seed_if_needed(const char *db_path, const char *seed_path)
{
    char *consumed_path;
    FILE *seed;
    FILE *db;
    char line[AUTH_LINE_MAX];
    int rc;

    consumed_path = NULL;
    seed = NULL;
    db = NULL;
    rc = -1;

    if (db_path == NULL || seed_path == NULL) {
        goto cleanup;
    }

    if (auth_make_seed_path(db_path, ".seed.consumed", &consumed_path) != 0) {
        goto cleanup;
    }

    if (access(db_path, F_OK) == 0) {
        rc = 0;
        goto cleanup;
    }

    if (access(seed_path, F_OK) != 0) {
        rc = 0;
        goto cleanup;
    }

    seed = fopen(seed_path, "r");
    if (seed == NULL) {
        goto cleanup;
    }

    db = fopen(db_path, "w");
    if (db == NULL) {
        goto cleanup;
    }

    while (fgets(line, sizeof(line), seed) != NULL) {
        char *fields[4];
        char *cursor;
        char *nl;
        int must_change;
        int deleted;
        uint8_t salt[AUTH_SALT_LEN];
        uint8_t hash[AUTH_HASH_LEN];
        char salt_hex[AUTH_SALT_LEN * 2u + 1u];
        char hash_hex[AUTH_HASH_LEN * 2u + 1u];
        size_t i;

        nl = strchr(line, '\n');
        if (nl != NULL) {
            *nl = '\0';
        }

        if (line[0] == '\0') {
            continue;
        }

        cursor = line;
        for (i = 0; i < 4; i++) {
            fields[i] = (i == 0) ? strtok(cursor, ":") : strtok(NULL, ":");
            cursor = NULL;
            if (fields[i] == NULL) {
                goto cleanup;
            }
        }
        if (strtok(NULL, ":") != NULL) {
            goto cleanup;
        }

        if (fields[0][0] == '\0' || strchr(fields[0], ':') != NULL) {
            goto cleanup;
        }

        if (auth_parse_bool(fields[2], &must_change) != 0 ||
            auth_parse_bool(fields[3], &deleted) != 0) {
            goto cleanup;
        }

        if (RAND_bytes(salt, AUTH_SALT_LEN) != 1) {
            goto cleanup;
        }
        if (auth_pbkdf2(fields[1], salt, hash) != 0) {
            goto cleanup;
        }

        if (auth_hex_encode(salt, AUTH_SALT_LEN, salt_hex, sizeof(salt_hex)) != 0 ||
            auth_hex_encode(hash, AUTH_HASH_LEN, hash_hex, sizeof(hash_hex)) != 0) {
            goto cleanup;
        }

        if (fprintf(db, "%s:%d:%d:%s:%s\n", fields[0], must_change, deleted, salt_hex, hash_hex) < 0) {
            goto cleanup;
        }
    }

    if (ferror(seed)) {
        goto cleanup;
    }

    if (fclose(db) != 0) {
        db = NULL;
        goto cleanup;
    }
    db = NULL;

    if (fclose(seed) != 0) {
        seed = NULL;
        goto cleanup;
    }
    seed = NULL;

    if (rename(seed_path, consumed_path) != 0) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (db != NULL) {
        fclose(db);
    }
    if (seed != NULL) {
        fclose(seed);
    }
    if (rc != 0 && db_path != NULL) {
        unlink(db_path);
    }
    free(consumed_path);
    return rc;
}

static int auth_bootstrap_from_seed(const char *db_path)
{
    char *seed_path;
    int rc;

    if (auth_make_seed_path(db_path, ".seed", &seed_path) != 0) {
        return -1;
    }

    rc = auth_bootstrap_from_seed_if_needed(db_path, seed_path);
    free(seed_path);
    return rc;
}

int auth_load_db(const char *path)
{
    FILE *fp;
    char line[AUTH_LINE_MAX];

    if (path == NULL) {
        return -1;
    }

    if (auth_bootstrap_from_seed(path) != 0) {
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    auth_clear_state();

    while (fgets(line, sizeof(line), fp) != NULL) {
        auth_user_t u;
        char *nl;

        nl = strchr(line, '\n');
        if (nl != NULL) {
            *nl = '\0';
        }

        if (line[0] == '\0') {
            continue;
        }

        if (auth_parse_db_line(line, &u) != 0) {
            fclose(fp);
            auth_clear_state();
            return -1;
        }

        if (auth_find_user(u.username) != NULL) {
            free(u.username);
            fclose(fp);
            auth_clear_state();
            return -1;
        }

        if (auth_push_user(&u) != 0) {
            free(u.username);
            fclose(fp);
            auth_clear_state();
            return -1;
        }
    }

    if (ferror(fp)) {
        fclose(fp);
        auth_clear_state();
        return -1;
    }

    if (fclose(fp) != 0) {
        auth_clear_state();
        return -1;
    }

    g_db_path = strdup(path);
    if (g_db_path == NULL) {
        auth_clear_state();
        return -1;
    }

    return 0;
}

static int auth_apply_new_password(auth_user_t *u, const char *new_pw)
{
    uint8_t new_salt[AUTH_SALT_LEN];
    uint8_t new_hash[AUTH_HASH_LEN];

    if (u == NULL || new_pw == NULL) {
        return -1;
    }

    if (RAND_bytes(new_salt, AUTH_SALT_LEN) != 1) {
        return -1;
    }
    if (auth_pbkdf2(new_pw, new_salt, new_hash) != 0) {
        return -1;
    }

    memcpy(u->salt, new_salt, AUTH_SALT_LEN);
    memcpy(u->hash, new_hash, AUTH_HASH_LEN);
    u->must_change = 0;
    return 0;
}

int auth_verify_password(const char *username, const char *password, int *must_change_out, int *deleted_out)
{
    auth_user_t *u;
    uint8_t check_hash[AUTH_HASH_LEN];

    if (username == NULL || password == NULL) {
        return -1;
    }

    u = auth_find_user(username);
    if (u == NULL) {
        return -1;
    }

    if (auth_pbkdf2(password, u->salt, check_hash) != 0) {
        return -1;
    }

    if (memcmp(check_hash, u->hash, AUTH_HASH_LEN) != 0) {
        return -1;
    }

    if (must_change_out != NULL) {
        *must_change_out = u->must_change;
    }
    if (deleted_out != NULL) {
        *deleted_out = u->deleted;
    }

    return 0;
}

int auth_change_password(const char *username, const char *old_pw, const char *new_pw)
{
    auth_user_t *u;
    uint8_t old_hash[AUTH_HASH_LEN];
    if (username == NULL || old_pw == NULL || new_pw == NULL || g_db_path == NULL) {
        return -1;
    }

    u = auth_find_user(username);
    if (u == NULL) {
        return -1;
    }

    if (auth_pbkdf2(old_pw, u->salt, old_hash) != 0) {
        return -1;
    }
    if (memcmp(old_hash, u->hash, AUTH_HASH_LEN) != 0) {
        return -1;
    }

    if (auth_apply_new_password(u, new_pw) != 0) {
        return -1;
    }

    if (auth_write_db(g_db_path) != 0) {
        return -1;
    }

    return 0;
}

int auth_change_password_authenticated(const char *username, const char *new_pw)
{
    auth_user_t *u;

    if (username == NULL || new_pw == NULL || g_db_path == NULL) {
        return -1;
    }

    u = auth_find_user(username);
    if (u == NULL) {
        return -1;
    }

    if (auth_apply_new_password(u, new_pw) != 0) {
        return -1;
    }

    if (auth_write_db(g_db_path) != 0) {
        return -1;
    }

    return 0;
}

int auth_set_deleted(const char *username, int deleted)
{
    auth_user_t *u;

    if (username == NULL || g_db_path == NULL) {
        return -1;
    }
    if (deleted != 0 && deleted != 1) {
        return -1;
    }

    u = auth_find_user(username);
    if (u == NULL) {
        return -1;
    }

    u->deleted = deleted;

    if (auth_write_db(g_db_path) != 0) {
        return -1;
    }

    return 0;
}
