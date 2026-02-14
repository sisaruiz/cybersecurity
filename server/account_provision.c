#include "auth.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AP_DB_PATH "server/res/users.db"
#define AP_LINE_MAX 1024

typedef struct ap_user {
    char *username;
    int must_change;
    int deleted;
    uint8_t salt[AUTH_SALT_LEN];
    uint8_t hash[AUTH_HASH_LEN];
} ap_user_t;

static void ap_free_users(ap_user_t *users, size_t len)
{
    size_t i;

    if (users == NULL) {
        return;
    }

    for (i = 0; i < len; i++) {
        free(users[i].username);
    }
    free(users);
}

static int ap_parse_bool(const char *s, int *out)
{
    char *end = NULL;
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

static int ap_pbkdf2(const char *password,
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

static int ap_parse_line(char *line, ap_user_t *out)
{
    char *fields[5];
    size_t i;

    if (line == NULL || out == NULL) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    for (i = 0; i < 5; i++) {
        fields[i] = (i == 0) ? strtok(line, ":") : strtok(NULL, ":");
        line = NULL;
        if (fields[i] == NULL) {
            return -1;
        }
    }
    if (strtok(NULL, ":") != NULL) {
        return -1;
    }

    if (fields[0][0] == '\0' || strchr(fields[0], ':') != NULL) {
        return -1;
    }

    out->username = strdup(fields[0]);
    if (out->username == NULL) {
        return -1;
    }

    if (ap_parse_bool(fields[1], &out->must_change) != 0 ||
        ap_parse_bool(fields[2], &out->deleted) != 0 ||
        auth_hex_decode(fields[3], out->salt, AUTH_SALT_LEN) != 0 ||
        auth_hex_decode(fields[4], out->hash, AUTH_HASH_LEN) != 0) {
        free(out->username);
        out->username = NULL;
        return -1;
    }

    return 0;
}

static int ap_load_db(ap_user_t **users_out, size_t *len_out)
{
    FILE *fp;
    char line[AP_LINE_MAX];
    ap_user_t *users = NULL;
    size_t len = 0;
    size_t cap = 0;

    if (users_out == NULL || len_out == NULL) {
        return -1;
    }

    fp = fopen(AP_DB_PATH, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        ap_user_t user;
        ap_user_t *next;
        char *nl = strchr(line, '\n');

        if (nl != NULL) {
            *nl = '\0';
        }
        if (line[0] == '\0') {
            continue;
        }

        if (ap_parse_line(line, &user) != 0) {
            fclose(fp);
            ap_free_users(users, len);
            return -1;
        }

        if (len == cap) {
            size_t new_cap = (cap == 0u) ? 8u : cap * 2u;
            if (new_cap < cap) {
                fclose(fp);
                free(user.username);
                ap_free_users(users, len);
                return -1;
            }
            next = realloc(users, new_cap * sizeof(*next));
            if (next == NULL) {
                fclose(fp);
                free(user.username);
                ap_free_users(users, len);
                return -1;
            }
            users = next;
            cap = new_cap;
        }

        users[len++] = user;
    }

    if (ferror(fp)) {
        fclose(fp);
        ap_free_users(users, len);
        return -1;
    }

    if (fclose(fp) != 0) {
        ap_free_users(users, len);
        return -1;
    }

    *users_out = users;
    *len_out = len;
    return 0;
}

static int ap_write_db_atomic(const ap_user_t *users, size_t len)
{
    char template_path[] = "server/res/users.db.tmpXXXXXX";
    int fd;
    FILE *fp;
    size_t i;

    fd = mkstemp(template_path);
    if (fd < 0) {
        return -1;
    }

    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        unlink(template_path);
        return -1;
    }

    for (i = 0; i < len; i++) {
        char salt_hex[AUTH_SALT_LEN * 2u + 1u];
        char hash_hex[AUTH_HASH_LEN * 2u + 1u];

        if (auth_hex_encode(users[i].salt, AUTH_SALT_LEN, salt_hex, sizeof(salt_hex)) != 0 ||
            auth_hex_encode(users[i].hash, AUTH_HASH_LEN, hash_hex, sizeof(hash_hex)) != 0) {
            fclose(fp);
            unlink(template_path);
            return -1;
        }

        if (fprintf(fp, "%s:%d:%d:%s:%s\n",
                    users[i].username,
                    users[i].must_change,
                    users[i].deleted,
                    salt_hex,
                    hash_hex) < 0) {
            fclose(fp);
            unlink(template_path);
            return -1;
        }
    }

    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(template_path);
        return -1;
    }

    if (fclose(fp) != 0) {
        unlink(template_path);
        return -1;
    }

    if (rename(template_path, AP_DB_PATH) != 0) {
        unlink(template_path);
        return -1;
    }

    return 0;
}

static int ap_update_record(ap_user_t *users,
                            size_t len,
                            const char *username,
                            const char *new_password,
                            int *was_found,
                            int *was_active)
{
    size_t i;

    if (users == NULL || username == NULL || new_password == NULL || was_found == NULL || was_active == NULL) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        if (strcmp(users[i].username, username) == 0) {
            *was_found = 1;

            if (users[i].deleted == 0) {
                *was_active = 1;
                return 0;
            }

            if (RAND_bytes(users[i].salt, AUTH_SALT_LEN) != 1) {
                return -1;
            }
            if (ap_pbkdf2(new_password, users[i].salt, users[i].hash) != 0) {
                return -1;
            }
            users[i].must_change = 1;
            users[i].deleted = 0;
            return 0;
        }
    }

    return 0;
}

static int ap_append_user(ap_user_t **users, size_t *len, const char *username, const char *new_password)
{
    ap_user_t *next;
    ap_user_t *u;

    if (users == NULL || len == NULL || username == NULL || new_password == NULL) {
        return -1;
    }

    next = realloc(*users, (*len + 1u) * sizeof(*next));
    if (next == NULL) {
        return -1;
    }
    *users = next;

    u = &((*users)[*len]);
    memset(u, 0, sizeof(*u));

    u->username = strdup(username);
    if (u->username == NULL) {
        return -1;
    }

    if (RAND_bytes(u->salt, AUTH_SALT_LEN) != 1) {
        free(u->username);
        u->username = NULL;
        return -1;
    }
    if (ap_pbkdf2(new_password, u->salt, u->hash) != 0) {
        free(u->username);
        u->username = NULL;
        return -1;
    }

    u->must_change = 1;
    u->deleted = 0;
    (*len)++;
    return 0;
}

int main(int argc, char **argv)
{
    ap_user_t *users = NULL;
    size_t users_len = 0;
    int was_found = 0;
    int was_active = 0;
    const char *username;
    const char *new_password;

    if (argc != 4 || strcmp(argv[1], "register") != 0) {
        fprintf(stderr, "Usage:\n  ./server/account_provision register <username> <new_password>\n");
        return 1;
    }

    username = argv[2];
    new_password = argv[3];

    if (username[0] == '\0' || strchr(username, ':') != NULL) {
        fprintf(stderr, "Invalid username\n");
        return 1;
    }

    if (ap_load_db(&users, &users_len) != 0) {
        fprintf(stderr, "Failed to load %s\n", AP_DB_PATH);
        return 1;
    }

    if (ap_update_record(users, users_len, username, new_password, &was_found, &was_active) != 0) {
        ap_free_users(users, users_len);
        fprintf(stderr, "Failed to provision account\n");
        return 1;
    }

    if (was_active) {
        ap_free_users(users, users_len);
        fprintf(stderr, "User already active. Refusing to overwrite active account.\n");
        return 1;
    }

    if (!was_found && ap_append_user(&users, &users_len, username, new_password) != 0) {
        ap_free_users(users, users_len);
        fprintf(stderr, "Failed to create user record\n");
        return 1;
    }

    if (ap_write_db_atomic(users, users_len) != 0) {
        ap_free_users(users, users_len);
        fprintf(stderr, "Failed to update %s\n", AP_DB_PATH);
        return 1;
    }

    ap_free_users(users, users_len);
    return 0;
}
