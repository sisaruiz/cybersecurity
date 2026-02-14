#ifndef SERVER_AUTH_H
#define SERVER_AUTH_H

#include <stddef.h>
#include <stdint.h>

#define AUTH_SALT_LEN 16u
#define AUTH_HASH_LEN 32u
#define AUTH_PBKDF2_ITERS 200000

int auth_load_db(const char *path);
int auth_bootstrap_from_seed_if_needed(const char *db_path, const char *seed_path);
int auth_verify_password(const char *username, const char *password, int *must_change_out, int *deleted_out);
int auth_change_password(const char *username, const char *old_pw, const char *new_pw);
int auth_set_deleted(const char *username, int deleted);

int auth_hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len);
int auth_hex_decode(const char *in, uint8_t *out, size_t out_len);

#endif /* SERVER_AUTH_H */
