#ifndef SERVER_STORAGE_H
#define SERVER_STORAGE_H

#include <stddef.h>
#include <stdint.h>

int ks_create_keys(const char *username, const char *password);
int ks_get_public(const char *username, uint8_t **pem, size_t *pem_len);
int ks_sign_doc(const char *username, const char *password,
                const uint8_t *doc, size_t doc_len,
                uint8_t **sig, size_t *sig_len);
int ks_delete_keys(const char *username);

#endif /* SERVER_STORAGE_H */
