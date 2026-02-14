#ifndef SERVER_STORAGE_H
#define SERVER_STORAGE_H

#include <stddef.h>
#include <stdint.h>

int ks_derive_session_key(const char *username,
                          const char *password,
                          uint8_t key_out[32]);

int ks_create_keys(const char *username, const char *password);
/* Session-only variant: caller supplies a login-derived user wrap key kept in RAM. */
int ks_create_keys_session(const char *username, const uint8_t user_wrap_key[32]);
int ks_get_public(const char *username, uint8_t **pem, size_t *pem_len);
int ks_sign_doc(const char *username, const char *password,
                const uint8_t *doc, size_t doc_len,
                uint8_t **sig, size_t *sig_len);
/* Session-only variant: caller supplies a login-derived user wrap key kept in RAM. */
int ks_sign_doc_session(const char *username,
                        const uint8_t user_wrap_key[32],
                        const uint8_t *doc, size_t doc_len,
                        uint8_t **sig, size_t *sig_len);
int ks_delete_keys(const char *username);
int ks_reencrypt_private_for_new_session_key(const char *username,
                                             const uint8_t old_session_key[32],
                                             const uint8_t new_session_key[32]);

#endif /* SERVER_STORAGE_H */
