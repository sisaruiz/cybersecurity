#ifndef COMMON_HANDSHAKE_H
#define COMMON_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#define ECDH_CURVE_NID NID_X9_62_prime256v1

typedef enum hs_msg_type {
    HS_CHLO = 1,
    HS_SHLO = 2,
} hs_msg_type_t;

int hs_send_chlo(int fd, const uint8_t *client_pub, size_t client_pub_len);
int hs_recv_chlo(int fd, uint8_t **client_pub, size_t *client_pub_len);

int hs_send_shlo(int fd, const uint8_t *server_pub, size_t server_pub_len,
                 const uint8_t *sig, size_t sig_len);
int hs_recv_shlo(int fd, uint8_t **server_pub, size_t *server_pub_len,
                 uint8_t **sig, size_t *sig_len);

int hs_derive_keys(const uint8_t *shared_secret, size_t shared_secret_len,
                   const uint8_t *transcript, size_t transcript_len,
                   uint8_t c2s_key[32], uint8_t s2c_key[32]);

int hs_gen_ecdh_keypair(uint8_t **pub_out, size_t *pub_len_out, EVP_PKEY **pkey_out);
int hs_compute_shared(EVP_PKEY *own_priv, const uint8_t *peer_pub, size_t peer_pub_len,
                      uint8_t **secret_out, size_t *secret_len_out);
int hs_sign_transcript(const char *server_priv_pem_path,
                       const uint8_t *t, size_t tlen,
                       uint8_t **sig_out, size_t *sig_len_out);
int hs_verify_transcript(const char *server_pub_pem_path,
                         const uint8_t *t, size_t tlen,
                         const uint8_t *sig, size_t siglen);

#endif /* COMMON_HANDSHAKE_H */
