#ifndef COMMON_HANDSHAKE_H
#define COMMON_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#define HS_ECDH_KEY_LEN 32u
#define HS_SIGN_KEY_LEN 32u
#define HS_SIG_LEN 64u

/*
 * Generate an ephemeral X25519 keypair for key agreement.
 * Returns 0 on success and -1 on failure.
 */
int hs_generate_ecdh_keypair(uint8_t priv_out[HS_ECDH_KEY_LEN],
                             uint8_t pub_out[HS_ECDH_KEY_LEN]);

/*
 * Derive a shared secret using local X25519 private key and peer public key.
 * Returns 0 on success and -1 on failure.
 */
int hs_derive_shared_secret(const uint8_t local_priv[HS_ECDH_KEY_LEN],
                            const uint8_t peer_pub[HS_ECDH_KEY_LEN],
                            uint8_t shared_secret_out[HS_ECDH_KEY_LEN]);

/*
 * Sign the server ephemeral public key using Ed25519 server signing key.
 * Returns 0 on success and -1 on failure.
 */
int hs_sign_server_ephemeral(const uint8_t server_sign_priv[HS_SIGN_KEY_LEN],
                             const uint8_t server_eph_pub[HS_ECDH_KEY_LEN],
                             uint8_t signature_out[HS_SIG_LEN]);

/*
 * Verify server signature over its ephemeral public key.
 * Returns 0 on success and -1 on failure.
 */
int hs_verify_server_ephemeral(const uint8_t server_sign_pub[HS_SIGN_KEY_LEN],
                               const uint8_t server_eph_pub[HS_ECDH_KEY_LEN],
                               const uint8_t signature[HS_SIG_LEN]);

#endif /* COMMON_HANDSHAKE_H */
