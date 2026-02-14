#include "../common/dsspacket.h"
#include "../common/handshake.h"
#include "../common/net.h"
#include "../common/replay.h"
#include "../common/securechan.h"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int send_encrypted_pong(int fd,
                               const uint8_t key_out[32],
                               const uint8_t req_nonce[REQ_NONCE_LEN],
                               const char *message)
{
    dss_header_t out_hdr;
    uint8_t aad[DSSPACKET_AAD_LEN];
    size_t aad_len;
    size_t pt_len;
    size_t total_payload_len;
    uint8_t *out_payload;
    uint8_t *iv;
    uint8_t *tag;
    uint8_t *ct;

    pt_len = strlen(message);
    total_payload_len = GCM_IV_LEN + GCM_TAG_LEN + pt_len;
    if (total_payload_len > UINT32_MAX) {
        return -1;
    }

    memset(&out_hdr, 0, sizeof(out_hdr));
    out_hdr.opcode = OP_SIGN_DOC;
    memcpy(out_hdr.req_nonce, req_nonce, REQ_NONCE_LEN);
    out_hdr.payload_len = htonl((uint32_t)total_payload_len);

    if (dsspacket_build_aad(&out_hdr, aad, &aad_len) != 0) {
        return -1;
    }

    out_payload = malloc(total_payload_len);
    if (out_payload == NULL) {
        return -1;
    }

    iv = out_payload;
    tag = out_payload + GCM_IV_LEN;
    ct = out_payload + GCM_IV_LEN + GCM_TAG_LEN;

    /* Generate a fresh IV for each encrypted response frame. */
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) {
        free(out_payload);
        return -1;
    }

    if (sc_aead_encrypt(key_out, iv,
                        aad, aad_len,
                        (const uint8_t *)message, pt_len,
                        ct, tag) != 0) {
        free(out_payload);
        return -1;
    }

    if (dsspacket_send(fd, &out_hdr, out_payload) != 0) {
        free(out_payload);
        return -1;
    }

    free(out_payload);
    return 0;
}

int main(int argc, char **argv)
{
    const char *port;
    int listen_fd;
    int client_fd;
    ReplayCache cache;
    int rc;
    uint8_t c2s_key[32];
    uint8_t s2c_key[32];
    uint8_t key_in[32];
    uint8_t key_out[32];
    uint8_t *client_pub;
    size_t client_pub_len;
    uint8_t *server_pub;
    size_t server_pub_len;
    EVP_PKEY *server_ecdh_priv;
    uint8_t *shared_secret;
    size_t shared_secret_len;
    uint8_t *transcript;
    size_t transcript_len;
    uint8_t *sig;
    size_t sig_len;

    port = (argc > 1) ? argv[1] : "9000";
    listen_fd = -1;
    client_fd = -1;
    memset(&cache, 0, sizeof(cache));
    client_pub = NULL;
    client_pub_len = 0;
    server_pub = NULL;
    server_pub_len = 0;
    server_ecdh_priv = NULL;
    shared_secret = NULL;
    shared_secret_len = 0;
    transcript = NULL;
    transcript_len = 0;
    sig = NULL;
    sig_len = 0;

    listen_fd = tcp_listen(port);
    if (listen_fd < 0) {
        perror("tcp_listen");
        return 1;
    }

    client_fd = tcp_accept(listen_fd);
    if (client_fd < 0) {
        perror("tcp_accept");
        close(listen_fd);
        return 1;
    }

    /* Perform ECDH handshake and derive directional session keys. */
    if (hs_recv_chlo(client_fd, &client_pub, &client_pub_len) != 0) {
        fprintf(stderr, "hs_recv_chlo failed\n");
        goto cleanup;
    }
    puts("Handshake: CHLO received");

    if (hs_gen_ecdh_keypair(&server_pub, &server_pub_len, &server_ecdh_priv) != 0) {
        fprintf(stderr, "hs_gen_ecdh_keypair failed\n");
        goto cleanup;
    }

    if (client_pub_len > SIZE_MAX - server_pub_len) {
        fprintf(stderr, "transcript length overflow\n");
        goto cleanup;
    }

    transcript_len = client_pub_len + server_pub_len;
    transcript = malloc(transcript_len);
    if (transcript == NULL) {
        fprintf(stderr, "transcript allocation failed\n");
        goto cleanup;
    }

    memcpy(transcript, client_pub, client_pub_len);
    memcpy(transcript + client_pub_len, server_pub, server_pub_len);

    if (hs_sign_transcript("server/res/keys/server_private.pem", transcript, transcript_len,
                           &sig, &sig_len) != 0) {
        fprintf(stderr, "hs_sign_transcript failed\n");
        goto cleanup;
    }
    puts("Handshake: transcript signed");

    if (hs_send_shlo(client_fd, server_pub, server_pub_len, sig, sig_len) != 0) {
        fprintf(stderr, "hs_send_shlo failed\n");
        goto cleanup;
    }
    puts("Handshake: SHLO sent");

    if (hs_compute_shared(server_ecdh_priv, client_pub, client_pub_len,
                          &shared_secret, &shared_secret_len) != 0) {
        fprintf(stderr, "hs_compute_shared failed\n");
        goto cleanup;
    }

    if (hs_derive_keys(shared_secret, shared_secret_len,
                       transcript, transcript_len,
                       c2s_key, s2c_key) != 0) {
        fprintf(stderr, "hs_derive_keys failed\n");
        goto cleanup;
    }
    puts("Handshake: session keys derived");

    memcpy(key_in, c2s_key, sizeof(key_in));
    memcpy(key_out, s2c_key, sizeof(key_out));

    rc = replay_init(&cache, 0);
    if (rc != 0) {
        fprintf(stderr, "replay_init failed\n");
        goto cleanup;
    }

    /* Process one client in a simple single-threaded loop. */
    for (;;) {
        dss_header_t in_hdr;
        uint8_t aad[DSSPACKET_AAD_LEN];
        size_t aad_len;
        uint8_t *payload;
        uint32_t payload_len;
        const uint8_t *iv;
        const uint8_t *tag;
        const uint8_t *ct;
        size_t ct_len;
        uint8_t *pt;
        int replay_rc;
        const char *reply_text;

        payload = NULL;
        pt = NULL;

        rc = dsspacket_recv(client_fd, &in_hdr, &payload);
        if (rc != 0) {
            dsspacket_free(payload);
            break;
        }

        replay_rc = replay_check_and_add(&cache, in_hdr.req_nonce);
        if (replay_rc < 0) {
            dsspacket_free(payload);
            break;
        }

        payload_len = ntohl(in_hdr.payload_len);
        if (payload_len < (GCM_IV_LEN + GCM_TAG_LEN)) {
            dsspacket_free(payload);
            break;
        }

        if (dsspacket_build_aad(&in_hdr, aad, &aad_len) != 0) {
            dsspacket_free(payload);
            break;
        }

        iv = payload;
        tag = payload + GCM_IV_LEN;
        ct = payload + GCM_IV_LEN + GCM_TAG_LEN;
        ct_len = payload_len - GCM_IV_LEN - GCM_TAG_LEN;

        pt = (ct_len > 0) ? malloc(ct_len) : NULL;
        if (ct_len > 0 && pt == NULL) {
            dsspacket_free(payload);
            break;
        }

        if (sc_aead_decrypt(key_in, iv,
                            aad, aad_len,
                            ct, ct_len,
                            tag,
                            pt) != 0) {
            free(pt);
            dsspacket_free(payload);
            break;
        }

        if (in_hdr.opcode == OP_SIGN_DOC) {
            reply_text = (replay_rc == 0) ? "REPLAY" : "OK";
        } else {
            reply_text = "UNKNOWN";
        }

        if (send_encrypted_pong(client_fd, key_out, in_hdr.req_nonce, reply_text) != 0) {
            free(pt);
            dsspacket_free(payload);
            break;
        }

        free(pt);
        dsspacket_free(payload);
    }

cleanup:
    free(sig);
    free(transcript);
    free(shared_secret);
    free(server_pub);
    free(client_pub);
    EVP_PKEY_free(server_ecdh_priv);
    replay_free(&cache);
    close(client_fd);
    close(listen_fd);
    return 0;
}
