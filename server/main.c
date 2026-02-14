#include "../common/dsspacket.h"
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
                               const uint8_t session_key[GCM_KEY_LEN],
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
    out_hdr.opcode = PONG;
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

    if (sc_aead_encrypt(session_key, iv,
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
    const uint8_t session_key[GCM_KEY_LEN] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };

    port = (argc > 1) ? argv[1] : "9000";
    listen_fd = -1;
    client_fd = -1;
    memset(&cache, 0, sizeof(cache));

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

    rc = replay_init(&cache, 0);
    if (rc != 0) {
        fprintf(stderr, "replay_init failed\n");
        close(client_fd);
        close(listen_fd);
        return 1;
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

        if (sc_aead_decrypt(session_key, iv,
                            aad, aad_len,
                            ct, ct_len,
                            tag,
                            pt) != 0) {
            free(pt);
            dsspacket_free(payload);
            break;
        }

        if (in_hdr.opcode == PING) {
            reply_text = (replay_rc == 0) ? "REPLAY" : "OK";
        } else {
            reply_text = "UNKNOWN";
        }

        if (send_encrypted_pong(client_fd, session_key, in_hdr.req_nonce, reply_text) != 0) {
            free(pt);
            dsspacket_free(payload);
            break;
        }

        free(pt);
        dsspacket_free(payload);
    }

    replay_free(&cache);
    close(client_fd);
    close(listen_fd);
    return 0;
}
