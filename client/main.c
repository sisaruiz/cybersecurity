#include "../common/dsspacket.h"
#include "../common/net.h"
#include "../common/securechan.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fill_random_nonce(uint8_t nonce[REQ_NONCE_LEN])
{
    int fd;
    size_t offset;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    offset = 0;
    while (offset < REQ_NONCE_LEN) {
        ssize_t n = read(fd, nonce + offset, REQ_NONCE_LEN - offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }
        offset += (size_t)n;
    }

    if (close(fd) != 0) {
        return -1;
    }

    return 0;
}

static int send_encrypted_ping(int fd,
                               const uint8_t session_key[GCM_KEY_LEN],
                               const uint8_t req_nonce[REQ_NONCE_LEN])
{
    dss_header_t hdr;
    const char *message;
    size_t pt_len;
    size_t payload_len;
    uint8_t aad[DSSPACKET_AAD_LEN];
    size_t aad_len;
    uint8_t *payload;
    uint8_t *iv;
    uint8_t *tag;
    uint8_t *ct;

    message = "hello";
    pt_len = strlen(message);
    payload_len = GCM_IV_LEN + GCM_TAG_LEN + pt_len;
    if (payload_len > UINT32_MAX) {
        return -1;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.opcode = PING;
    memcpy(hdr.req_nonce, req_nonce, REQ_NONCE_LEN);
    hdr.payload_len = htonl((uint32_t)payload_len);

    if (dsspacket_build_aad(&hdr, aad, &aad_len) != 0) {
        return -1;
    }

    payload = malloc(payload_len);
    if (payload == NULL) {
        return -1;
    }

    iv = payload;
    tag = payload + GCM_IV_LEN;
    ct = payload + GCM_IV_LEN + GCM_TAG_LEN;

    /* Generate a fresh IV for each encrypted request frame. */
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) {
        free(payload);
        return -1;
    }

    if (sc_aead_encrypt(session_key, iv,
                        aad, aad_len,
                        (const uint8_t *)message, pt_len,
                        ct, tag) != 0) {
        free(payload);
        return -1;
    }

    if (dsspacket_send(fd, &hdr, payload) != 0) {
        free(payload);
        return -1;
    }

    free(payload);
    return 0;
}

static int recv_decrypt_and_print_pong(int fd, const uint8_t session_key[GCM_KEY_LEN])
{
    dss_header_t hdr;
    uint8_t aad[DSSPACKET_AAD_LEN];
    size_t aad_len;
    uint8_t *payload;
    uint32_t payload_len;
    const uint8_t *iv;
    const uint8_t *tag;
    const uint8_t *ct;
    size_t ct_len;
    uint8_t *pt;

    payload = NULL;
    pt = NULL;

    if (dsspacket_recv(fd, &hdr, &payload) != 0) {
        return -1;
    }

    payload_len = ntohl(hdr.payload_len);
    if (payload_len < (GCM_IV_LEN + GCM_TAG_LEN)) {
        dsspacket_free(payload);
        return -1;
    }

    if (dsspacket_build_aad(&hdr, aad, &aad_len) != 0) {
        dsspacket_free(payload);
        return -1;
    }

    iv = payload;
    tag = payload + GCM_IV_LEN;
    ct = payload + GCM_IV_LEN + GCM_TAG_LEN;
    ct_len = payload_len - GCM_IV_LEN - GCM_TAG_LEN;

    pt = (ct_len > 0) ? malloc(ct_len + 1u) : malloc(1u);
    if (pt == NULL) {
        dsspacket_free(payload);
        return -1;
    }

    if (sc_aead_decrypt(session_key, iv,
                        aad, aad_len,
                        ct, ct_len,
                        tag,
                        pt) != 0) {
        free(pt);
        dsspacket_free(payload);
        return -1;
    }

    pt[ct_len] = '\0';
    fputs((const char *)pt, stdout);
    fputc('\n', stdout);

    free(pt);
    dsspacket_free(payload);
    return 0;
}

int main(int argc, char **argv)
{
    const char *host;
    const char *port;
    int fd;
    uint8_t req_nonce[REQ_NONCE_LEN];
    const uint8_t session_key[GCM_KEY_LEN] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };

    host = (argc > 1) ? argv[1] : "127.0.0.1";
    port = (argc > 2) ? argv[2] : "9000";

    if (fill_random_nonce(req_nonce) != 0) {
        perror("fill_random_nonce");
        return 1;
    }

    fd = tcp_connect(host, port);
    if (fd < 0) {
        perror("tcp_connect");
        return 1;
    }

    /* Send an initial encrypted PING with a fresh nonce. */
    if (send_encrypted_ping(fd, session_key, req_nonce) != 0) {
        perror("send_encrypted_ping");
        close(fd);
        return 1;
    }

    if (recv_decrypt_and_print_pong(fd, session_key) != 0) {
        perror("recv_decrypt_and_print_pong");
        close(fd);
        return 1;
    }

    /* Send the same nonce again to trigger replay detection. */
    if (send_encrypted_ping(fd, session_key, req_nonce) != 0) {
        perror("send_encrypted_ping");
        close(fd);
        return 1;
    }

    if (recv_decrypt_and_print_pong(fd, session_key) != 0) {
        perror("recv_decrypt_and_print_pong");
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
