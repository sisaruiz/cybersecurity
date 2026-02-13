#include "../common/dsspacket.h"
#include "../common/net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

static int send_ping(int fd, const uint8_t req_nonce[REQ_NONCE_LEN], const char *payload)
{
    dss_header_t hdr;
    size_t payload_len;

    if (payload == NULL) {
        errno = EINVAL;
        return -1;
    }

    payload_len = strlen(payload);
    if (payload_len > UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.opcode = PING;
    memcpy(hdr.req_nonce, req_nonce, REQ_NONCE_LEN);
    hdr.payload_len = htonl((uint32_t)payload_len);

    return dsspacket_send(fd, &hdr, (const uint8_t *)payload);
}

static int recv_and_print_pong(int fd)
{
    dss_header_t hdr;
    uint8_t *payload;
    uint32_t payload_len;

    payload = NULL;
    if (dsspacket_recv(fd, &hdr, &payload) != 0) {
        return -1;
    }

    payload_len = ntohl(hdr.payload_len);
    if (payload_len > 0) {
        fwrite(payload, 1, payload_len, stdout);
    }
    fputc('\n', stdout);

    dsspacket_free(payload);
    return 0;
}

int main(int argc, char **argv)
{
    const char *host;
    const char *port;
    int fd;
    uint8_t req_nonce[REQ_NONCE_LEN];

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

    /* Send an initial PING with a fresh nonce. */
    if (send_ping(fd, req_nonce, "hello") != 0) {
        perror("send_ping");
        close(fd);
        return 1;
    }

    if (recv_and_print_pong(fd) != 0) {
        perror("recv_and_print_pong");
        close(fd);
        return 1;
    }

    /* Send the same nonce again to trigger replay detection. */
    if (send_ping(fd, req_nonce, "hello") != 0) {
        perror("send_ping");
        close(fd);
        return 1;
    }

    if (recv_and_print_pong(fd) != 0) {
        perror("recv_and_print_pong");
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
