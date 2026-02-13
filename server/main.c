#include "../common/dsspacket.h"
#include "../common/net.h"
#include "../common/replay.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int send_pong(int fd, const uint8_t req_nonce[REQ_NONCE_LEN], const char *message)
{
    dss_header_t out_hdr;
    size_t payload_len;

    payload_len = strlen(message);
    if (payload_len > UINT32_MAX) {
        return -1;
    }

    memset(&out_hdr, 0, sizeof(out_hdr));
    out_hdr.opcode = PONG;
    memcpy(out_hdr.req_nonce, req_nonce, REQ_NONCE_LEN);
    out_hdr.payload_len = htonl((uint32_t)payload_len);

    return dsspacket_send(fd, &out_hdr, (const uint8_t *)message);
}

int main(int argc, char **argv)
{
    const char *port;
    int listen_fd;
    int client_fd;
    ReplayCache cache;
    int rc;

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
        uint8_t *payload;

        payload = NULL;
        rc = dsspacket_recv(client_fd, &in_hdr, &payload);
        if (rc != 0) {
            dsspacket_free(payload);
            break;
        }

        if (in_hdr.opcode == PING) {
            rc = replay_check_and_add(&cache, in_hdr.req_nonce);
            if (rc < 0) {
                dsspacket_free(payload);
                break;
            }

            if (rc == 0) {
                /* Nonce already observed, mark as replay. */
                if (send_pong(client_fd, in_hdr.req_nonce, "REPLAY") != 0) {
                    dsspacket_free(payload);
                    break;
                }
            } else {
                if (send_pong(client_fd, in_hdr.req_nonce, "OK") != 0) {
                    dsspacket_free(payload);
                    break;
                }
            }
        } else {
            if (send_pong(client_fd, in_hdr.req_nonce, "UNKNOWN") != 0) {
                dsspacket_free(payload);
                break;
            }
        }

        dsspacket_free(payload);
    }

    replay_free(&cache);
    close(client_fd);
    close(listen_fd);
    return 0;
}
