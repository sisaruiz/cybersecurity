#include "dsspacket.h"

#include "net.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

#define DSSPACKET_MAX_PAYLOAD_LEN (10u * 1024u * 1024u)

enum {
    DSSPACKET_ERR_INVALID_ARG = -1,
    DSSPACKET_ERR_LENGTH = -2,
    DSSPACKET_ERR_IO = -3,
    DSSPACKET_ERR_OOM = -4,
    DSSPACKET_ERR_PROTOCOL = -5,
};

int dsspacket_send(int fd, const dss_header_t *hdr, const uint8_t *payload)
{
    uint32_t payload_len;
    uint32_t total_len;
    uint32_t total_len_be;

    if (fd < 0 || hdr == NULL) {
        return DSSPACKET_ERR_INVALID_ARG;
    }

    payload_len = ntohl(hdr->payload_len);
    if (payload_len > DSSPACKET_MAX_PAYLOAD_LEN) {
        return DSSPACKET_ERR_LENGTH;
    }

    if (payload_len > 0 && payload == NULL) {
        return DSSPACKET_ERR_INVALID_ARG;
    }

    if ((uint64_t)sizeof(dss_header_t) + payload_len > UINT32_MAX) {
        return DSSPACKET_ERR_LENGTH;
    }

    total_len = (uint32_t)sizeof(dss_header_t) + payload_len;
    total_len_be = htonl(total_len);

    /* Send frame length first, then header, then payload bytes. */
    if (send_all(fd, &total_len_be, sizeof(total_len_be)) != 0) {
        return DSSPACKET_ERR_IO;
    }

    if (send_all(fd, hdr, sizeof(*hdr)) != 0) {
        return DSSPACKET_ERR_IO;
    }

    if (payload_len > 0 && send_all(fd, payload, payload_len) != 0) {
        return DSSPACKET_ERR_IO;
    }

    return 0;
}

int dsspacket_recv(int fd, dss_header_t *hdr, uint8_t **payload_out)
{
    uint32_t total_len_be;
    uint32_t total_len;
    uint32_t payload_len;
    uint8_t *payload = NULL;

    if (fd < 0 || hdr == NULL || payload_out == NULL) {
        return DSSPACKET_ERR_INVALID_ARG;
    }

    *payload_out = NULL;

    if (recv_all(fd, &total_len_be, sizeof(total_len_be)) != 0) {
        return DSSPACKET_ERR_IO;
    }

    total_len = ntohl(total_len_be);
    if (total_len < sizeof(dss_header_t)) {
        return DSSPACKET_ERR_PROTOCOL;
    }

    if (total_len - (uint32_t)sizeof(dss_header_t) > DSSPACKET_MAX_PAYLOAD_LEN) {
        return DSSPACKET_ERR_LENGTH;
    }

    /* Receive header exactly as transmitted on the wire. */
    if (recv_all(fd, hdr, sizeof(*hdr)) != 0) {
        return DSSPACKET_ERR_IO;
    }

    payload_len = ntohl(hdr->payload_len);
    if (payload_len > DSSPACKET_MAX_PAYLOAD_LEN) {
        return DSSPACKET_ERR_LENGTH;
    }

    if ((uint32_t)sizeof(dss_header_t) + payload_len != total_len) {
        return DSSPACKET_ERR_PROTOCOL;
    }

    if (payload_len == 0) {
        return 0;
    }

    payload = malloc(payload_len);
    if (payload == NULL) {
        return DSSPACKET_ERR_OOM;
    }

    if (recv_all(fd, payload, payload_len) != 0) {
        free(payload);
        return DSSPACKET_ERR_IO;
    }

    *payload_out = payload;
    return 0;
}

void dsspacket_free(uint8_t *payload)
{
    free(payload);
}
